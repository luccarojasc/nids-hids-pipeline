"""Demonstração descartável em VM própria; nunca executar na Workstation2."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid

from mitigation import nft_lab
from mitigation.policy import NS, simulate

SERVER_CODE = '''import selectors,socket
s=selectors.DefaultSelector()
for port in (22,2222):
    sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(("192.0.2.1",port)); sock.listen(); s.register(sock,selectors.EVENT_READ)
while True:
    for key,_ in s.select():
        c,_=key.fileobj.accept(); c.close()
'''
PROBE_CODE = '''import socket,sys
try:
    c=socket.create_connection(("192.0.2.1",int(sys.argv[1])),timeout=0.6); c.close()
except socket.timeout:
    sys.exit(2)
except OSError as exc:
    print(exc,file=sys.stderr); sys.exit(3)
'''


def guard(confirm):
    if not confirm or platform.node().split(".")[0].lower() == "workstation2":
        raise ValueError("Requer confirmação de VM própria; Workstation2 proibida")
    if os.geteuid() != 0:
        raise ValueError("Requer root dentro da VM descartável")
    for name in ("ip", "nft", "systemd-detect-virt"):
        if shutil.which(name) is None:
            raise ValueError(f"Dependência ausente na VM: {name}")
    result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError("VM não identificada; não remover esta verificação")
    return result.stdout.strip()


def lab_commands():
    scope = {"dataset": "controlled_test", "scenario": "ttl_demo", "host": "lab_server",
             "destination_ip": nft_lab.SERVER, "destination_port": 22, "source_ip": nft_lab.CLIENT}
    def command(rid, aid, kind, seconds, ttl=None, score=None):
        return {"request_id": rid, "alert_id": aid, "kind": kind, "t_ns": seconds * NS,
                "mode": "B2", "scope": dict(scope), "ttl_s": ttl, "score": score}
    critical = command("critical-a", "a", "critical", 300, 1800, 100)
    return [command("open-a", "a", "open", 0, 900, 50), critical, dict(critical),
            command("open-b", "b", "open", 450, 900, 50),
            command("close-a", "a", "close", 600), command("close-b", "b", "close", 600)]


def demo(root, out, profile, confirm):
    virtualization = guard(confirm)
    root, out = Path(root).resolve(), Path(out).resolve()
    if root not in out.parents:
        raise ValueError("Saída deve ficar dentro da cópia do laboratório")
    cfg = json.loads((root / "config/mitigacao-semana6.json").read_text())
    commands = lab_commands()
    actions, summary = simulate(commands, cfg)
    out.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex[:8]
    client, server = "tcc6_cli_" + token, "tcc6_srv_" + token
    factor = 150 if profile == "accelerated" else 1
    resources, process = [], None
    log, t0 = [], time.monotonic_ns()
    successful = False

    def record(event, **values):
        row = {"event": event, "elapsed_ns": time.monotonic_ns() - t0, **values}
        log.append(row)
        with (out / "journal.jsonl").open("a") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        print(event, flush=True)

    def run(argv):
        before = time.monotonic_ns()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        record("command", argv=argv, returncode=result.returncode,
               duration_ns=time.monotonic_ns() - before, stdout=result.stdout, stderr=result.stderr)
        result.check_returncode()
        return result.stdout

    def probe(port, expected, label):
        if process.poll() is not None:
            raise RuntimeError("Servidor de teste terminou")
        before = time.monotonic_ns()
        result = subprocess.run(["ip", "netns", "exec", client, sys.executable, "-c", PROBE_CODE, str(port)],
                                capture_output=True, text=True, timeout=5)
        record(label, port=port, returncode=result.returncode, stderr=result.stderr,
               duration_ns=time.monotonic_ns() - before, expected=expected)
        if result.returncode != expected:
            raise RuntimeError(f"Sonda {label}: retorno {result.returncode}, esperado {expected}")

    def snapshot(label):
        data = run(["ip", "netns", "exec", server, "nft", "-j", "list", "table", "inet", nft_lab.TABLE])
        (out / f"{label}.json").write_text(data)

    def wait_until(deadline):
        while time.monotonic() < deadline:
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))

    record("environment", hostname=platform.node(), kernel=platform.release(), python=platform.python_version(),
           virtualization=virtualization, profile=profile, time_divisor=factor,
           client_namespace=client, server_namespace=server)
    try:
        run(["nft", "--version"])
        run(["ip", "-Version"])
        for ns in (client, server):
            run(["ip", "netns", "add", ns]); resources.append(ns)
            run(["ip", "-n", ns, "link", "set", "lo", "up"])
        # O par é criado diretamente nos namespaces; nenhuma interface física é movida.
        run(["ip", "-n", client, "link", "add", "lab0", "type", "veth", "peer", "name", "lab0", "netns", server])
        for ns, address in ((client, nft_lab.CLIENT), (server, nft_lab.SERVER)):
            run(["ip", "-n", ns, "addr", "add", address + "/30", "dev", "lab0"])
            run(["ip", "-n", ns, "link", "set", "lab0", "up"])
        setup = nft_lab.setup_batch()
        (out / "setup.nft").write_text(setup)
        nft_lab.invoke(server, setup)
        process = subprocess.Popen(["ip", "netns", "exec", server, sys.executable, "-c", SERVER_CODE],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        wait_until(time.monotonic() + 0.5)
        probe(22, 0, "before_allowed")
        probe(2222, 0, "control_before_allowed")
        clock_start = time.monotonic()
        baseline_deadline = None
        last_deadline = None
        for index, action in enumerate(a for a in actions if a["action"] != "expire"):
            wait_until(clock_start + action["t_ns"] / NS / factor)
            name = action["action"]
            record("policy_action", decision=action)
            if name in ("apply", "renew"):
                if name == "renew" and time.monotonic() >= baseline_deadline:
                    raise RuntimeError("Atraso excedeu TTL inicial; preservar falha e repetir em nova pasta")
                ttl = (action["expires_ns"] - action["t_ns"]) // NS // factor
                batch = nft_lab.action_batch(name, ttl)
                (out / f"batch-{index}.nft").write_text(batch)
                before = time.monotonic()
                nft_lab.invoke(server, batch)
                last_deadline = time.monotonic() + ttl
                record("applied", action=name, ttl_s=ttl, command_duration_s=time.monotonic() - before)
                if name == "apply":
                    baseline_deadline = last_deadline
                snapshot(f"after-{name}")
                probe(22, 2, f"{name}_blocked")
                probe(2222, 0, f"{name}_control_allowed")
        wait_until(baseline_deadline + 0.3)
        if time.monotonic() + 0.8 >= last_deadline:
            raise RuntimeError("Sem margem para comprovar renovação")
        probe(22, 2, "after_original_deadline_still_blocked")
        snapshot("after-original-deadline")
        wait_until(last_deadline + 0.5)
        probe(22, 0, "after_expiry_allowed")
        probe(2222, 0, "after_expiry_control_allowed")
        snapshot("after-expiry")
        successful = True
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)
            if process.stderr is not None:
                record("server_stderr", value=process.stderr.read())
                process.stderr.close()
        cleanup = []
        for ns in reversed(resources):
            result = subprocess.run(["ip", "netns", "del", ns], capture_output=True, text=True, timeout=10)
            cleanup.append({"namespace": ns, "returncode": result.returncode, "stderr": result.stderr})
        record("cleanup", results=cleanup)
        if any(x["returncode"] != 0 for x in cleanup):
            successful = False
        evidence = {"profile": profile, "time_divisor": factor, "synthetic_software_demo": True,
                    "metrics_enabled": False, "completed": successful, "policy_summary": summary,
                    "commands": commands, "code_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [Path(__file__).resolve(), root / "src/mitigation/policy.py", root / "src/mitigation/nft_lab.py", root / "config/mitigacao-semana6.json"]},
                    "outputs_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}}
        (out / "manifest.json").write_text(json.dumps(evidence, indent=2) + "\n")
    if not successful:
        raise RuntimeError("Demonstração ou limpeza incompleta; revisar journal.jsonl")
    (out / "SUCCESS").write_text("semana6: mecanismo nftables demonstrado em VM isolada\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", choices=("accelerated", "contract"), default="accelerated")
    parser.add_argument("--confirm-isolated-vm", action="store_true")
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Interrupção: limpar recursos próprios")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        demo(args.root, args.out, args.profile, args.confirm_isolated_vm)
    except (Exception, KeyboardInterrupt) as exc:
        print("DEMO INCOMPLETA:", exc, file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr or "", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())