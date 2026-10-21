import importlib.util
import io
import json
from pathlib import Path
import shutil
import re
import subprocess

import pytest

from mitigation.policy import NS, check_config, digest, from_transitions, simulate
from mitigation import nft_lab
from mitigation.run import execute, preflight, verify
from motor.contract import sha
from motor.detect import execute as execute_week5
from motor.alerts import MODES

ROOT = Path(__file__).resolve().parents[1]


def config():
    return json.loads((ROOT / "config/mitigacao-semana6.json").read_text())


def command(kind="open", t=0, aid="a", mode="B2", source="192.0.2.2", host="lab"):
    scope = {"dataset": "test", "scenario": "ttl", "host": host,
             "destination_ip": "192.0.2.1", "destination_port": 22, "source_ip": source}
    return {"request_id": digest([aid, kind, t]), "alert_id": aid, "mode": mode,
            "kind": kind, "t_ns": t * NS, "scope": scope,
            "ttl_s": None if kind == "close" else 1800 if kind == "critical" else 900,
            "score": None if kind == "close" else 100 if kind == "critical" else 50}


def run(*commands):
    return simulate(list(commands), config())


def test_normal_apply_expiry_and_close_does_not_release():
    actions, summary = run(command(), command("close", 10))
    assert [x["action"] for x in actions] == ["apply", "close_ignored", "expire"]
    assert actions[-1]["t_ns"] == 900 * NS
    assert summary["active_at_end"] == 0 and not summary["metrics_enabled"]


def test_second_user_alert_merges_and_renews_same_service():
    actions, _ = run(command(), command(t=2, aid="b"))
    assert [x["action"] for x in actions] == ["apply", "renew", "expire"]
    assert actions[-1]["t_ns"] == 902 * NS


def test_critical_promotes_and_normal_never_shortens():
    actions, _ = run(command(), command("critical", 100), command(t=200, aid="b"))
    assert [x["action"] for x in actions] == ["apply", "renew", "retain", "expire"]
    assert actions[-1]["t_ns"] == 1900 * NS


def test_duplicate_exactly_once():
    a = command()
    actions, summary = run(a, dict(a))
    assert [x["action"] for x in actions] == ["apply", "duplicate_ignored", "expire"]
    assert summary["unique_requests"] == 1


def test_duplicate_conflict_rejected():
    a, b = command(), command(t=1)
    b["request_id"] = a["request_id"]
    with pytest.raises(ValueError, match="Mesmo ID"):
        run(a, b)


@pytest.mark.parametrize("change", ["mode", "source", "host", "dataset", "scenario", "destination_ip"])
def test_independent_scopes(change):
    a, b = command(), command(aid="b")
    if change == "mode":
        b["mode"] = "B1"
    elif change == "source":
        b["scope"]["source_ip"] = "192.0.2.3"
    else:
        b["scope"][change] = "192.0.2.3" if change == "destination_ip" else "other"
    actions, _ = run(a, b)
    assert sum(x["action"] == "apply" for x in actions) == 2
    assert sum(x["action"] == "expire" for x in actions) == 2


def test_expiry_boundary_is_processed_before_new_request():
    actions, _ = run(command(), command(t=900, aid="b"))
    assert [x["action"] for x in actions] == ["apply", "expire", "apply", "expire"]


def test_empty_and_reordered_input():
    assert run()[0] == []
    a, b, c = command(), command("critical", 10), command("close", 20)
    assert run(a, b, c) == run(c, a, b)


@pytest.mark.parametrize("bad", ["ipv6", "port", "ttl", "score", "time", "critical_B1"])
def test_invalid_command_rejected(bad):
    c = command()
    if bad == "ipv6": c["scope"]["source_ip"] = "::1"
    if bad == "port": c["scope"]["destination_port"] = 80
    if bad == "ttl": c["ttl_s"] = 900.0
    if bad == "score": c["score"] = 99
    if bad == "time": c["t_ns"] = -1
    if bad == "critical_B1": c = command("critical", 2, mode="B1")
    with pytest.raises(ValueError):
        run(c)


def test_critical_requires_open_and_cannot_follow_close():
    with pytest.raises(ValueError):
        run(command("critical", 1))
    with pytest.raises(ValueError):
        run(command(), command("close", 1), command("critical", 2))
    with pytest.raises(ValueError):
        run(command(), command("critical", 1), command("critical", 2))


def test_changed_contract_rejected():
    cfg = config(); cfg["base_ttl_s"] = 6
    with pytest.raises(ValueError):
        check_config(cfg)


def test_adapter_does_not_use_final_critical_state_for_open():
    scope = command()["scope"]
    alert = {"id": "a", "mode": "B2", **scope, "opened_ns": 0, "ended_ns": 20 * NS,
             "critical_ns": 10 * NS, "recommended_ttl_s": 1800, "score": 100}
    transitions = [{"alert_id": "a", "mode": "B2", "action": "open", "t_ns": 0,
                    "score": 50, "recommended_ttl_s": 900},
                   {"alert_id": "a", "mode": "B2", "action": "critical", "t_ns": 10 * NS,
                    "score": 100, "recommended_ttl_s": 1800}]
    rows = from_transitions([alert], transitions, config())
    assert rows[0]["ttl_s"] == 900 and rows[1]["ttl_s"] == 1800
    actions, _ = simulate(rows, config())
    assert actions[0]["expires_ns"] == 900 * NS
    assert actions[1]["expires_ns"] == 1810 * NS


def test_nft_renderer_scoped_and_atomic_renewal(monkeypatch):
    calls = []
    def fake(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(nft_lab.subprocess, "run", fake)
    batch = nft_lab.action_batch("renew", 12)
    nft_lab.invoke("tcc6_srv_1234abcd", batch)
    argv, kwargs = calls[0]
    assert argv[:4] == ["ip", "netns", "exec", "tcc6_srv_1234abcd"]
    assert argv[-3:] == ["nft", "-f", "-"]
    assert kwargs["input"].count("element") == 2
    assert "delete element" in batch and "add element" in batch
    assert "flush ruleset" not in nft_lab.setup_batch()
    assert "tcp dport 22" in nft_lab.setup_batch()
    assert not kwargs.get("shell", False)


@pytest.mark.parametrize("ns", ["", "default", "Workstation2", "tcc6_srv_1234abcd; echo bad"])
def test_nft_namespace_rejected(ns):
    with pytest.raises(ValueError):
        nft_lab.namespace(ns)


def test_nft_failure_is_propagated(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr="controlled failure")
    monkeypatch.setattr(nft_lab.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        nft_lab.invoke("tcc6_srv_1234abcd", nft_lab.action_batch("apply", 6))


def demo_module(root=ROOT):
    spec = importlib.util.spec_from_file_location("demo6", root / "scripts/semana6_vm_demo.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def test_vm_guard_rejects_shared_host_and_missing_confirmation(monkeypatch):
    mod = demo_module()
    monkeypatch.setattr(mod.platform, "node", lambda: "Workstation2")
    with pytest.raises(ValueError, match="Workstation2"):
        mod.guard(True)
    monkeypatch.setattr(mod.platform, "node", lambda: "lab-vm")
    with pytest.raises(ValueError):
        mod.guard(False)


def test_lab_commands_exercise_renewal_duplicate_and_retention():
    actions, _ = run(*demo_module().lab_commands())
    assert [a["action"] for a in actions] == ["apply", "renew", "duplicate_ignored", "retain",
                                              "close_ignored", "close_ignored", "expire"]
    assert actions[-1]["t_ns"] == 2100 * NS


def test_full_offline_package_and_tamper(tmp_path):
    from test_motor_semana5 import reference_fixture
    p5 = reference_fixture(tmp_path)
    # Completar as fontes que irão constar no manifesto novo da Semana 5.
    for path in (ROOT / "src/motor").glob("*.py"):
        shutil.copyfile(path, tmp_path / "src/motor" / path.name)
    execute_week5(tmp_path, p5, tmp_path / "week5", MODES)
    cfg = config()
    cfg.update(reference_dir="week5", reference_config_sha256=sha(p5), expected_alerts={m: 1 for m in MODES})
    p6 = tmp_path / "config/mitigacao-semana6.json"
    p6.write_text(json.dumps(cfg))
    shutil.copytree(ROOT / "src/mitigation", tmp_path / "src/mitigation")
    preflight(tmp_path, p6)
    out = tmp_path / "out6"
    execute(tmp_path, p6, out)
    assert (out / "SUCCESS").is_file()
    verify(out)
    with pytest.raises(FileExistsError):
        execute(tmp_path, p6, out)
    (out / "actions.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="alterada"):
        verify(out)
    (tmp_path / "src/motor/core.py").write_text("# modified\n")
    with pytest.raises(ValueError, match="Fonte"):
        preflight(tmp_path, p6)


@pytest.mark.parametrize("fail_probe", [False, True])
def test_demo_flow_and_cleanup_with_fake_executor(tmp_path, monkeypatch, fail_probe):
    # Nenhuma chamada de kernel/firewall: relógio, sondas e executor substituídos.
    for rel in ("config/mitigacao-semana6.json", "scripts/semana6_vm_demo.py",
                "src/mitigation/policy.py", "src/mitigation/nft_lab.py"):
        target = tmp_path / rel; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    mod = demo_module(tmp_path)
    clock, until, resources = [0.0], [0.0], set()
    monkeypatch.setattr(mod, "guard", lambda confirm: "mock_vm")
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(mod.time, "monotonic_ns", lambda: int(clock[0] * NS))
    monkeypatch.setattr(mod.time, "sleep", lambda value: clock.__setitem__(0, clock[0] + value))
    class Process:
        def __init__(self, *args, **kwargs): self.done = False; self.stderr = io.StringIO("")
        def poll(self): return 0 if self.done else None
        def terminate(self): self.done = True
        def kill(self): self.done = True
        def wait(self, timeout=None): self.done = True; return 0
    def invoke(ns, batch):
        ttl = re.search(r"timeout (\d+)s", batch)
        if ttl: until[0] = clock[0] + int(ttl.group(1))
    def fake_run(argv, **kwargs):
        rc, stdout = 0, ""
        if argv[:3] == ["ip", "netns", "add"]: resources.add(argv[3])
        if argv[:3] == ["ip", "netns", "del"]: resources.remove(argv[3])
        if mod.PROBE_CODE in argv:
            port = int(argv[-1]); rc = 2 if port == 22 and clock[0] < until[0] else 0
            if fail_probe and clock[0] < until[0] and port == 22: rc = 3
        if "nft" in argv and "-j" in argv: stdout = '{"nftables": []}'
        return subprocess.CompletedProcess(argv, rc, stdout, "controlled" if rc == 3 else "")
    monkeypatch.setattr(mod.subprocess, "Popen", Process)
    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.nft_lab, "invoke", invoke)
    out = tmp_path / "demo-out"
    if fail_probe:
        with pytest.raises(RuntimeError, match="Sonda"):
            mod.demo(tmp_path, out, "accelerated", True)
        assert not (out / "SUCCESS").exists()
    else:
        mod.demo(tmp_path, out, "accelerated", True)
        assert (out / "SUCCESS").exists()
    assert resources == set()
    assert json.loads((out / "manifest.json").read_text())["completed"] is (not fail_probe)