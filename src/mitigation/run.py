"""CLI offline da Semana 6. Nenhuma opção aplica firewall."""
import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path

from motor.contract import sha
from motor.detect import verify as verify_week5
from motor.run import read_lines, save_json, save_lines
from mitigation.policy import MODES, check_config, from_transitions, simulate


def preflight(root, config):
    root = Path(root).resolve()
    cfg = json.loads(Path(config).read_text())
    check_config(cfg)
    ref = (root / cfg["reference_dir"]).resolve()
    if root not in ref.parents or not (ref / "SUCCESS").is_file():
        raise ValueError("Referência Semana 5 ausente ou fora do projeto")
    verify_week5(ref)
    manifest = json.loads((ref / "manifest.json").read_text())
    if manifest["config_sha256"] != cfg["reference_config_sha256"]:
        raise ValueError("Configuração de referência divergente")
    if set(manifest["modes"]) != set(MODES):
        raise ValueError("Referência deve conter B1/B2/B3")
    for relative, expected in manifest["sources_sha256"].items():
        path = (root / relative).resolve()
        if root not in path.parents or sha(path) != expected:
            raise ValueError(f"Fonte do motor divergente: {relative}")
    alerts = read_lines(ref / "alerts.jsonl")
    transitions = read_lines(ref / "transitions.jsonl")
    counts = {m: sum(a["mode"] == m for a in alerts) for m in MODES}
    if counts != cfg["expected_alerts"]:
        raise ValueError("Contagens de alertas divergentes da referência escolhida")
    commands = from_transitions(alerts, transitions, cfg)
    simulate(commands, cfg)
    print(json.dumps({"alerts": counts, "transitions": len(transitions), "executor": cfg["executor"]}, indent=2))
    print("OK: referência e interface de decisões conferidas.")
    return cfg, ref, alerts, transitions, commands


def verify(out):
    out = Path(out)
    manifest = json.loads((out / "manifest.json").read_text())
    for relative, expected in manifest["outputs_sha256"].items():
        path = (out / relative).resolve()
        if out.resolve() not in path.parents or sha(path) != expected:
            raise ValueError(f"Saída alterada: {relative}")
    cfg = json.loads((out / "config.json").read_text())
    commands = from_transitions(read_lines(out / "alerts.jsonl"), read_lines(out / "transitions.jsonl"), cfg)
    if commands != read_lines(out / "commands.jsonl"):
        raise ValueError("Comandos divergentes das transições")
    actions, summary = simulate(commands, cfg)
    if actions != read_lines(out / "actions.jsonl") or summary != json.loads((out / "summary.json").read_text()):
        raise ValueError("Reprodução da política divergente")
    print("OK: pacote e política offline reproduzidos; nenhuma ação de firewall.")


def execute(root, config, out):
    root, out = Path(root).resolve(), Path(out).resolve()
    if root not in out.parents:
        raise ValueError("Saída deve estar dentro do projeto")
    cfg, ref, alerts, transitions, commands = preflight(root, config)
    out.mkdir(parents=True, exist_ok=False)
    actions, summary = simulate(commands, cfg)
    save_json(out / "config.json", cfg)
    for name, rows in (("alerts", alerts), ("transitions", transitions), ("commands", commands), ("actions", actions)):
        save_lines(out / f"{name}.jsonl", rows)
    save_json(out / "summary.json", summary)
    git = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    sources = sorted((root / "src/mitigation").glob("*.py")) + sorted((root / "src/motor").glob("*.py"))
    manifest = {"reference_dir": str(ref), "reference_manifest_sha256": sha(ref / "manifest.json"),
                "reference_outputs_sha256": {p.name: sha(p) for p in (ref / "alerts.jsonl", ref / "transitions.jsonl")},
                "config_sha256": sha(config), "git_head": git.stdout.strip() if git.returncode == 0 else None,
                "python": platform.python_version(), "sources_sha256": {str(p.relative_to(root)): sha(p) for p in sources},
                "outputs_sha256": {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()}}
    save_json(out / "manifest.json", manifest)
    verify(out)
    (out / "SUCCESS").write_text("semana6: politica offline conferida; firewall nao executado\n")
    print(json.dumps(summary, indent=2))
    print("Saídas:", out)


def main():
    parser = argparse.ArgumentParser(description="Semana 6: TTL offline, sem firewall")
    parser.add_argument("command", choices=("inspect", "run", "verify"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            if args.out is None:
                parser.error("verify requer --out")
            verify(args.out)
        else:
            if args.root is None or args.config is None:
                parser.error("inspect/run requerem --root e --config")
            if args.command == "inspect":
                preflight(args.root, args.config)
            else:
                if args.out is None:
                    parser.error("run requer --out novo")
                execute(args.root, args.config, args.out)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("ERRO:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())