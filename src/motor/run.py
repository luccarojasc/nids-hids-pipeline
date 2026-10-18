"""CLI: conferir entradas, executar núcleo e conferir o pacote resultante."""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

from motor.contract import load_config, load_inputs, scope, sha
from motor.core import maxima, replay


def save_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def save_lines(path, rows):
    with Path(path).open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def read_lines(path):
    with Path(path).open(encoding="utf-8") as inp:
        return [json.loads(line) for line in inp if line.strip()]


def inspect(root, config):
    cfg = load_config(config)
    rows, manifest, excluded, summary = load_inputs(root, cfg)
    for item in manifest:
        print(f"{item['rows']:3d} registros | {item['role']:5s} | {Path(item['path']).name}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("OK: contrato técnico. Não certifica rótulos, exposição ou elegibilidade de métricas.")
    return cfg, rows, manifest, excluded, summary


def execute(root, config, out):
    cfg, rows, manifest, excluded, summary = inspect(root, config)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    traces, links, associations = [], [], []
    for case in cfg["cases"]:
        selected = [r for r in rows if scope(r) == scope(case)]
        if not any(r["kind"] == "auth" for r in selected) or not any(r["kind"] == "net" for r in selected):
            raise ValueError(f"Cenário sem um dos planos: {scope(case)}")
        tr, li, ass = replay(selected, cfg, case)
        traces.extend(tr)
        links.extend(li)
        associations.extend(ass)
    save_json(out / "config.json", cfg)
    save_lines(out / "events.jsonl", rows)
    save_lines(out / "excluded.jsonl", excluded)
    save_lines(out / "trace.jsonl", traces)
    save_lines(out / "links.jsonl", links)
    save_lines(out / "connections.jsonl", associations)
    summary.update(maxima=maxima(traces), link_status=dict(Counter(x["status"] for x in links)),
                   connection_status=dict(Counter(x["status"] for x in associations)),
                   metrics_enabled=False, phase="semana4_contadores_sem_alertas")
    save_json(out / "summary.json", summary)
    root = Path(root).resolve()
    source_paths = sorted((root / "src/motor").glob("*.py"))
    sources = {str(p.relative_to(root)): sha(p) for p in source_paths}
    code_hash = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()
    git = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=False)
    manifest_out = {"inputs": manifest, "sources_sha256": sources, "code_sha256": code_hash,
                    "git_head": git.stdout.strip() if git.returncode == 0 else None,
                    "python": platform.python_version(), "pandas": pd.__version__,
                    "config_sha256": sha(config),
                    "outputs_sha256": {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()}}
    save_json(out / "manifest.json", manifest_out)
    verify(out)
    # SUCCESS é criado somente depois da conferência e significa sucesso técnico.
    (out / "SUCCESS").write_text("semana4: contrato e replay conferidos\n", encoding="utf-8")
    print(json.dumps(summary["maxima"], ensure_ascii=False, indent=2))
    print(f"Saídas: {out}")


def verify(out):
    out = Path(out)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["outputs_sha256"].items():
        if sha(out / name) != expected:
            raise ValueError(f"Saída alterada ou incompleta: {name}")
    cfg = load_config(out / "config.json")
    events = {r["id"]: r for r in read_lines(out / "events.jsonl")}
    for snap in read_lines(out / "trace.jsonl"):
        t = snap["t_ns"]
        if snap["Nn_rede"] != len(set(snap["network_ids"])):
            raise ValueError("Contagem de rede não reconciliada")
        for cid in snap["network_ids"]:
            net = events[cid]
            if not (net["end"] is not None and net["end"] <= t
                    and t - cfg["window_ns"] < net["start"] <= t
                    and 0 < net["duration"] <= cfg["short_max_ns"]):
                raise ValueError("Contribuição de rede fora do contrato temporal")
        assigned = []
        for user in snap["users"]:
            if user["Nh"] != len(set(user["host_ids"])) or user["Nn_associado"] != len(set(user["network_ids"])):
                raise ValueError("Contagem por usuário não reconciliada")
            for hid in user["host_ids"]:
                host = events[hid]
                if not (host["kind"] == "auth" and host["outcome"] == "failure"
                        and host["user"] == user["user"] and host["available"] <= t
                        and t - cfg["window_ns"] < host["start"] <= t):
                    raise ValueError("Contribuição de host fora do contrato")
            if not set(user["network_ids"]) <= set(snap["network_ids"]):
                raise ValueError("Rede associada fora de Nn_rede")
            assigned.extend(user["network_ids"])
        if len(assigned) != len(set(assigned)):
            raise ValueError("Conexão atribuída a vários usuários no mesmo instante")
    print("OK: integridade das saídas, IDs, contadores e disponibilidade temporal.")


def main():
    parser = argparse.ArgumentParser(description="Semana 4: contrato e replay de contadores SSH")
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
                inspect(args.root, args.config)
            else:
                if args.out is None:
                    parser.error("run requer --out novo")
                execute(args.root, args.config, args.out)
    except (ValueError, OSError, KeyError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())