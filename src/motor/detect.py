"""CLI da Semana 5; consome a execução preservada da Semana 4."""
import argparse
import json
import platform
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import yaml

from motor.alerts import MODES, compare_units, detect_case
from motor.contract import load_config as load_core_config, scope, sha, stamp
from motor.rules import base_evidence, load_rules
from motor.run import read_lines, save_json, save_lines, verify as verify_week4

BASE_FILES = ("src/motor/__init__.py", "src/motor/contract.py", "src/motor/core.py", "src/motor/run.py")
OUTPUTS = ("alerts", "transitions", "decisions", "critical_checks", "trace")


def load_config(path):
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    if cfg["contract_version"] != "semana5_v1":
        raise ValueError("Contrato da Semana 5 incompatível")
    for field in ("window_ns", "host_threshold", "network_threshold", "short_max_ns",
                  "critical_horizon_ns", "base_score", "critical_score", "base_ttl_s", "critical_ttl_s"):
        if type(cfg[field]) is not int or cfg[field] <= 0:
            raise ValueError(f"Configuração inválida: {field}")
    if (cfg["base_score"], cfg["critical_score"], cfg["base_ttl_s"], cfg["critical_ttl_s"]) != (50, 100, 900, 1800):
        raise ValueError("Score/TTL fora da convenção semana5_v1")
    if cfg["critical_horizon_ns"] != cfg["window_ns"]:
        raise ValueError("Horizonte de criticidade deve ser a janela nesta versão")
    names = []
    for unit in cfg["analysis_units"]:
        names.append(unit["id"])
        if stamp(unit["start"]) >= stamp(unit["end"]):
            raise ValueError("Intervalo de descrição inválido")
    if len(names) != len(set(names)):
        raise ValueError("Unidade de descrição repetida")
    return cfg


def preflight(root, config):
    root = Path(root).resolve()
    cfg = load_config(config)
    ref = (root / cfg["reference_dir"]).resolve()
    if root not in ref.parents or not (ref / "SUCCESS").is_file():
        raise ValueError("Referência da Semana 4 ausente ou incompleta")
    verify_week4(ref)
    manifest = json.loads((ref / "manifest.json").read_text(encoding="utf-8"))
    if manifest["code_sha256"] != cfg["reference_code_sha256"]:
        raise ValueError("Hash do núcleo de referência divergente")
    if manifest["config_sha256"] != cfg["reference_config_sha256"]:
        raise ValueError("Hash da configuração de referência divergente")
    for relative in BASE_FILES:
        if sha(root / relative) != manifest["sources_sha256"][relative]:
            raise ValueError(f"Arquivo da Semana 4 alterado: {relative}")
    for item in manifest["inputs"]:
        if sha(item["path"]) != item["sha256"]:
            raise ValueError(f"Parquet alterado: {item['path']}")
    if sha(root / "config/motor-semana4.json") != manifest["config_sha256"]:
        raise ValueError("Configuração local da Semana 4 alterada")
    core = load_core_config(ref / "config.json")
    for field in ("window_ns", "host_threshold", "network_threshold", "short_max_ns"):
        if cfg[field] != core[field]:
            raise ValueError(f"Mudança silenciosa de parâmetro: {field}")
    rows = read_lines(ref / "events.jsonl")
    total = sum(x["rows"] for x in manifest["inputs"])
    if total != cfg["expected_input_rows"] or len(rows) != cfg["expected_selected_events"]:
        raise ValueError("Contagens de referência divergentes")
    if len({r["id"] for r in rows}) != len(rows):
        raise ValueError("IDs selecionados repetidos")
    cases = {scope(c): c for c in core["cases"]}
    for unit in cfg["analysis_units"]:
        case = cases[scope(unit)]
        if not any(t["host"] == unit["host"] and t["ip"] == unit["destination_ip"]
                   and t["port"] == unit["destination_port"] for t in case["targets"]):
            raise ValueError("Unidade fora do mapa de alvos")
    rules = load_rules(root, cfg)
    hits = base_evidence(rows, rules, core)
    print(json.dumps({"input_rows": total, "selected_events": len(rows), "sigma_rules": len(rules),
                      "base_evidence": dict(Counter(h["rule"] for h in hits))}, indent=2))
    print("OK: referência, parâmetros e seleções-base conferidos.")
    return cfg, core, rows, hits, ref


def build(rows, core, cfg, modes):
    output = {name: [] for name in OUTPUTS}
    for mode in modes:
        for case in core["cases"]:
            selected = [r for r in rows if scope(r) == scope(case)]
            result = detect_case(selected, core, cfg, case, mode)
            for name in OUTPUTS:
                output[name].extend(result[name])
    output["comparison"] = compare_units(output["alerts"], cfg, modes)
    output["summary"] = {
        "phase": "semana5_alertas_offline_sem_mitigacao", "modes": list(modes),
        "metrics_enabled": False,
        "counts": [{"mode": mode,
                    "alerts": sum(a["mode"] == mode for a in output["alerts"]),
                    "critical_alerts": sum(a["mode"] == mode and a["critical"] for a in output["alerts"])}
                   for mode in modes],
        "critical_check_reasons": dict(Counter(x["reason"] for x in output["critical_checks"])),
    }
    return output


def verify(out):
    out = Path(out)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    for relative, digest in manifest["outputs_sha256"].items():
        if sha(out / relative) != digest:
            raise ValueError(f"Saída alterada: {relative}")
    cfg = load_config(out / "config.json")
    core = load_core_config(out / "core_config.json")
    rows = read_lines(out / "events.jsonl")
    rules = load_rules(out, cfg)
    if base_evidence(rows, rules, core) != read_lines(out / "base_hits.jsonl"):
        raise ValueError("Seleções-base não reconciliadas")
    expected = build(rows, core, cfg, manifest["modes"])
    for name in OUTPUTS:
        if expected[name] != read_lines(out / f"{name}.jsonl"):
            raise ValueError(f"Replay divergente: {name}")
    for name in ("comparison", "summary"):
        if expected[name] != json.loads((out / f"{name}.json").read_text(encoding="utf-8")):
            raise ValueError(f"Resumo divergente: {name}")
    by_id = {r["id"]: r for r in rows}
    for alert in expected["alerts"]:
        if alert["mode"] == "B1" and (alert["user"] is not None or alert["trigger_host_ids"] or alert["critical"]):
            raise ValueError("B1 contaminado por host")
        if alert["mode"] == "B2" and alert["trigger_network_ids"]:
            raise ValueError("B2 contaminado por rede")
        for cid in alert["trigger_network_ids"]:
            if by_id[cid]["end"] is None or by_id[cid]["end"] > alert["opened_ns"]:
                raise ValueError("Alerta antecipou fechamento")
        for hid in alert["trigger_host_ids"]:
            if by_id[hid]["available"] > alert["opened_ns"]:
                raise ValueError("Alerta antecipou host")
        if alert["critical"]:
            success = by_id[alert["critical_success_id"]]
            if not (success["outcome"] == "success" and success["user"] == alert["user"]
                    and success["start"] > alert["opened_ns"]
                    and success["available"] == alert["critical_ns"]
                    and alert["critical_ns"] <= alert["opened_ns"] + cfg["critical_horizon_ns"]):
                raise ValueError("Criticidade temporal inconsistente")
    print("OK: hashes, reprodução das decisões e invariantes de alertas conferidos.")


def execute(root, config, out, modes):
    root, out = Path(root).resolve(), Path(out).resolve()
    if root not in out.parents or out == root:
        raise ValueError("Saída deve estar dentro do projeto")
    cfg, core, rows, hits, ref = preflight(root, config)
    out.mkdir(parents=True, exist_ok=False)
    result = build(rows, core, cfg, modes)
    save_json(out / "config.json", cfg)
    save_json(out / "core_config.json", core)
    save_lines(out / "events.jsonl", rows)
    save_lines(out / "base_hits.jsonl", hits)
    for name in OUTPUTS:
        save_lines(out / f"{name}.jsonl", result[name])
    for name in ("comparison", "summary"):
        save_json(out / f"{name}.json", result[name])
    for relative in cfg["rules"].values():
        destination = out / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    git = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    manifest = {"modes": list(modes), "reference_dir": str(ref),
                "reference_manifest_sha256": sha(ref / "manifest.json"),
                "config_sha256": sha(config), "python": platform.python_version(),
                "pandas": pd.__version__, "pyyaml": yaml.__version__,
                "git_head": git.stdout.strip() if git.returncode == 0 else None,
                "sources_sha256": {str(p.relative_to(root)): sha(p) for p in sorted((root / "src/motor").glob("*.py"))},
                "outputs_sha256": {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    save_json(out / "manifest.json", manifest)
    verify(out)
    (out / "SUCCESS").write_text("semana5: alertas e rastreabilidade conferidos\n", encoding="utf-8")
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    print(json.dumps(result["comparison"], ensure_ascii=False, indent=2))
    print(f"Saídas: {out}")


def main():
    parser = argparse.ArgumentParser(description="Semana 5: B1/B2/B3, alertas e criticidade offline")
    parser.add_argument("command", choices=("inspect", "run", "verify"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--mode", choices=(*MODES, "all"), default="all")
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
                modes = MODES if args.mode == "all" else (args.mode,)
                execute(args.root, args.config, args.out, modes)
    except (ValueError, OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())