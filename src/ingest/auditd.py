import argparse
import gzip
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

HEAD = re.compile(
    r"^(?:node=(?P<node>\S+) )?type=(?P<type>\S+) "
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\): ?(?P<body>.*)$"
)
KV = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
TYPES = {"USER_AUTH", "USER_LOGIN", "USER_ACCT", "USER_START", "CRED_ACQ"}
SKIP_PREFIXES = ("labels", "attacker")
CONTAINERS = {"gather", "logs", "log", "var", "audit"}
# Correspondências verificadas entre diretórios/identificadores e hostnames.
HOST_ALIASES = {
    ("camlds", "scenario_3_ssh_puppet", "reposerver"): "puppet",
    ("ait", "russellmitchell", "intranet_server"): "intranet-server",
}


def open_text(path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def kv(text):
    return {k: v for k, v in reversed(KV.findall(text))}


def unquote(v):
    if v and v[0] in "\"'":
        return v[1:-1]
    # auditd grava sem aspas, em hexadecimal, valores com espaço ou caracteres especiais
    if v and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-F]+", v):
        try:
            return bytes.fromhex(v).decode()
        except (ValueError, UnicodeDecodeError):
            return v
    return v


def host_from_path(root, path):
    for part in path.relative_to(root).parts[:-1]:
        if part not in CONTAINERS:
            return part
    return root.name


def parse_file(path, root, dataset, scenario):
    host = host_from_path(root, path)
    rows = []
    with open_text(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n").split("\x1d")[0]
            m = HEAD.match(line)
            if not m or m["type"] not in TYPES:
                continue
            outer = kv(m["body"])
            inner = kv(outer.get("msg", "")[1:-1])
            if "sshd" not in unquote(inner.get("exe", "")):
                continue
            addr = inner.get("addr", "?")
            res = inner.get("res", "")
            pid = outer.get("pid", "")
            rows.append({
                "@timestamp": datetime.fromtimestamp(float(m["epoch"]), tz=timezone.utc),
                "event.kind": "event",
                "event.category": "authentication",
                "event.action": f"auditd_{m['type'].lower()}",
                "event.outcome": {"success": "success", "failed": "failure"}.get(res, "unknown"),
                "event.dataset": "auditd.log",
                "event.sequence": int(m["serial"]),
                "event.original": line,
                "host.name": HOST_ALIASES.get(
                    (dataset, scenario, m["node"] or host),
                    m["node"] or host,
                ),
                "labels.host_original": m["node"] or host,
                "process.name": "sshd",
                "process.pid": int(pid) if pid.isdigit() else None,
                "source.ip": None if addr in ("?", "") else addr,
                "user.name": unquote(inner.get("acct", "")) or None,
                "log.file.path": str(path),
                "log.file.line": lineno,
                "labels.dataset": dataset,
                "labels.scenario": scenario,
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description="audit.log (sshd/PAM) -> parquet em ECS")
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    files = sorted(p for p in a.root.rglob("audit.log*")
                   if p.is_file() and not any(part.startswith(SKIP_PREFIXES) for part in p.relative_to(a.root).parts))
    if not files:
        sys.exit(f"nenhum audit.log em {a.root}")
    rows = []
    for f in files:
        rows.extend(parse_file(f, a.root, a.dataset, a.scenario))
    df = pd.DataFrame(rows)
    if df.empty:
        sys.exit("nenhum registro do sshd reconhecido")
    df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True)
    df["process.pid"] = df["process.pid"].astype("Int64")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.sort_values("@timestamp").to_parquet(a.out, index=False)
    print(f"{len(files)} arquivos, {len(df)} registros -> {a.out}")
    print(df.groupby(["host.name", "event.action", "event.outcome"]).size().to_string())


if __name__ == "__main__":
    main()