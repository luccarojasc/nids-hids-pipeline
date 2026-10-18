import argparse
import gzip
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) (?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
RULES = [
    ("ssh_login", "failure", re.compile(
        r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
        r"(?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("ssh_login", "success", re.compile(
        r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
        r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("ssh_invalid_user", "failure", re.compile(
        r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")),
]
SKIP_PREFIXES = ("labels", "attacker")


def open_text(path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def match_header(line):
    m = SYSLOG.match(line)
    if m:
        return "syslog", m
    m = ISO.match(line)
    if m:
        return "iso", m
    return None, None


def classify(msg):
    for action, outcome, rx in RULES:
        e = rx.search(msg)
        if e:
            return action, outcome, e
    return None


def to_utc(kind, m, year, tz_offset_min):
    if kind == "iso":
        raw = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", m["ts"].replace("Z", "+00:00"))
        ts = datetime.fromisoformat(raw)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone(timedelta(minutes=tz_offset_min)))
        return ts.astimezone(timezone.utc)
    h, mi, s = map(int, m["time"].split(":"))
    local = datetime(year, MONTHS[m["mon"]], int(m["day"]), h, mi, s)
    return (local - timedelta(minutes=tz_offset_min)).replace(tzinfo=timezone.utc)


def load_labels(root, log_path):
    rel = log_path.relative_to(root)
    if len(rel.parts) < 2:
        return {}
    cand = root / "labels" / Path(*rel.parts[1:])
    if not cand.is_file():
        return {}
    out = {}
    with open(cand, errors="replace") as fh:
        for raw in fh:
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and "line" in item:
                out[int(item["line"])] = ",".join(map(str, item.get("labels", [])))
    return out


def parse_file(path, root, dataset, scenario, year, tz_offset_min):
    labels = load_labels(root, path)
    rows = []
    prev_month = None
    y = year
    with open_text(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            kind, m = match_header(line)
            if kind is None or not m["prog"].startswith("sshd"):
                continue
            if kind == "syslog":
                month = MONTHS[m["mon"]]
                # syslog não grava o ano: dezembro seguido de janeiro no mesmo arquivo é virada de ano
                if prev_month == 12 and month == 1:
                    y += 1
                prev_month = month
            hit = classify(m["msg"])
            if hit is None:
                continue
            action, outcome, e = hit
            rows.append({
                "@timestamp": to_utc(kind, m, y, tz_offset_min),
                "event.kind": "event",
                "event.category": "authentication",
                "event.action": action,
                "event.outcome": outcome,
                "event.dataset": "system.auth",
                "event.original": line,
                "host.name": m["host"],
                "process.name": "sshd",
                "process.pid": int(m["pid"]) if m["pid"] else None,
                "source.ip": e["ip"],
                "source.port": int(e["port"]) if e["port"] else None,
                "user.name": e["user"],
                "log.file.path": str(path),
                "log.file.line": lineno,
                "labels.dataset": dataset,
                "labels.scenario": scenario,
                "labels.attack": labels.get(lineno, ""),
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description="auth.log (sshd) -> parquet em ECS")
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--year", type=int, required=True)
    ap.add_argument("--tz-offset", type=int, default=0,
                    help="minutos a leste de UTC do relógio que escreveu o log")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    files = sorted(p for p in a.root.rglob("auth.log*")
                   if p.is_file() and not any(part.startswith(SKIP_PREFIXES) for part in p.relative_to(a.root).parts))
    if not files:
        sys.exit(f"nenhum auth.log em {a.root}")
    rows = []
    for f in files:
        rows.extend(parse_file(f, a.root, a.dataset, a.scenario, a.year, a.tz_offset))
    df = pd.DataFrame(rows)
    if df.empty:
        sys.exit("nenhum evento do sshd reconhecido")
    df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True)
    for col in ("process.pid", "source.port"):
        df[col] = df[col].astype("Int64")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.sort_values("@timestamp").to_parquet(a.out, index=False)
    print(f"{len(files)} arquivos, {len(df)} eventos -> {a.out}")
    print(df.groupby(["host.name", "event.action", "event.outcome"]).size().to_string())


if __name__ == "__main__":
    main()