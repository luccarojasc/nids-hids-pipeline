import argparse
import gzip
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

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
EVENTS = [
    ("failed", re.compile(
        r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
        r"(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("accepted", re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
        r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")),
]
KINDS = [k for k, _ in EVENTS]


def open_text(path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path)
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    files = sorted(p for p in args.root.rglob("auth.log*")
                   if p.is_file() and "labels" not in p.relative_to(args.root).parts)
    if not files:
        sys.exit(f"nenhum auth.log em {args.root}")

    fmt = Counter()
    sshd_lines = 0
    unparsed = Counter()
    per_day = defaultdict(Counter)
    ips = {k: Counter() for k in KINDS}
    users = {k: Counter() for k in KINDS}
    samples = {}

    for f in files:
        with open_text(f) as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                m = SYSLOG.match(line)
                if m:
                    fmt["syslog"] += 1
                    day = f"{MONTHS[m['mon']]:02d}-{int(m['day']):02d}"
                else:
                    m = ISO.match(line)
                    if not m:
                        fmt["desconhecido"] += 1
                        continue
                    fmt["iso8601"] += 1
                    day = m["ts"][:10]
                if not m["prog"].startswith("sshd"):
                    continue
                sshd_lines += 1
                for kind, rx in EVENTS:
                    e = rx.search(m["msg"])
                    if e:
                        per_day[(m["host"], day)][kind] += 1
                        ips[kind][e["ip"]] += 1
                        users[kind][e["user"]] += 1
                        samples.setdefault(kind, f"{f.name}: {line}")
                        break
                else:
                    unparsed[re.sub(r"\d+", "N", m["msg"])[:70]] += 1

    print(f"arquivos ({len(files)}):")
    for f in files:
        print(f"  {f}")
    print(f"\nformato das linhas: {dict(fmt)}")
    print(f"linhas do sshd: {sshd_lines}")
    print("\nhost | dia | failed | invalid_user | accepted")
    for (host, day), c in sorted(per_day.items()):
        print(f"{host} | {day} | {c['failed']} | {c['invalid_user']} | {c['accepted']}")
    for kind in KINDS:
        print(f"\ntop IPs [{kind}]: {ips[kind].most_common(args.top)}")
        print(f"top usuários [{kind}]: {users[kind].most_common(args.top)}")
    print("\nexemplos:")
    for kind, s in samples.items():
        print(f"  [{kind}] {s}")
    print("\nmensagens do sshd não classificadas (mais comuns):")
    for msg, n in unparsed.most_common(args.top):
        print(f"  {n:7d}  {msg}")


if __name__ == "__main__":
    main()