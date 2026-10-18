import argparse
import subprocess
import sys
from pathlib import Path

import pandas as pd

FIELDS = ["tcp.stream", "frame.time_epoch", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset"]
TRUE = {"1", "True", "true"}
DEFAULT_FILTER = "tcp.port==22 && (tcp.flags.syn==1 || tcp.flags.fin==1 || tcp.flags.reset==1)"


def packets(pcap, display_filter):
    cmd = ["nice", "-n", "19", "tshark", "-r", str(pcap), "-n", "-Y", display_filter,
           "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        parts = line.rstrip("\n").split("\t")
        if len(parts) == len(FIELDS) and parts[0] and parts[2]:
            yield dict(zip(FIELDS, parts))
    if proc.wait() != 0:
        sys.exit(f"tshark terminou com código {proc.returncode} em {pcap}")


def connections(rows):
    conns = {}
    for r in rows:
        c = conns.setdefault(r["tcp.stream"], {"start": None, "end": None, "client": None, "established": False})
        t = float(r["frame.time_epoch"])
        syn, ack = r["tcp.flags.syn"] in TRUE, r["tcp.flags.ack"] in TRUE
        if syn and not ack and c["client"] is None:
            c["start"] = t
            c["client"] = (r["ip.src"], int(r["tcp.srcport"]), r["ip.dst"], int(r["tcp.dstport"]))
        elif syn and ack:
            c["established"] = True
        if r["tcp.flags.fin"] in TRUE or r["tcp.flags.reset"] in TRUE:
            c["end"] = t if c["end"] is None else max(c["end"], t)
    return conns


def to_rows(conns, pcap, dataset, scenario):
    for stream, c in conns.items():
        if c["client"] is None:
            continue
        sip, sport, dip, dport = c["client"]
        dur = c["end"] - c["start"] if c["end"] is not None else None
        yield {
            "@timestamp": pd.Timestamp(c["start"], unit="s", tz="UTC"),
            "event.kind": "event",
            "event.category": "network",
            "event.action": "tcp_connection",
            "event.outcome": "success" if c["established"] else "failure",
            "event.dataset": "tshark.conn",
            "event.duration": int(dur * 1e9) if dur is not None else None,
            "network.transport": "tcp",
            "source.ip": sip,
            "source.port": sport,
            "destination.ip": dip,
            "destination.port": dport,
            "log.file.path": str(pcap),
            "labels.dataset": dataset,
            "labels.scenario": scenario,
            "labels.stream": int(stream),
        }


def main():
    ap = argparse.ArgumentParser(description="PCAP -> conexões TCP em ECS, via tshark")
    ap.add_argument("--pcap", type=Path, nargs="+", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--filter", default=DEFAULT_FILTER)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    rows = []
    for pcap in a.pcap:
        rows.extend(to_rows(connections(packets(pcap, a.filter)), pcap, a.dataset, a.scenario))
    df = pd.DataFrame(rows)
    if df.empty:
        sys.exit("nenhuma conexão reconhecida")
    df["event.duration"] = df["event.duration"].astype("Int64")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.sort_values("@timestamp").to_parquet(a.out, index=False)
    print(f"{len(df)} conexões -> {a.out}")
    print(df.groupby(["source.ip", "event.outcome"]).size().sort_values(ascending=False).head(10).to_string())


if __name__ == "__main__":
    main()