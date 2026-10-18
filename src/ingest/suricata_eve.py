import argparse
import json
import sys
from pathlib import Path

import pandas as pd


def main():
    ap = argparse.ArgumentParser(description="eve.json (flow) -> parquet em ECS")
    ap.add_argument("--eve", type=Path, nargs="+", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    rows = []
    for eve in a.eve:
        with open(eve, errors="replace") as fh:
            for raw in fh:
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if ev.get("event_type") != "flow" or ev.get("proto") != "TCP":
                    continue
                if a.port and a.port not in (ev.get("dest_port"), ev.get("src_port")):
                    continue
                fl = ev.get("flow", {})
                start = pd.Timestamp(fl.get("start") or ev["timestamp"]).tz_convert("UTC")
                end = pd.Timestamp(fl["end"]).tz_convert("UTC") if fl.get("end") else None
                rows.append({
                    "@timestamp": start,
                    "event.kind": "event",
                    "event.category": "network",
                    "event.action": "tcp_connection",
                    "event.outcome": "failure" if fl.get("state") == "new" else "success",
                    "event.dataset": "suricata.flow",
                    "event.end": end,
                    "suricata.eve.flow_id": (
                        str(ev["flow_id"]) if ev.get("flow_id") is not None else None
                    ),
                    "suricata.eve.flow.state": fl.get("state"),
                    "suricata.eve.flow.reason": fl.get("reason"),
                    "suricata.eve.tcp.state": ev.get("tcp", {}).get("state"),
                    "event.duration": (end - start).value if end is not None else None,
                    "network.transport": "tcp",
                    "network.packets": fl.get("pkts_toserver", 0) + fl.get("pkts_toclient", 0),
                    "source.ip": ev.get("src_ip"),
                    "source.port": ev.get("src_port"),
                    "destination.ip": ev.get("dest_ip"),
                    "destination.port": ev.get("dest_port"),
                    "log.file.path": str(eve),
                    "labels.dataset": a.dataset,
                    "labels.scenario": a.scenario,
                })
    df = pd.DataFrame(rows)
    if df.empty:
        sys.exit("nenhum fluxo TCP reconhecido")
    for col in ("event.duration", "source.port", "destination.port"):
        df[col] = df[col].astype("Int64")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.sort_values("@timestamp").to_parquet(a.out, index=False)
    print(f"{len(df)} fluxos -> {a.out}")
    print(df.groupby(["source.ip", "event.outcome"]).size().sort_values(ascending=False).head(10).to_string())


if __name__ == "__main__":
    main()