"""Replay determinístico de contadores. Não gera alertas B1/B2/B3."""
from collections import defaultdict
from itertools import groupby

from motor.contract import scope, stamp


def key(row):
    return (*scope(row), row["host"], row["dest"], row["dport"], row["ip"])


def describe(k):
    return dict(zip(("dataset", "scenario", "host", "destination_ip",
                     "destination_port", "source_ip"), k))


def replay(events, cfg, case):
    window = cfg["window_ns"]
    stop = None if case["end"] is None else stamp(case["end"])
    timeline = []
    for row in events:
        if scope(row) != scope(case):
            raise ValueError("Execute um cenário por replay")
        if row["kind"] == "auth":
            timeline.append((row["available"], 2, row["id"], "auth", row))
        else:
            timeline.append((row["start"], 0, row["id"], "open", row))
            if row["end"] is not None:
                timeline.append((row["end"], 1, row["id"], "close", row))
        timeline.append((row["start"] + window, 3, row["id"], "expire", row))
    timeline.sort(key=lambda x: x[:3])
    conns, hosts, keys = {}, [], set()
    trace, links = [], []
    for t, grouped in groupby(timeline, key=lambda item: item[0]):
        if stop is not None and t >= stop:
            break
        for _, _, _, action, row in grouped:
            k = key(row)
            if action == "open":
                keys.add(k)
                # Fim disponível apenas quando o evento close for processado.
                conns[row["id"]] = {"row": row, "known_end": None, "users": set(),
                                    "host_ids": [], "uncertain": False}
            elif action == "close":
                conns[row["id"]]["known_end"] = t
            elif action == "auth":
                keys.add(k)
                hosts.append(row)
                candidates = []
                if row["port"] is not None:
                    for cid, state in conns.items():
                        net = state["row"]
                        same = key(net) == k and net["port"] == row["port"]
                        # Host representa o intervalo [timestamp, timestamp+1s).
                        temporal = (row["start"] - cfg["association_max_age_ns"]
                                    <= net["start"] < row["available"])
                        end = state["known_end"]
                        compatible_end = (end is None or
                                          end >= row["start"] - cfg["close_tolerance_ns"])
                        if same and temporal and compatible_end:
                            candidates.append(cid)
                if len(candidates) == 1:
                    state = conns[candidates[0]]
                    state["users"].add(row["user"])
                    state["host_ids"].append(row["id"])
                    if len(state["users"]) > 1:
                        state["uncertain"] = True
                    status = "ambiguous_user" if state["uncertain"] else "unique_at_time"
                elif len(candidates) > 1:
                    status = "ambiguous_connection"
                    for cid in candidates:
                        conns[cid]["uncertain"] = True
                else:
                    status = "missing_port" if row["port"] is None else "no_candidate"
                links.append({"t_ns": t, "host_id": row["id"], "user": row["user"],
                              "candidate_ids": sorted(candidates), "status": status,
                              **describe(k)})
        # Snapshot somente após todo o lote no mesmo instante lógico.
        for k in sorted(keys):
            failures = [h for h in hosts if key(h) == k and h["outcome"] == "failure"
                        and t - window < h["start"] <= t]
            short = []
            for cid, state in conns.items():
                net, end = state["row"], state["known_end"]
                if (key(net) == k and end is not None and end <= t
                        and t - window < net["start"] <= t
                        and 0 < end - net["start"] <= cfg["short_max_ns"]):
                    short.append(cid)
            users = sorted({h["user"] for h in hosts if key(h) == k})
            by_user = []
            for user in users:
                hids = sorted(h["id"] for h in failures if h["user"] == user)
                nids = sorted(cid for cid in short if conns[cid]["users"] == {user}
                              and not conns[cid]["uncertain"])
                by_user.append({"user": user, "Nh": len(hids), "Nn_associado": len(nids),
                                "host_ids": hids, "network_ids": nids})
            trace.append({"t_ns": t, **describe(k), "Nn_rede": len(short),
                          "network_ids": sorted(short), "users": by_user,
                          "Nn_sem_usuario_unico": sum(not conns[cid]["users"] or
                                                      conns[cid]["uncertain"] for cid in short)})
    final = []
    for cid, state in sorted(conns.items()):
        final.append({"connection_id": cid, "known_end_ns": state["known_end"],
                      "users": sorted(state["users"]), "host_ids": sorted(state["host_ids"]),
                      "status": ("ambiguous" if state["uncertain"] else
                                 "unique" if len(state["users"]) == 1 else "unknown")})
    return trace, links, final


def maxima(trace):
    groups = defaultdict(lambda: {"max_Nn_rede": 0, "users": {}})
    for snap in trace:
        k = (snap["dataset"], snap["scenario"], snap["host"], snap["source_ip"])
        item = groups[k]
        item["max_Nn_rede"] = max(item["max_Nn_rede"], snap["Nn_rede"])
        for user in snap["users"]:
            entry = item["users"].setdefault(user["user"], {"max_Nh": 0, "max_Nn_associado": 0})
            entry["max_Nh"] = max(entry["max_Nh"], user["Nh"])
            entry["max_Nn_associado"] = max(entry["max_Nn_associado"], user["Nn_associado"])
    return [{"dataset": k[0], "scenario": k[1], "host": k[2], "source_ip": k[3], **v}
            for k, v in sorted(groups.items())]