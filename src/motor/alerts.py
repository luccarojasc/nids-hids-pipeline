"""Uma lógica de alertas parametrizada por B1/B2/B3; nenhuma ação de rede."""
from collections import defaultdict
from itertools import groupby

from motor.contract import stamp, uid
from motor.core import describe, key, replay

MODES = ("B1", "B2", "B3")
KEY_FIELDS = ("dataset", "scenario", "host", "destination_ip", "destination_port", "source_ip")


def snapshot_key(snap):
    return tuple(snap[f] for f in KEY_FIELDS)


def evaluate(snap, user, mode, cfg):
    nh = None if mode == "B1" else user["Nh"]
    nn = snap["Nn_rede"] if mode == "B1" else user["Nn_associado"] if mode == "B3" else None
    h_ok = nh is None or nh >= cfg["host_threshold"]
    n_ok = nn is None or nn >= cfg["network_threshold"]
    scores = []
    if nh is not None:
        scores.append(min(cfg["base_score"], cfg["base_score"] * nh // cfg["host_threshold"]))
    if nn is not None:
        scores.append(min(cfg["base_score"], cfg["base_score"] * nn // cfg["network_threshold"]))
    reason = ("thresholds_met" if h_ok and n_ok else "both_below_threshold" if not h_ok and not n_ok
              else "host_below_threshold" if not h_ok else "network_below_threshold")
    return {"Nh": nh, "Nn": nn, "predicate": h_ok and n_ok, "evidence_score": min(scores),
            "reason": reason, "host_ids": [] if mode == "B1" else list(user["host_ids"]),
            "network_ids": (list(snap["network_ids"]) if mode == "B1" else
                            list(user["network_ids"]) if mode == "B3" else [])}


def detect_case(rows, core_cfg, cfg, case, mode):
    if mode not in MODES:
        raise ValueError("Modo inválido")
    selected = [r for r in rows if mode == "B3" or r["kind"] == ("net" if mode == "B1" else "auth")]
    trace, links, _ = replay(selected, core_cfg, case)
    successes, links_at = defaultdict(list), defaultdict(list)
    for row in selected:
        if row["kind"] == "auth" and row["outcome"] == "success":
            successes[(row["available"], key(row), row["user"])].append(row)
    for link in links:
        links_at[link["t_ns"]].append(link)
    conn_users, ambiguous, success_link = defaultdict(set), set(), {}
    active, alerts, decisions, transitions, checks = {}, [], [], [], []
    observed_until = trace[-1]["t_ns"] if trace else None
    for t, grouped in groupby(trace, key=lambda s: s["t_ns"]):
        if mode == "B3":
            # Todo o lote de associações antes de avaliar criticidade naquele instante.
            for link in links_at[t]:
                cids = link["candidate_ids"]
                success_link[link["host_id"]] = cids
                if len(cids) > 1:
                    ambiguous.update(cids)
                elif len(cids) == 1:
                    conn_users[cids[0]].add(link["user"])
                    if len(conn_users[cids[0]]) > 1 or link["status"].startswith("ambiguous"):
                        ambiguous.add(cids[0])
        for snap in grouped:
            k = snapshot_key(snap)
            users = [None] if mode == "B1" else snap["users"]
            for user in users:
                username = None if user is None else user["user"]
                state_key = (*k, username)
                values = evaluate(snap, user, mode, cfg)
                previous = active.get(state_key)
                alert = previous
                if values["predicate"] and alert is None:
                    alert = {"id": uid([mode, *state_key, t]), "mode": mode, **describe(k),
                             "user": username, "opened_ns": t, "ended_ns": None,
                             "end_reason": "censored_at_replay_end", "observed_until_ns": observed_until,
                             "trigger_Nh": values["Nh"], "trigger_Nn": values["Nn"],
                             "trigger_host_ids": values["host_ids"], "trigger_network_ids": values["network_ids"],
                             "score": cfg["base_score"], "critical": False, "critical_ns": None,
                             "critical_success_id": None, "critical_connection_id": None,
                             "recommended_ttl_s": cfg["base_ttl_s"]}
                    active[state_key] = alert
                    alerts.append(alert)
                    transitions.append({"alert_id": alert["id"], "mode": mode, "t_ns": t,
                                        "action": "open", "score": alert["score"],
                                        "recommended_ttl_s": alert["recommended_ttl_s"]})
                elif not values["predicate"] and alert is not None:
                    alert.update(ended_ns=t, end_reason=values["reason"])
                    transitions.append({"alert_id": alert["id"], "mode": mode, "t_ns": t,
                                        "action": "close", "reason": values["reason"]})
                    del active[state_key]
                    alert = None
                if mode != "B1":
                    for success in sorted(successes[(t, k, username)], key=lambda r: r["id"]):
                        connection = None
                        if previous is None:
                            reason = "no_preexisting_active_alert"
                        elif alert is None:
                            reason = "base_condition_no_longer_met"
                        elif success["start"] <= alert["opened_ns"]:
                            reason = "success_not_strictly_after_trigger"
                        elif t > alert["opened_ns"] + cfg["critical_horizon_ns"]:
                            reason = "outside_critical_horizon"
                        elif alert["critical"]:
                            reason = "already_critical"
                        else:
                            reason = "promoted"
                            if mode == "B3":
                                cids = success_link.get(success["id"], [])
                                if (len(cids) != 1 or cids[0] in ambiguous or
                                        conn_users[cids[0]] != {username}):
                                    reason = "success_connection_not_unique"
                                else:
                                    connection = cids[0]
                        check = {"mode": mode, "t_ns": t, "success_id": success["id"],
                                 "alert_id": previous["id"] if previous else None, "reason": reason}
                        checks.append(check)
                        if reason == "promoted":
                            alert.update(critical=True, critical_ns=t, score=cfg["critical_score"],
                                         critical_success_id=success["id"], critical_connection_id=connection,
                                         recommended_ttl_s=cfg["critical_ttl_s"])
                            transitions.append({"alert_id": alert["id"], "mode": mode, "t_ns": t,
                                                "action": "critical", "success_id": success["id"],
                                                "connection_id": connection, "score": alert["score"],
                                                "recommended_ttl_s": alert["recommended_ttl_s"]})
                decisions.append({"mode": mode, "t_ns": t, **describe(k), "user": username, **values,
                                  "active_alert_id": alert["id"] if alert else None,
                                  "critical": bool(alert and alert["critical"])})
    return {"alerts": alerts, "transitions": transitions, "decisions": decisions,
            "critical_checks": checks, "trace": [{"mode": mode, **s} for s in trace]}


def compare_units(alerts, cfg, modes):
    result = []
    for unit in cfg["analysis_units"]:
        start, end = stamp(unit["start"]), stamp(unit["end"])
        for mode in modes:
            selected = [a for a in alerts if a["mode"] == mode and
                        all(a[f] == unit[f] for f in KEY_FIELDS) and start <= a["opened_ns"] < end]
            result.append({"unit_id": unit["id"], "classification": unit["classification"],
                           "mode": mode, "any_alert_opened": bool(selected), "alerts_opened": len(selected),
                           "alert_ids": [a["id"] for a in selected],
                           "users": sorted({a["user"] for a in selected if a["user"] is not None}),
                           "first_open_ns": min((a["opened_ns"] for a in selected), default=None),
                           "metrics_enabled": False})
    return result