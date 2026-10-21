"""Política determinística: não chama subprocessos nem modifica firewall."""
import hashlib
import ipaddress
import json
from collections import Counter

NS = 1_000_000_000
FIELDS = ("dataset", "scenario", "host", "destination_ip", "destination_port", "source_ip")
MODES = ("B1", "B2", "B3")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_config(cfg):
    expected = {"contract_version": "semana6_v1", "base_ttl_s": 900, "critical_ttl_s": 1800,
                "base_score": 50, "critical_score": 100, "service_port": 22,
                "clock": "logical_ns", "executor": "simulation_only",
                "renewal": "max_existing_and_request_deadline", "close_policy": "keep_until_expiry",
                "drain_timers": True}
    for key, value in expected.items():
        if type(cfg.get(key)) is not type(value) or cfg[key] != value:
            raise ValueError(f"Configuração fora de semana6_v1: {key}")


def validate(command, cfg):
    if command["mode"] not in MODES or command["kind"] not in ("open", "critical", "close"):
        raise ValueError("Modo ou transição inválida")
    if type(command["t_ns"]) is not int or command["t_ns"] < 0:
        raise ValueError("Tempo lógico inválido")
    if not all(isinstance(command[x], str) and command[x] for x in ("request_id", "alert_id")):
        raise ValueError("Identificador ausente")
    scope = command["scope"]
    if set(scope) != set(FIELDS):
        raise ValueError("Escopo incompleto")
    if not all(isinstance(scope[x], str) and scope[x] for x in ("dataset", "scenario", "host")):
        raise ValueError("Identidade de escopo inválida")
    for field in ("destination_ip", "source_ip"):
        ip = ipaddress.ip_address(scope[field])
        if ip.version != 4 or str(ip) != scope[field] or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Esta versão requer IPv4 unicast explícito")
    if type(scope["destination_port"]) is not int or scope["destination_port"] != cfg["service_port"]:
        raise ValueError("Serviço fora do contrato")
    if command["kind"] != "close":
        critical = command["kind"] == "critical"
        if critical and command["mode"] == "B1":
            raise ValueError("B1 não recebe criticidade de host")
        if type(command["ttl_s"]) is not int or command["ttl_s"] != cfg["critical_ttl_s" if critical else "base_ttl_s"]:
            raise ValueError("TTL incompatível com a transição")
        if type(command["score"]) is not int or command["score"] != cfg["critical_score" if critical else "base_score"]:
            raise ValueError("Score incompatível com a transição")


def from_transitions(alerts, transitions, cfg):
    """Usa o score/TTL da transição, nunca o estado final retroativamente."""
    by_id = {a["id"]: a for a in alerts}
    if len(by_id) != len(alerts):
        raise ValueError("Alertas repetidos")
    commands = []
    for tr in transitions:
        alert = by_id[tr["alert_id"]]
        if tr["mode"] != alert["mode"]:
            raise ValueError("Modo divergente do alerta")
        kind = tr["action"]
        expected_time = {"open": alert["opened_ns"], "critical": alert["critical_ns"],
                         "close": alert["ended_ns"]}.get(kind)
        if expected_time is None or tr["t_ns"] != expected_time:
            raise ValueError("Transição sem correspondência temporal no alerta")
        item = {"request_id": digest([tr["alert_id"], kind, tr["t_ns"]]),
                "alert_id": tr["alert_id"], "mode": tr["mode"], "kind": kind,
                "t_ns": tr["t_ns"], "scope": {f: alert[f] for f in FIELDS},
                "ttl_s": tr.get("recommended_ttl_s"), "score": tr.get("score")}
        validate(item, cfg)
        commands.append(item)
    return sorted(commands, key=lambda c: (c["t_ns"], {"open": 0, "critical": 1, "close": 2}[c["kind"]], c["request_id"]))


def simulate(commands, cfg):
    check_config(cfg)
    ordered = sorted(commands, key=lambda c: (c["t_ns"], {"open": 0, "critical": 1, "close": 2}.get(c["kind"], 3), c["request_id"]))
    active, seen, opened, promoted, closed = {}, {}, {}, set(), set()
    actions = []

    def record(action, t, key, previous, until, command=None):
        scope = dict(zip(FIELDS, key[1:]))
        actions.append({"seq": len(actions) + 1, "action": action, "t_ns": t,
                        "mode": key[0], "scope": scope, "previous_expires_ns": previous,
                        "expires_ns": until, "request_id": command["request_id"] if command else None,
                        "alert_id": command["alert_id"] if command else None,
                        "executor": "simulation_only", "projected_timer": action == "expire"})

    def expire(t):
        due = sorted((v, k) for k, v in active.items() if v <= t)
        for until, key in due:
            record("expire", until, key, until, None)
            del active[key]

    for command in ordered:
        validate(command, cfg)
        t = command["t_ns"]
        expire(t)
        key = (command["mode"], *(command["scope"][f] for f in FIELDS))
        rid = command["request_id"]
        if rid in seen:
            if seen[rid] != command:
                raise ValueError("Mesmo ID com conteúdo diferente")
            record("duplicate_ignored", t, key, active.get(key), active.get(key), command)
            continue
        seen[rid] = command
        aid, kind = command["alert_id"], command["kind"]
        if kind == "open":
            if aid in opened:
                raise ValueError("Segunda abertura do mesmo alerta")
            opened[aid] = (key, t)
        else:
            if aid not in opened or opened[aid][0] != key or t < opened[aid][1]:
                raise ValueError("Transição sem abertura compatível")
            if aid in closed:
                raise ValueError("Transição após encerramento do alerta")
            if kind == "critical":
                if aid in promoted or t <= opened[aid][1]:
                    raise ValueError("Promoção repetida ou sem ordem estrita")
                promoted.add(aid)
        old = active.get(key)
        if kind == "close":
            closed.add(aid)
            record("close_ignored", t, key, old, old, command)
            continue
        candidate = t + command["ttl_s"] * NS
        until = max(old or candidate, candidate)
        action = "apply" if old is None else "renew" if until > old else "retain"
        active[key] = until
        record(action, t, key, old, until, command)
    if active:
        expire(max(active.values()))
    summary = {"executor": "simulation_only", "metrics_enabled": False,
               "timers_drained": True, "active_at_end": len(active),
               "counts": [{"mode": mode, **{name: sum(x["mode"] == mode and x["action"] == name for x in actions)
                          for name in ("apply", "renew", "retain", "expire", "close_ignored", "duplicate_ignored")}}
                          for mode in MODES],
               "unique_requests": len(seen),
               "transition_kinds": dict(Counter(x["kind"] for x in seen.values()))}
    return actions, summary