"""Subconjunto explícito de seleções Sigma; não é um backend Sigma geral."""
from pathlib import Path
from uuid import UUID

import yaml


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for k, v in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in result:
            raise ValueError(f"Chave YAML repetida: {key}")
        result[key] = loader.construct_object(v, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def load_rules(root, cfg):
    if set(cfg["rules"]) != {"failure", "success", "short"}:
        raise ValueError("Forneça exatamente três regras-base")
    rules, ids = {}, set()
    root = Path(root).resolve()
    for name, relative in cfg["rules"].items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("Regra requer caminho relativo sem ..")
        path = (root / relative).resolve()
        if root not in path.parents:
            raise ValueError("Regra fora da raiz")
        rule = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
        if not isinstance(rule, dict):
            raise ValueError("Regra deve ser um mapa YAML")
        for field in ("title", "id", "status", "description", "logsource", "detection", "level"):
            if field not in rule:
                raise ValueError(f"Regra {name} sem {field}")
        UUID(rule["id"])
        if rule["id"] in ids:
            raise ValueError("IDs de regra repetidos")
        ids.add(rule["id"])
        category = "network_connection" if name == "short" else "authentication"
        if rule["logsource"] != {"product": "tcc_pipeline", "category": category}:
            raise ValueError("Logsource fora do adaptador local")
        detection = rule["detection"]
        if set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
            raise ValueError("Somente condition: selection é suportada")
        if not isinstance(detection["selection"], dict) or not detection["selection"]:
            raise ValueError("Seleção vazia ou não suportada")
        for field, value in detection["selection"].items():
            pieces = field.split("|")
            if len(pieces) > 2 or (len(pieces) == 2 and pieces[1] not in ("gt", "lte", "exists")):
                raise ValueError(f"Modificador não suportado: {field}")
            modifier = pieces[1] if len(pieces) == 2 else "eq"
            if modifier == "exists" and not isinstance(value, bool):
                raise ValueError("exists requer booleano")
            if modifier in ("gt", "lte") and type(value) not in (int, float):
                raise ValueError("Comparação numérica requer número")
            if modifier == "eq" and (type(value) not in (str, int, bool)
                                      or isinstance(value, str) and any(c in value for c in "*?\\")):
                raise ValueError("Somente literais simples; sem listas/wildcards")
        rules[name] = rule
    return rules


def matches(rule, event):
    for expression, expected in rule["detection"]["selection"].items():
        field, *modifiers = expression.split("|")
        modifier = modifiers[0] if modifiers else "eq"
        if modifier == "exists":
            if (field in event) != expected:
                return False
            continue
        if field not in event:
            return False
        value = event[field]
        if modifier in ("gt", "lte"):
            if type(value) not in (int, float):
                return False
            if not (value > expected if modifier == "gt" else value <= expected):
                return False
        elif isinstance(value, str) and isinstance(expected, str):
            if value.casefold() != expected.casefold():
                return False
        elif type(value) is not type(expected) or value != expected:
            return False
    return True


def base_evidence(rows, rules, core_cfg):
    """Agenda evidências; selecionar uma conexão não a disponibiliza no SYN."""
    hits = []
    for row in rows:
        if row["kind"] == "auth":
            event = {"event.dataset": "system.auth", "event.action": "ssh_login",
                     "event.outcome": row["outcome"]}
            expected = {"failure"} if row["outcome"] == "failure" else {"success"}
            available = row["available"]
        else:
            event = {"event.dataset": "tshark.conn", "event.action": "tcp_connection",
                     "network.transport": "tcp", "destination.port": row["dport"],
                     "labels.duration_method": core_cfg["duration_method"]}
            if row["end"] is not None:
                event.update({"event.end": row["end"], "event.duration": row["duration"],
                              "labels.evidence_phase": "closed"})
            expected = ({"short"} if row["duration"] is not None and
                        0 < row["duration"] <= core_cfg["short_max_ns"] else set())
            available = row["end"]
        found = {name for name, rule in rules.items() if matches(rule, event)}
        if found != expected:
            raise ValueError(f"Regra divergente do contrato do núcleo: {row['id']}")
        for name in sorted(found):
            hits.append({"event_id": row["id"], "rule": name,
                         "rule_id": rules[name]["id"], "available_ns": available})
    return sorted(hits, key=lambda h: (h["available_ns"], h["event_id"], h["rule"]))