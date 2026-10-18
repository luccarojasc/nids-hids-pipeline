"""Validação e seleção explícita, sem modificar os Parquets de ingestão."""
import hashlib
import ipaddress
import json
from collections import Counter
from pathlib import Path

import pandas as pd

SOURCES = {"auth": "system.auth", "audit": "auditd.log", "net": "tshark.conn"}
COMMON = {"@timestamp", "event.dataset", "event.action", "event.outcome",
          "labels.dataset", "labels.scenario", "log.file.path"}
FIELDS = {
    "auth": {"host.name", "source.ip", "source.port", "user.name", "log.file.line"},
    "audit": set(),
    "net": {"source.ip", "source.port", "destination.ip", "destination.port",
            "network.transport", "event.end", "event.duration",
            "labels.stream", "labels.duration_method"},
}


def missing(value):
    return value is None or bool(pd.isna(value))


def integer(value, field):
    if missing(value) or isinstance(value, bool):
        raise ValueError(f"{field}: inteiro obrigatório")
    n = int(value)
    if n != value:
        raise ValueError(f"{field}: valor não inteiro: {value!r}")
    return n


def stamp(value):
    if missing(value):
        raise ValueError("Timestamp obrigatório ausente")
    ts = pd.Timestamp(value)
    if ts.tzinfo is None:
        raise ValueError(f"Timestamp sem fuso: {value!r}")
    return int(ts.tz_convert("UTC").value)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def uid(parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()


def scope(row):
    return row["dataset"], row["scenario"]


def load_config(path):
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    if cfg["contract_version"] != "semana4_v1":
        raise ValueError("Versão de contrato não suportada")
    for name in ("window_ns", "host_threshold", "network_threshold", "short_max_ns",
                 "host_resolution_ns", "association_max_age_ns"):
        if integer(cfg[name], name) <= 0:
            raise ValueError(f"{name} deve ser positivo")
    if integer(cfg["close_tolerance_ns"], "close_tolerance_ns") < 0:
        raise ValueError("Tolerância negativa")
    if cfg["host_resolution_ns"] != 1_000_000_000:
        raise ValueError("Este contrato usa resolução de host de 1 segundo")
    keys = [scope(c) for c in cfg["cases"]]
    if len(keys) != len(set(keys)):
        raise ValueError("Cenário duplicado")
    for case in cfg["cases"]:
        if (case["start"] is None) != (case["end"] is None):
            raise ValueError("Forneça os dois limites ou nenhum")
        if case["start"] is not None and stamp(case["start"]) >= stamp(case["end"]):
            raise ValueError("Intervalo inválido")
        hosts = [t["host"] for t in case["targets"]]
        if len(hosts) != len(set(hosts)):
            raise ValueError("Host repetido no mapa")
        for target in case["targets"]:
            ipaddress.ip_address(target["ip"])
            if target["port"] != 22 or not target["sensor_path"].startswith("/"):
                raise ValueError("Alvo fora do contrato SSH/22")
    return cfg


def select(row, role, case, cfg):
    """Retorna evento normalizado ou razão explícita de exclusão."""
    if role == "audit":
        return None, "audit_somente_corrobora"
    if role == "auth" and row["event.action"] != "ssh_login":
        return None, "host_acao_fora_do_contador"
    if role == "net" and (row["event.action"] != "tcp_connection"
                          or row["network.transport"] != "tcp"):
        raise ValueError("Evento de rede incompatível")
    target_fields = ("host.name",) if role == "auth" else ("destination.ip", "destination.port")
    if any(missing(row[col]) for col in target_fields):
        return None, "alvo_ausente"
    start = stamp(row["@timestamp"])
    if case["start"] is not None:
        if not stamp(case["start"]) <= start < stamp(case["end"]):
            return None, "fora_do_periodo_por_inicio"
    path = row["log.file.path"]
    if not isinstance(path, str) or not path:
        raise ValueError("Proveniência sem caminho")
    targets = [t for t in case["targets"] if (
        row["host.name"] == t["host"] if role == "auth" else
        row["destination.ip"] == t["ip"] and row["destination.port"] == t["port"]
        and t["sensor_path"] in path)]
    if not targets:
        return None, "fora_do_mapa_de_alvos_sensores"
    if len(targets) != 1:
        raise ValueError("Mapa de alvos ambíguo")
    target = targets[0]
    if missing(row["source.ip"]) or not str(row["source.ip"]):
        return None, "origem_ausente"
    ip = str(ipaddress.ip_address(row["source.ip"]))
    port = None if missing(row["source.port"]) else integer(row["source.port"], "source.port")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Porta de origem inválida")
    result = {
        "kind": role, "dataset": case["dataset"], "scenario": case["scenario"],
        "host": target["host"], "dest": target["ip"], "dport": target["port"],
        "ip": ip, "port": port, "start": start, "path": path,
        "outcome": row["event.outcome"],
    }
    if role == "auth":
        if missing(row["user.name"]) or not str(row["user.name"]):
            return None, "usuario_ausente"
        if row["event.outcome"] not in ("success", "failure"):
            raise ValueError("Resultado de autenticação incompatível")
        line = integer(row["log.file.line"], "log.file.line")
        if line < 1:
            raise ValueError("Linha física deve começar em 1")
        resolution = cfg["host_resolution_ns"]
        result.update(user=str(row["user.name"]), line=line,
                      available=(start // resolution + 1) * resolution)
        result["id"] = uid([*scope(result), role, path, line])
    else:
        if port is None:
            raise ValueError("Conexão sem porta de origem")
        if row["labels.duration_method"] != cfg["duration_method"]:
            raise ValueError("Método de duração divergente")
        end_missing, dur_missing = missing(row["event.end"]), missing(row["event.duration"])
        if end_missing != dur_missing:
            raise ValueError("Fim e duração devem ser simultaneamente ausentes")
        end = None if end_missing else stamp(row["event.end"])
        duration = None if dur_missing else integer(row["event.duration"], "event.duration")
        if end is not None and (end < start or end - start != duration):
            raise ValueError("Duração negativa ou inconsistente com início/fim")
        stream = integer(row["labels.stream"], "labels.stream")
        if stream < 0:
            raise ValueError("Stream negativo")
        result.update(end=end, duration=duration, stream=stream)
        result["id"] = uid([*scope(result), role, path, stream])
    return result, None


def deduplicate(events):
    """Deduplica a mesma identidade; conflitos e sobreposições exigem revisão."""
    unique, duplicate_ids = {}, []
    for row in events:
        old = unique.get(row["id"])
        if old is not None:
            if old != row:
                raise ValueError(f"Identidade com conteúdo divergente: {row['id']}")
            duplicate_ids.append(row["id"])
        else:
            unique[row["id"]] = row
    rows = sorted(unique.values(), key=lambda r: (r["start"], r["id"]))
    # Assinaturas equivalentes entre arquivos não são fundidas silenciosamente.
    signatures = {}
    for row in rows:
        signature = (*scope(row), row["kind"], row["host"], row["ip"], row["port"],
                     row["dest"], row["dport"], row["start"], row.get("user"), row["outcome"])
        if row["kind"] == "net":
            signature = signature[:-2]  # ignora outcome; identidade parte do SYN
        if signature in signatures and (row["kind"] == "net" or signatures[signature] != row["path"]):
            raise ValueError(f"Possível duplicata em identidades distintas: {row['id']}")
        signatures[signature] = row["path"]
    nets = [r for r in rows if r["kind"] == "net"]
    for i, left in enumerate(nets):
        for right in nets[i + 1:]:
            key = lambda r: (*scope(r), r["ip"], r["port"], r["dest"], r["dport"])
            if (key(left) == key(right) and left["path"] != right["path"]
                    and left["end"] is not None and right["start"] <= left["end"]):
                raise ValueError("Conexões sobrepostas entre arquivos: revisar antes do replay")
    return rows, duplicate_ids


def load_inputs(root, cfg):
    root = Path(root).resolve()
    cases = {scope(c): c for c in cfg["cases"]}
    events, manifest, excluded, seen_paths = [], [], [], set()
    for spec in cfg["inputs"]:
        path = (root / spec["path"]).resolve()
        if root not in path.parents or path in seen_paths:
            raise ValueError("Entrada fora do projeto ou repetida na configuração")
        seen_paths.add(path)
        df = pd.read_parquet(path)
        role = spec["role"]
        required = COMMON | FIELDS[role]
        if required - set(df.columns):
            raise ValueError(f"{path.name}: campos ausentes {sorted(required - set(df.columns))}")
        if len(df) != spec["rows"]:
            raise ValueError(f"{path.name}: {len(df)} linhas; referência {spec['rows']}")
        for col, expected in (("labels.dataset", spec["dataset"]),
                              ("labels.scenario", spec["scenario"]),
                              ("event.dataset", SOURCES[role])):
            if not df[col].eq(expected).fillna(False).all():
                raise ValueError(f"{path.name}: conteúdo incompatível em {col}")
        manifest.append({"path": str(path), "rows": len(df), "sha256": sha(path),
                         "columns": sorted(df.columns), "role": role})
        for index, raw in enumerate(df.to_dict("records"), 1):
            event, reason = select(raw, role, cases[scope(spec)], cfg)
            if reason:
                excluded.append({"input": str(path), "row_1based": index, "reason": reason})
            else:
                events.append(event)
    events, duplicates = deduplicate(events)
    summary = {
        "input_rows": sum(x["rows"] for x in manifest), "selected_events": len(events),
        "selected_by_kind": dict(Counter(e["kind"] for e in events)),
        "excluded_by_reason": dict(Counter(e["reason"] for e in excluded)),
        "duplicate_rows": len(duplicates), "duplicate_ids": duplicates,
    }
    if not events:
        raise ValueError("Nenhum evento selecionado")
    return events, manifest, excluded, summary