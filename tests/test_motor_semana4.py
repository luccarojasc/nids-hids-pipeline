import copy
import json
from pathlib import Path

import pandas as pd
import pytest

from motor.contract import deduplicate, load_config, select, stamp
from motor.core import replay
from motor.run import execute, verify

NS = 1_000_000_000
CONFIG = Path(__file__).resolve().parents[1] / "config/motor-semana4.json"


def setup():
    cfg = load_config(CONFIG)
    return cfg, cfg["cases"][0]


def net(name="n", start=0, end=2, port=1000):
    return {"id": name, "kind": "net", "dataset": "camlds", "scenario": "scenario_3_ssh_puppet",
            "host": "puppet", "dest": "172.17.100.122", "dport": 22,
            "ip": "192.42.1.174", "port": port, "start": int(start * NS),
            "end": None if end is None else int(end * NS),
            "duration": None if end is None else int((end - start) * NS),
            "path": "/cam/inetfw/log.pcap.1", "stream": 1, "outcome": "success"}


def host(name="h", t=1, user="alice", port=1000, outcome="failure"):
    row = net(name, t, None, port)
    row.update(kind="auth", user=user, available=(t + 1) * NS, outcome=outcome,
               path="/cam/reposerver/auth.log", line=1)
    return row


def snaps(events):
    cfg, case = setup()
    return replay(events, cfg, case)


def at(trace, seconds):
    return next(s for s in trace if s["t_ns"] == int(seconds * NS))


def test_network_not_available_before_close_and_host_bucket_end():
    trace, _, _ = snaps([net(end=3), host()])
    assert at(trace, 0)["Nn_rede"] == 0
    assert at(trace, 2)["users"][0]["Nh"] == 1
    assert at(trace, 2)["Nn_rede"] == 0
    assert at(trace, 3)["users"][0]["Nn_associado"] == 1


def test_left_boundary_expires_without_new_packets():
    trace, _, _ = snaps([net(), host(t=0)])
    assert at(trace, 2)["Nn_rede"] == 1
    assert at(trace, 300)["Nn_rede"] == 0
    assert at(trace, 300)["users"][0]["Nh"] == 0


@pytest.mark.parametrize("end, expected", [(None, 0), (0, 0), (5, 1), (6, 0)])
def test_duration_limits(end, expected):
    trace, _, _ = snaps([net(end=end)])
    assert max(s["Nn_rede"] for s in trace) == expected


def test_two_users_revoke_association_without_rewriting_past():
    trace, _, final = snaps([net(), host(), host("h2", t=3, user="bob")])
    assert at(trace, 2)["users"][0]["Nn_associado"] == 1
    assert all(u["Nn_associado"] == 0 for u in at(trace, 4)["users"])
    assert at(trace, 4)["Nn_rede"] == 1
    assert final[0]["status"] == "ambiguous"


def test_reused_port_multiple_live_candidates_is_ambiguous():
    _, links, final = snaps([net("old", end=None), net("new", start=1, end=3), host(t=1)])
    assert links[0]["status"] == "ambiguous_connection"
    assert all(c["status"] == "ambiguous" for c in final)


def test_future_syn_cannot_match_earlier_host():
    _, links, _ = snaps([host(t=0), net(start=2, end=3)])
    assert links[0]["status"] == "no_candidate"


def test_fractional_syn_in_host_second_can_match():
    _, links, _ = snaps([host(t=0), net(start=0.7, end=2)])
    assert links[0]["status"] == "unique_at_time"


def test_missing_port_preserves_host_failure_only():
    trace, links, _ = snaps([host(port=None), net()])
    assert links[0]["status"] == "missing_port"
    assert at(trace, 2)["users"][0]["Nh"] == 1
    assert at(trace, 2)["users"][0]["Nn_associado"] == 0


def test_network_counter_independent_of_host_and_success_not_failure():
    only, _, _ = snaps([net()])
    both, _, _ = snaps([net(), host(outcome="success")])
    assert at(only, 2)["network_ids"] == at(both, 2)["network_ids"]
    assert at(both, 2)["users"][0]["Nh"] == 0


def test_target_isolation():
    other = host()
    other.update(host="other", dest="10.0.0.2")
    _, links, _ = snaps([net(), other])
    assert links[0]["status"] == "no_candidate"


def test_determinism_with_equal_timestamps():
    rows = [net(), host(), host("h2", user="bob")]
    assert snaps(rows) == snaps(list(reversed(rows)))


def test_deduplication_and_conflicts():
    row = net()
    events, duplicates = deduplicate([row, copy.deepcopy(row)])
    assert len(events) == 1 and duplicates == ["n"]
    changed = dict(row, end=4 * NS)
    with pytest.raises(ValueError, match="divergente"):
        deduplicate([row, changed])


def test_cross_file_duplicate_is_not_silently_merged():
    with pytest.raises(ValueError, match="duplicata"):
        deduplicate([net(), dict(net("copy"), path="/other/log.pcap")])


def test_cross_file_overlap_stops():
    with pytest.raises(ValueError, match="sobrepostas"):
        deduplicate([net(end=4), dict(net("next", 3, 5), path="/other/log.pcap")])


def test_same_second_distinct_host_lines_are_preserved():
    first = host()
    second = dict(host("h2"), line=2)
    rows, _ = deduplicate([first, second])
    assert len(rows) == 2


def raw_net():
    return {"@timestamp": pd.Timestamp("2025-12-12T12:42:34Z"),
            "event.dataset": "tshark.conn", "event.action": "tcp_connection",
            "event.outcome": "success", "labels.dataset": "camlds",
            "labels.scenario": "scenario_3_ssh_puppet", "log.file.path": "/cam/inetfw/log.pcap.1",
            "source.ip": "192.42.1.174", "source.port": 1000,
            "destination.ip": "172.17.100.122", "destination.port": 22,
            "network.transport": "tcp", "event.end": pd.Timestamp("2025-12-12T12:42:36Z"),
            "event.duration": 2 * NS, "labels.stream": 1,
            "labels.duration_method": "syn_to_first_fin_or_rst_v1"}


def raw_host():
    row = raw_net()
    row.update({"event.dataset": "system.auth", "event.action": "ssh_login",
                "event.outcome": "failure", "host.name": "puppet", "user.name": "admin",
                "log.file.path": "/cam/reposerver/auth.log", "log.file.line": 42})
    return row


def test_contract_audit_and_invalid_user_do_not_enter_Nh():
    cfg, case = setup()
    assert select({}, "audit", case, cfg)[1] == "audit_somente_corrobora"
    assert select({"event.action": "ssh_invalid_user"}, "auth", case, cfg)[0] is None


def test_contract_duration_mismatch_and_naive_time_stop():
    cfg, case = setup()
    row = raw_net()
    row["event.duration"] = 1
    with pytest.raises(ValueError, match="inconsistente"):
        select(row, "net", case, cfg)
    with pytest.raises(ValueError, match="sem fuso"):
        stamp("2022-01-21T00:00:00")


def test_ait_period_is_half_open():
    cfg, _ = setup()
    case = cfg["cases"][1]
    row = raw_host()
    row.update({"host.name": "mail", "@timestamp": pd.Timestamp(case["start"])})
    assert select(row, "auth", case, cfg)[0] is not None
    row["@timestamp"] = pd.Timestamp(case["end"])
    assert select(row, "auth", case, cfg)[1] == "fora_do_periodo_por_inicio"


def test_replay_respects_period_end():
    cfg, case = setup()
    case = dict(case, start="1970-01-01T00:00:00Z", end="1970-01-01T00:00:02Z")
    trace, _, _ = replay([net(end=2)], cfg, case)
    assert all(s["t_ns"] < 2 * NS and s["Nn_rede"] == 0 for s in trace)


def test_roundtrip_parquet_outputs_and_tamper_detection(tmp_path):
    cfg, case = setup()
    cfg["cases"] = [case]
    cfg["inputs"] = []
    for role, data in (("auth", raw_host()), ("net", raw_net())):
        name = f"{role}.parquet"
        pd.DataFrame([data]).to_parquet(tmp_path / name, index=False)
        cfg["inputs"].append({"path": name, "role": role, "rows": 1,
                               "dataset": case["dataset"], "scenario": case["scenario"]})
    config = tmp_path / "config.json"
    config.write_text(json.dumps(cfg), encoding="utf-8")
    out = tmp_path / "run"
    execute(tmp_path, config, out)
    assert (out / "SUCCESS").is_file()
    verify(out)
    with pytest.raises(FileExistsError):
        execute(tmp_path, config, out)
    with (out / "trace.jsonl").open("a") as fh:
        fh.write("{}\n")
    with pytest.raises(ValueError, match="alterada"):
        verify(out)