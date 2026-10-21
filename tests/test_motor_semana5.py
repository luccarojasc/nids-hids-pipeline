import json
import shutil
from pathlib import Path

import pandas as pd
import pytest

from motor.alerts import MODES, compare_units, detect_case, evaluate
from motor.contract import load_config as load_core
from motor.detect import BASE_FILES, execute, load_config, preflight, verify
from motor.rules import UniqueLoader, base_evidence, load_rules, matches
from motor.run import execute as execute_week4
import yaml

ROOT = Path(__file__).resolve().parents[1]
NS = 1_000_000_000


def settings():
    core = load_core(ROOT / "config/motor-semana4.json")
    cfg = load_config(ROOT / "config/motor-semana5.json")
    return core, cfg, core["cases"][0]


def net(i, start=0, end=1, port=None):
    return {"id": f"n{i}", "kind": "net", "dataset": "camlds", "scenario": "scenario_3_ssh_puppet",
            "host": "puppet", "dest": "172.17.100.122", "dport": 22, "ip": "192.42.1.174",
            "port": 1000 + i if port is None else port, "start": start * NS,
            "end": None if end is None else end * NS,
            "duration": None if end is None else (end - start) * NS,
            "path": "/cam/inetfw/log.pcap.1", "stream": i, "outcome": "success"}


def host(i, t=0, user="alice", outcome="failure", port=None):
    r = net(i, t, None, port)
    r.update(id=f"h{i}", kind="auth", user=user, outcome=outcome,
             available=(t + 1) * NS, line=i + 1, path="/cam/reposerver/auth.log")
    return r


def burst(offset=0, start=0):
    return [net(i, start, start + 1) for i in range(offset, offset + 10)] + [
        host(i, start) for i in range(offset, offset + 10)]


def run(rows, mode="B3", case=None):
    core, cfg, default_case = settings()
    return detect_case(rows, core, cfg, case or default_case, mode)


@pytest.mark.parametrize("mode", MODES)
def test_positive_trigger_only_once_and_at_evidence_availability(mode):
    result = run(burst(), mode)
    assert len(result["alerts"]) == 1
    a = result["alerts"][0]
    assert a["opened_ns"] == NS and a["ended_ns"] == 300 * NS
    assert a["score"] == 50 and a["recommended_ttl_s"] == 900


@pytest.mark.parametrize("mode,kind", [("B1", "net"), ("B2", "auth")])
def test_baseline_has_no_dependency_on_other_plane(mode, kind):
    rows = burst() + [host(90, 50, "other", "success"), net(99, 60, 61)]
    assert run(rows, mode) == run([r for r in rows if r["kind"] == kind], mode)


def test_B3_does_not_use_all_connections_for_each_user():
    rows = [net(i) for i in range(10)] + [host(i, port=1000 + i % 3) for i in range(5)]
    assert len(run(rows, "B1")["alerts"]) == 1
    assert len(run(rows, "B2")["alerts"]) == 1
    result = run(rows)
    assert not result["alerts"]
    assert any(x["Nh"] == 5 and x["Nn"] == 3 and x["reason"] == "network_below_threshold"
               for x in result["decisions"])


def test_false_then_true_rearms():
    assert len(run(burst() + burst(20, 400))["alerts"]) == 2


@pytest.mark.parametrize("mode", ["B2", "B3"])
def test_later_same_user_success_promotes_once(mode):
    rows = burst() + [net(20, 2, None), host(20, 2, outcome="success"),
                      net(21, 4, None), host(21, 4, outcome="success")]
    result = run(rows, mode)
    a = result["alerts"][0]
    assert a["critical"] and a["critical_ns"] == 3 * NS
    assert a["score"] == 100 and a["recommended_ttl_s"] == 1800
    assert sum(t["action"] == "critical" for t in result["transitions"]) == 1


def test_B1_never_uses_success_for_criticality():
    r = run(burst() + [host(20, 2, outcome="success")], "B1")
    assert not r["alerts"][0]["critical"] and not r["critical_checks"]


@pytest.mark.parametrize("time,reason", [(0, "no_preexisting_active_alert"),
                                        (1, "success_not_strictly_after_trigger")])
def test_success_before_or_tied_with_trigger_does_not_promote(time, reason):
    r = run(burst() + [host(20, time, outcome="success")], "B2")
    assert not r["alerts"][0]["critical"]
    assert reason in {x["reason"] for x in r["critical_checks"]}


def test_different_user_success_does_not_promote():
    r = run(burst() + [host(20, 2, "bob", "success")], "B2")
    assert not r["alerts"][0]["critical"]


def test_no_promotion_after_condition_expires():
    r = run(burst() + [host(20, 299, outcome="success")], "B2")
    assert not r["alerts"][0]["critical"]
    assert r["critical_checks"][0]["reason"] == "base_condition_no_longer_met"


def test_no_promotion_outside_horizon_even_if_alert_still_active():
    r = run(burst() + burst(20, 290) + [host(50, 302, outcome="success")], "B2")
    assert len(r["alerts"]) == 1 and not r["alerts"][0]["critical"]
    assert r["critical_checks"][0]["reason"] == "outside_critical_horizon"


def test_B3_requires_unique_success_connection_after_entire_batch():
    rows = burst() + [net(20, 2, None), host(20, 2, outcome="success"),
                      host(21, 2, user="bob", port=1020)]
    r = run(rows)
    assert not r["alerts"][0]["critical"]
    assert r["critical_checks"][0]["reason"] == "success_connection_not_unique"


def test_later_ambiguity_closes_B3_but_preserves_alert_history():
    r = run(burst() + [host(20, 1, user="bob", port=1000)])
    assert len(r["alerts"]) == 1
    assert r["alerts"][0]["opened_ns"] == NS
    assert r["alerts"][0]["ended_ns"] == 2 * NS


def test_censoring_does_not_invent_episode_end():
    _, _, case = settings()
    case = dict(case, start="1970-01-01T00:00:00Z", end="1970-01-01T00:00:02Z")
    a = run(burst(), case=case)["alerts"][0]
    assert a["ended_ns"] is None and a["end_reason"] == "censored_at_replay_end"


def test_score_cannot_compensate_missing_plane():
    _, cfg, _ = settings()
    s = {"Nn_rede": 1000, "network_ids": []}
    u = {"Nh": 100, "Nn_associado": 0, "host_ids": [], "network_ids": []}
    v = evaluate(s, u, "B3", cfg)
    assert not v["predicate"] and v["evidence_score"] == 0


def test_common_unit_does_not_duplicate_B1_per_user():
    _, cfg, _ = settings()
    unit = dict(cfg["analysis_units"][0], start="1970-01-01T00:00:00Z", end="1970-01-01T00:05:01Z")
    cfg["analysis_units"] = [unit]
    rows = burst()
    rows += [host(i, user="bob", port=2000 + i) for i in range(20, 25)]
    alerts = run(rows, "B1")["alerts"] + run(rows, "B2")["alerts"]
    result = compare_units(alerts, cfg, ("B1", "B2"))
    assert result[0]["alerts_opened"] == 1 and result[0]["users"] == []
    assert result[1]["alerts_opened"] == 2 and result[1]["any_alert_opened"]


def test_rules_match_only_expected_base_events_and_ns_limits():
    core, cfg, _ = settings()
    rules = load_rules(ROOT, cfg)
    rows = [host(1), host(2, outcome="success"), net(3, 0, 5), net(4, 0, 6), net(5, 0, None)]
    hits = base_evidence(rows, rules, core)
    assert {h["event_id"] for h in hits} == {"h1", "h2", "n3"}
    assert next(h for h in hits if h["rule"] == "short")["available_ns"] == 5 * NS
    assert matches(rules["failure"], {"event.dataset": "SYSTEM.AUTH", "event.action": "ssh_login", "event.outcome": "failure"})


def test_yaml_duplicate_keys_and_unsupported_condition_fail(tmp_path):
    with pytest.raises(ValueError, match="repetida"):
        yaml.load("a: 1\na: 2\n", Loader=UniqueLoader)
    _, cfg, _ = settings()
    shutil.copytree(ROOT / "rules", tmp_path / "rules")
    p = tmp_path / cfg["rules"]["failure"]
    p.write_text(p.read_text().replace("condition: selection", "condition: selection or other"))
    with pytest.raises(ValueError, match="condition"):
        load_rules(tmp_path, cfg)


def test_rule_drift_stops_instead_of_silently_changing_counts():
    core, cfg, _ = settings()
    rules = load_rules(ROOT, cfg)
    rules["short"]["detection"]["selection"]["event.duration|lte"] = 1
    with pytest.raises(ValueError, match="divergente"):
        base_evidence([net(1)], rules, core)


def test_exists_means_presence_and_missing_end_is_omitted():
    rule = {"detection": {"selection": {"event.end|exists": True}}}
    assert matches(rule, {"event.end": None})
    assert not matches(rule, {})
    core, cfg, _ = settings()
    assert not base_evidence([net(1, 0, None)], load_rules(ROOT, cfg), core)


def test_deterministic_alerts_with_reordered_inputs():
    rows = burst() + [net(20, 2, None), host(20, 2, outcome="success")]
    assert run(rows) == run(list(reversed(rows)))


def reference_fixture(root):
    core, cfg, case = settings()
    core["cases"] = [case]
    core["inputs"] = []
    for relative in BASE_FILES:
        p = root / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, p)
    for role in ("auth", "net"):
        records = []
        for r in [e for e in burst() if e["kind"] == role]:
            item = {"@timestamp": pd.Timestamp(r["start"], unit="ns", tz="UTC"),
                    "labels.dataset": r["dataset"], "labels.scenario": r["scenario"],
                    "event.dataset": "system.auth" if role == "auth" else "tshark.conn",
                    "event.action": "ssh_login" if role == "auth" else "tcp_connection",
                    "event.outcome": r["outcome"], "log.file.path": r["path"],
                    "source.ip": r["ip"], "source.port": r["port"]}
            if role == "auth":
                item.update({"host.name": r["host"], "user.name": r["user"], "log.file.line": r["line"]})
            else:
                item.update({"destination.ip": r["dest"], "destination.port": 22, "network.transport": "tcp",
                             "event.end": pd.Timestamp(r["end"], unit="ns", tz="UTC"), "event.duration": r["duration"],
                             "labels.stream": r["stream"], "labels.duration_method": core["duration_method"]})
            records.append(item)
        p = root / f"{role}.parquet"
        pd.DataFrame(records).to_parquet(p, index=False)
        core["inputs"].append({"path": p.name, "rows": len(records), "role": role, **dict(zip(("dataset", "scenario"), scope_case(case)))})
    (root / "config").mkdir(exist_ok=True)
    p = root / "config/motor-semana4.json"
    p.write_text(json.dumps(core))
    execute_week4(root, p, root / "reference")
    manifest = json.loads((root / "reference/manifest.json").read_text())
    cfg.update(reference_dir="reference", reference_code_sha256=manifest["code_sha256"],
               reference_config_sha256=manifest["config_sha256"], expected_input_rows=20, expected_selected_events=20)
    cfg["analysis_units"] = [dict(cfg["analysis_units"][0], start="1970-01-01T00:00:00Z", end="1970-01-01T00:05:01Z")]
    p5 = root / "config/motor-semana5.json"
    p5.write_text(json.dumps(cfg))
    shutil.copytree(ROOT / "rules", root / "rules")
    return p5


def scope_case(case):
    return case["dataset"], case["scenario"]


def test_full_package_preflight_execution_verify_and_integrity(tmp_path):
    cfg = reference_fixture(tmp_path)
    preflight(tmp_path, cfg)
    out = tmp_path / "out5"
    execute(tmp_path, cfg, out, MODES)
    assert (out / "SUCCESS").is_file()
    summary = json.loads((out / "summary.json").read_text())
    assert [x["alerts"] for x in summary["counts"]] == [1, 1, 1]
    verify(out)
    with pytest.raises(FileExistsError):
        execute(tmp_path, cfg, out, MODES)
    with (out / "alerts.jsonl").open("a") as fh:
        fh.write("{}\n")
    with pytest.raises(ValueError, match="alterada"):
        verify(out)
    (tmp_path / BASE_FILES[2]).write_text("# changed\n")
    with pytest.raises(ValueError, match="Semana 4 alterado"):
        preflight(tmp_path, cfg)