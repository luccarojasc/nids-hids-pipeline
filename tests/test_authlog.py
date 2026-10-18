from datetime import datetime, timezone

from ingest.authlog import classify, match_header, parse_file, to_utc

FAILED = "Jan 21 10:15:02 web-01 sshd[4242]: Failed password for invalid user admin from 10.0.0.9 port 51514 ssh2"
ACCEPTED = "Jan 21 10:17:40 web-01 sshd[4300]: Accepted password for alice from 10.0.0.9 port 51600 ssh2"
INVALID = "Jan 21 10:15:01 web-01 sshd[4242]: Invalid user admin from 10.0.0.9 port 51514"
OTHER = "Jan 21 10:15:03 web-01 CRON[99]: pam_unix(cron:session): session opened for user root"


def test_failed():
    kind, m = match_header(FAILED)
    action, outcome, e = classify(m["msg"])
    assert (kind, action, outcome) == ("syslog", "ssh_login", "failure")
    assert (e["user"], e["ip"], e["port"]) == ("admin", "10.0.0.9", "51514")


def test_accepted():
    _, m = match_header(ACCEPTED)
    action, outcome, e = classify(m["msg"])
    assert (action, outcome, e["user"]) == ("ssh_login", "success", "alice")


def test_invalid_user():
    _, m = match_header(INVALID)
    action, outcome, _ = classify(m["msg"])
    assert (action, outcome) == ("ssh_invalid_user", "failure")


def test_non_sshd_is_ignored():
    _, m = match_header(OTHER)
    assert not m["prog"].startswith("sshd")


def test_timezone_offset():
    kind, m = match_header(FAILED)
    assert to_utc(kind, m, 2022, 60) == datetime(2022, 1, 21, 9, 15, 2, tzinfo=timezone.utc)


def test_year_rollover(tmp_path):
    log = tmp_path / "h1" / "auth.log"
    log.parent.mkdir()
    log.write_text(
        "Dec 31 23:59:59 h1 sshd[1]: Failed password for bob from 10.0.0.1 port 1 ssh2\n"
        "Jan  1 00:00:01 h1 sshd[2]: Failed password for bob from 10.0.0.1 port 2 ssh2\n"
    )
    rows = parse_file(log, tmp_path, "t", "t", 2021, 0)
    assert [r["@timestamp"].year for r in rows] == [2021, 2022]