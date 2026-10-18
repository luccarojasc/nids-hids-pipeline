from ingest.auditd import parse_file

LINE = (
    "type=USER_AUTH msg=audit(1642760102.345:812): pid=4242 uid=0 auid=4294967295 ses=4294967295 "
    "msg='op=PAM:authentication grantors=? acct=\"admin\" exe=\"/usr/sbin/sshd\" "
    "hostname=10.0.0.9 addr=10.0.0.9 terminal=ssh res=failed'"
)


def write(tmp_path, text):
    log = tmp_path / "web-01" / "audit.log"
    log.parent.mkdir()
    log.write_text(text + "\n")
    return log


def test_user_auth_failed(tmp_path):
    [row] = parse_file(write(tmp_path, LINE), tmp_path, "t", "t")
    assert row["event.outcome"] == "failure"
    assert (row["user.name"], row["source.ip"], row["process.pid"]) == ("admin", "10.0.0.9", 4242)
    assert row["host.name"] == "web-01"
    assert row["@timestamp"].year == 2022


def test_hex_encoded_acct(tmp_path):
    [row] = parse_file(write(tmp_path, LINE.replace('acct="admin"', "acct=61646D696E")), tmp_path, "t", "t")
    assert row["user.name"] == "admin"