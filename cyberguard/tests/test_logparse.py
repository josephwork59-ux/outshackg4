from tools.logparse import parse_line


def test_parses_syslog_auth_failure():
    line = "Sep  6 01:12:03 host sshd[20441]: Failed password for invalid user admin from 203.0.113.66 port 51422 ssh2"
    ev = parse_line(line, "auth.log", "syslog")
    assert ev is not None
    assert ev.kind == "auth_fail"
    assert ev.source_ip == "203.0.113.66"
    assert ev.process == "sshd"


def test_parses_syslog_auth_success():
    line = "Sep  6 01:13:02 host sshd[1]: Accepted password for deploy from 10.4.2.9 port 40122 ssh2"
    ev = parse_line(line, "auth.log", "syslog")
    assert ev.kind == "auth_ok"


def test_parses_nginx_combined():
    line = '198.51.100.23 - - [06/Sep/2026:01:30:11 +0000] "GET /a?id=1 HTTP/1.1" 500 812 "-" "sqlmap/1.7"'
    ev = parse_line(line, "access.log", "nginx")
    assert ev.kind == "http"
    assert ev.source_ip == "198.51.100.23"
    assert ev.http_status == 500
    assert ev.http_path == "/a?id=1"
    assert "sqlmap" in ev.fields["ua"]


def test_blank_line_is_none():
    assert parse_line("   ", "x") is None
