from tools.redaction import looks_like_secret, redact


def test_redacts_aws_key():
    out = redact('AWS_ACCESS_KEY_ID = "AKIAJ7EXAMPLE9DEMO42"')
    assert "AKIAJ7EXAMPLE9DEMO42" not in out
    assert "REDACTED" in out


def test_redacts_generic_secret_assignment():
    out = redact("api_key: s3cr3t_value_123456")
    assert "s3cr3t_value_123456" not in out


def test_redacts_private_key_block():
    blob = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    assert "abc" not in redact(blob)


def test_keeps_ip_addresses():
    # IPs are evidence and must survive redaction
    assert "203.0.113.66" in redact("Failed password from 203.0.113.66 port 22")


def test_looks_like_secret_detects_and_ignores():
    assert looks_like_secret('token = "abcdef123456"')
    assert looks_like_secret("AKIAJ7EXAMPLE9DEMO42")
    assert looks_like_secret("just a normal log line") is None
