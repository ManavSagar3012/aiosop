import os

from ai_osop.core.env_secret_scan import scan_environ


def test_scan_environ_detects_aws_key_without_logging_value():
    fake_env = {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}
    findings = scan_environ(fake_env)
    assert any(
        f["pattern"] == "aws_access_key" and f["name"] == "AWS_ACCESS_KEY_ID" for f in findings
    )
    text = str(findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in text


def test_scan_environ_ignores_known_safe_variables_and_missing_aws():
    fake_env = {"PATH": "/usr/bin", "HOME": "/home/u"}
    findings = scan_environ(fake_env)
    assert findings == []


def test_scan_environ_flags_jwt_like_values():
    fake_env = {
        "AUTHZ_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    }
    findings = scan_environ(fake_env)
    assert any(f["pattern"] == "jwt_like" for f in findings)
