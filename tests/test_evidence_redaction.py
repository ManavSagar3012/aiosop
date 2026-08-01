from ai_osop.evidence.redaction import redact_headers, redact_text


def test_redact_headers_scrubs_authorization_and_cookie() -> None:
    headers = {
        "Authorization": "Bearer sk-live-token",
        "Cookie": "session=abc123",
        "X-Api-Key": "key-xyz",
        "User-Agent": "AI-OSOP/1.0",
    }
    out = redact_headers(headers)
    assert out["User-Agent"] == "AI-OSOP/1.0"
    for h in ("Authorization", "Cookie", "X-Api-Key"):
        assert "[REDACTED:" in out[h]
        assert "sk-live-token" not in out[h]
        assert "abc123" not in out[h]


def test_redact_text_masks_long_hex_and_bearer_tokens() -> None:
    body = 'token=deadbeefcafe0123456789abcdef header: Bearer abcdef0123456789abcd'
    out = redact_text(body)
    assert "deadbeefcafe0123456789abcdef" not in out
    assert "abcdef0123456789abcd" not in out
    assert "[REDACTED" in out
