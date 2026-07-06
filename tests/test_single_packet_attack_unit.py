"""Offline unit tests for the raw single-packet request builder (no network)."""
import importlib.util
import os

_PATH = os.path.join(
    os.path.dirname(__file__), "..", "mcp-servers", "python", "turbo_intruder_mcp.py"
)
_spec = importlib.util.spec_from_file_location("turbo_intruder_mcp", _PATH)
turbo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(turbo)


def test_get_request_has_host_and_connection_close():
    raw = turbo._build_raw_request("GET", "example.com", "/x?q=1", {}, "")
    text = raw.decode()
    assert text.startswith("GET /x?q=1 HTTP/1.1\r\n")
    assert "Host: example.com\r\n" in text
    assert "Connection: close\r\n" in text
    assert text.endswith("\r\n\r\n")


def test_post_sets_content_length_and_appends_body():
    body = '{"amount":100}'
    raw = turbo._build_raw_request("POST", "h", "/pay", {"X-Token": "abc"}, body)
    text = raw.decode()
    assert f"Content-Length: {len(body)}\r\n" in text
    assert "X-Token: abc\r\n" in text
    assert text.endswith("\r\n\r\n" + body)


def test_caller_headers_do_not_duplicate_host_or_length():
    raw = turbo._build_raw_request(
        "POST", "h", "/p", {"Host": "evil", "Content-Length": "999"}, "ab"
    )
    text = raw.decode()
    assert text.count("Host:") == 1 and "Host: h\r\n" in text
    assert text.count("Content-Length:") == 1 and "Content-Length: 2\r\n" in text
