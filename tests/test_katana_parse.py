"""Test the security-bridge katana output parser (P1.2 fix).

The Go server returns katana's raw JSONL under 'raw' (its whole-output
json.Unmarshal fails on multi-line JSONL), so the adapter must parse it.
"""
from ai_osop.adapters.security_bridge_mcp import SecurityBridgeAdapter

_parse = SecurityBridgeAdapter._parse_katana_output


def test_parse_jsonl_raw():
    raw = "\n".join([
        '{"timestamp":"t","request":{"endpoint":"https://x.com/a?id=1"}}',
        '{"request":{"endpoint":"https://x.com/app.js"}}',
        '{"endpoint":"https://x.com/api/users"}',
    ])
    eps, js = _parse({"data": None, "raw": raw})
    assert "https://x.com/a?id=1" in eps
    assert "https://x.com/api/users" in eps
    assert js == ["https://x.com/app.js"]


def test_parse_plain_lines():
    raw = "https://x.com/1\nhttps://x.com/2\nnot-a-url\n"
    eps, js = _parse({"raw": raw})
    assert eps == ["https://x.com/1", "https://x.com/2"]


def test_parse_structured_data_and_dedup():
    data = [
        {"request": {"endpoint": "https://x.com/dup"}},
        "https://x.com/dup",  # duplicate, different shape
        "https://x.com/main.js",
    ]
    eps, js = _parse({"data": data})
    assert eps == ["https://x.com/dup"]
    assert js == ["https://x.com/main.js"]


def test_parse_empty():
    assert _parse({}) == ([], [])
    assert _parse({"raw": ""}) == ([], [])
