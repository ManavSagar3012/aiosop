import importlib.util, os
from fastapi.testclient import TestClient

_PATH = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "python", "oast_mcp.py")
_spec = importlib.util.spec_from_file_location("oast_mcp", _PATH)
oast = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oast)
client = TestClient(oast.app)


def _register(label="t"):
    r = client.post("/mcp/execute", json={
        "tool_name": "oast_register", "parameters": {"label": label}, "request_id": "r1"})
    assert r.status_code == 200
    return r.json()


def test_health_ready():
    assert client.get("/health").json()["status"] == "ready"


def test_register_returns_token_and_callback_url():
    body = _register()
    assert body["status"] == "success"
    res = body["result"]
    assert len(res["token"]) == 20
    assert res["callback_url"].endswith("/" + res["token"])
    assert res["callback_url"].startswith("http://")


def test_register_tokens_are_unique():
    a = _register()["result"]["token"]
    b = _register()["result"]["token"]
    assert a != b


def test_poll_unknown_token_is_empty():
    r = client.post("/mcp/execute", json={
        "tool_name": "oast_poll", "parameters": {"token": "doesnotexist"}, "request_id": "r2"})
    res = r.json()["result"]
    assert res["hit_count"] == 0 and res["interactions"] == []
