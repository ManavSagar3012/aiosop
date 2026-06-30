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


def test_capture_records_interaction_keyed_by_token():
    token = _register()["result"]["token"]
    # Simulate a target fetching the callback URL.
    assert client.get(f"/{token}").status_code == 200
    res = client.post("/mcp/execute", json={
        "tool_name": "oast_poll", "parameters": {"token": token}, "request_id": "r3"}).json()["result"]
    assert res["hit_count"] == 1
    hit = res["interactions"][0]
    assert hit["method"] == "GET" and hit["path"] == f"/{token}"


def test_capture_parses_token_from_subpath():
    token = _register()["result"]["token"]
    client.post(f"/{token}/exfil/data", content=b"secret")
    res = client.post("/mcp/execute", json={
        "tool_name": "oast_poll", "parameters": {"token": token}, "request_id": "r4"}).json()["result"]
    assert res["hit_count"] == 1
    assert res["interactions"][0]["path"] == f"/{token}/exfil/data"


def test_capture_unknown_token_not_stored():
    client.get("/unregistered-token-xyz")
    res = client.post("/mcp/execute", json={
        "tool_name": "oast_poll", "parameters": {"token": "unregistered-token-xyz"},
        "request_id": "r5"}).json()["result"]
    assert res["hit_count"] == 0


def test_capture_returns_gif():
    token = _register()["result"]["token"]
    r = client.get(f"/{token}")
    assert r.headers["content-type"] == "image/gif"
