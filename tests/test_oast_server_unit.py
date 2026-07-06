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


def _register_ctx(context):
    return client.post("/mcp/execute", json={
        "tool_name": "oast_register",
        "parameters": {"label": "p", "context": context},
        "request_id": "rc"}).json()["result"]["token"]


def _drain(since=0, engagement_id=None):
    params = {"since": since}
    if engagement_id:
        params["engagement_id"] = engagement_id
    return client.post("/mcp/execute", json={
        "tool_name": "oast_drain", "parameters": params, "request_id": "rd"}).json()["result"]


def test_interaction_has_seq_and_kind():
    token = _register()["result"]["token"]
    client.get(f"/{token}")
    hit = client.post("/mcp/execute", json={
        "tool_name": "oast_poll", "parameters": {"token": token},
        "request_id": "rp"}).json()["result"]["interactions"][0]
    assert hit["kind"] == "http" and isinstance(hit["seq"], int) and hit["interaction_id"]


def test_drain_echoes_probe_context():
    ctx = {"engagement_id": "engS", "vuln_class": "ssrf", "injection_point": "url"}
    token = _register_ctx(ctx)
    client.get(f"/{token}")
    res = _drain(since=0)
    mine = [i for i in res["interactions"] if i["token"] == token]
    assert len(mine) == 1
    assert mine[0]["context"] == ctx


def test_drain_cursor_only_returns_fresh_interactions():
    token = _register_ctx({"engagement_id": "engCur"})
    client.get(f"/{token}")
    first = _drain(since=0, engagement_id="engCur")
    assert first["count"] == 1
    # Re-draining from the returned cursor yields nothing new.
    second = _drain(since=first["cursor"], engagement_id="engCur")
    assert second["count"] == 0


def test_drain_engagement_filter():
    t1 = _register_ctx({"engagement_id": "engA"})
    t2 = _register_ctx({"engagement_id": "engB"})
    client.get(f"/{t1}")
    client.get(f"/{t2}")
    res = _drain(since=0, engagement_id="engA")
    tokens = {i["token"] for i in res["interactions"]}
    assert t1 in tokens and t2 not in tokens
