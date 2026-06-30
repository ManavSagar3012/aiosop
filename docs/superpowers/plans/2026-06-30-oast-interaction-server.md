# OAST Interaction Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-hosted OAST interaction server (HTTP callback capture) and wire blind-SSRF confirmation into `vuln_agent`, minting a validated finding only when a real out-of-band callback is captured.

**Architecture:** A new FastAPI MCP server (`oast-mcp`, port 8099) exposes `oast_register`/`oast_poll` tools and a catch-all route that records any inbound request keyed by a per-probe token. An `OASTAdapter` wraps it. A new `ssrf_scan` task registers a token, injects the callback URL into a target sink (query param or POST body field), sends the request, polls for a captured callback, and mints `Vulnerability(SSRF, CWE-918, validated=True)` on a hit.

**Tech Stack:** Python 3.11, FastAPI + uvicorn (matches `browser_mcp.py`/`turbo_intruder_mcp.py`), httpx, Pydantic models, Neo4j-backed `graph_memory`.

**Reference spec:** `docs/superpowers/specs/2026-06-30-oast-interaction-server-design.md`

---

## File Structure

- **Create** `mcp-servers/python/oast_mcp.py` — the OAST server (MCP tools + capture).
- **Create** `src/ai_osop/adapters/oast_mcp.py` — `OASTAdapter`.
- **Create** `tests/test_oast_server_unit.py` — offline TestClient unit tests.
- **Create** `.runlogs/validate_ssrf_oast_e2e.py` — live Juice Shop validation harness.
- **Modify** `src/ai_osop/core/config.py` — add oast settings.
- **Modify** `src/ai_osop/agents/vuln_agent.py` — `ssrf_scan` task + adapter wiring.
- **Modify** `launch_real.ps1` — start oast-mcp on 8099.

---

## Task 1: OAST server — register/poll tools + token store

**Files:**
- Create: `mcp-servers/python/oast_mcp.py`
- Test: `tests/test_oast_server_unit.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oast_server_unit.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_oast_server_unit.py -q -p no:cacheprovider --no-cov`
Expected: FAIL (module `oast_mcp.py` does not exist / import error).

- [ ] **Step 3: Write minimal implementation**

```python
# mcp-servers/python/oast_mcp.py
import argparse
import os
import threading
import time
import uuid
from typing import Any, Dict, List

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response
from pydantic import BaseModel

app = FastAPI(title="OAST Interaction MCP Server")

# In-memory, lock-guarded correlation state.
_LOCK = threading.Lock()
_TOKENS: Dict[str, Dict[str, Any]] = {}            # token -> {label, created_at}
_INTERACTIONS: Dict[str, List[Dict[str, Any]]] = {}  # token -> [interaction]
_TTL = 3600.0

# Reachability (the configurable-hybrid knob); overridden in __main__ from env/args.
PUBLIC_HOST = os.environ.get("OAST_PUBLIC_HOST", "127.0.0.1")
PORT = int(os.environ.get("OAST_PORT", "8099"))
SCHEME = os.environ.get("OAST_SCHEME", "http")

# 1x1 transparent GIF so <img>/fetch beacons get a valid response.
_GIF = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b"
)


def _prune_locked() -> None:
    now = time.time()
    for tok in list(_TOKENS):
        if now - _TOKENS[tok]["created_at"] > _TTL:
            _TOKENS.pop(tok, None)
            _INTERACTIONS.pop(tok, None)


@app.get("/health")
async def health():
    return {"status": "ready", "server": "oast-mcp"}


@app.post("/mcp/initialize")
async def initialize():
    return {
        "server_id": "oast-mcp",
        "capabilities": ["tool"],
        "status": "ready",
        "tools": [
            {"name": "oast_register",
             "description": "Mint an OAST correlation token and callback URL.",
             "parameters": {"type": "object", "properties": {
                 "label": {"type": "string"}}, "required": []}},
            {"name": "oast_poll",
             "description": "Return captured out-of-band interactions for a token.",
             "parameters": {"type": "object", "properties": {
                 "token": {"type": "string"}}, "required": ["token"]}},
        ],
    }


class ExecuteRequest(BaseModel):
    tool_name: str
    parameters: dict
    request_id: str


@app.post("/mcp/execute")
async def execute(req: ExecuteRequest):
    p = req.parameters
    if req.tool_name == "oast_register":
        with _LOCK:
            _prune_locked()
            token = uuid.uuid4().hex[:20]
            _TOKENS[token] = {"label": p.get("label", ""), "created_at": time.time()}
            _INTERACTIONS[token] = []
        url = f"{SCHEME}://{PUBLIC_HOST}:{PORT}/{token}"
        return {"request_id": req.request_id, "status": "success",
                "result": {"token": token, "callback_url": url}}
    if req.tool_name == "oast_poll":
        token = p.get("token", "")
        with _LOCK:
            hits = list(_INTERACTIONS.get(token, []))
        return {"request_id": req.request_id, "status": "success",
                "result": {"token": token, "hit_count": len(hits), "interactions": hits}}
    return {"request_id": req.request_id, "status": "error",
            "error": f"unknown tool: {req.tool_name}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--public-host", default=PUBLIC_HOST)
    parser.add_argument("--scheme", default=SCHEME)
    args = parser.parse_args()
    PORT = args.port
    PUBLIC_HOST = args.public_host
    SCHEME = args.scheme
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/test_oast_server_unit.py -q -p no:cacheprovider --no-cov`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add mcp-servers/python/oast_mcp.py tests/test_oast_server_unit.py
git commit -m "feat(oast): register/poll tools + token store"
```

---

## Task 2: OAST server — catch-all capture route

**Files:**
- Modify: `mcp-servers/python/oast_mcp.py` (append the capture route before `__main__`)
- Test: `tests/test_oast_server_unit.py` (add capture tests)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_oast_server_unit.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_oast_server_unit.py -k capture -q -p no:cacheprovider --no-cov`
Expected: FAIL (catch-all route not defined; requests to `/{token}` return 404).

- [ ] **Step 3: Write minimal implementation**

Insert this route into `mcp-servers/python/oast_mcp.py` immediately BEFORE the `if __name__ == "__main__":` block. It MUST be defined after `/health` and `/mcp/*` so those explicit routes take precedence (FastAPI matches in definition order):

```python
@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def capture(full_path: str, request: Request):
    """Catch-all: record any inbound request as an interaction keyed by the token
    in the first path segment. A captured callback is the ground-truth signal that
    a blind vulnerability fired."""
    token = full_path.split("/", 1)[0] if full_path else ""
    if token:
        try:
            raw = await request.body()
            body_snippet = raw[:512].decode("utf-8", "replace")
        except Exception:
            body_snippet = ""
        with _LOCK:
            if token in _TOKENS:
                _INTERACTIONS.setdefault(token, []).append({
                    "ts": time.time(),
                    "method": request.method,
                    "path": "/" + full_path,
                    "source_ip": request.client.host if request.client else "",
                    "headers": {k: v for k, v in request.headers.items()
                                if k.lower() in ("user-agent", "host", "referer", "x-forwarded-for")},
                    "body_snippet": body_snippet,
                })
    return Response(content=_GIF, media_type="image/gif")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/test_oast_server_unit.py -q -p no:cacheprovider --no-cov`
Expected: PASS (8 tests — the 4 from Task 1 plus 4 capture tests).

- [ ] **Step 5: Commit**

```bash
git add mcp-servers/python/oast_mcp.py tests/test_oast_server_unit.py
git commit -m "feat(oast): catch-all callback capture keyed by token"
```

---

## Task 3: OAST settings in config

**Files:**
- Modify: `src/ai_osop/core/config.py` (add fields to the `Settings` class, near the other `*_mcp_timeout` fields)

- [ ] **Step 1: Locate the Settings fields**

Run: `grep -n "mcp_timeout" src/ai_osop/core/config.py | head`
Expected: lines showing existing fields like `nuclei_mcp_timeout`, `browser_mcp_timeout`.

- [ ] **Step 2: Add OAST settings**

Add these fields to the `Settings` class alongside the existing `*_mcp_timeout` fields (match the surrounding style — they are plain typed fields with defaults):

```python
    # OAST interaction server (R1). public_host is the configurable-hybrid knob:
    # 127.0.0.1 for local validation, a real domain when running against external targets.
    oast_public_host: str = "127.0.0.1"
    oast_port: int = 8099
    oast_scheme: str = "http"
    oast_mcp_timeout: int = 30
```

- [ ] **Step 3: Verify it imports**

Run: `.venv/Scripts/python.exe -c "from ai_osop.core.config import settings; print(settings.oast_public_host, settings.oast_port, settings.oast_scheme)"`
Expected: `127.0.0.1 8099 http`

- [ ] **Step 4: Commit**

```bash
git add src/ai_osop/core/config.py
git commit -m "feat(oast): add oast_* settings (configurable-hybrid reachability)"
```

---

## Task 4: OASTAdapter

**Files:**
- Create: `src/ai_osop/adapters/oast_mcp.py`
- Test: `tests/test_oast_adapter_unit.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oast_adapter_unit.py
import asyncio
from types import SimpleNamespace

from ai_osop.adapters.oast_mcp import OASTAdapter


class _Resp:
    def __init__(self, status, result):
        self.status = status
        self.result = result
        self.error = ""


class _Registry:
    def __init__(self):
        self.calls = []
    async def execute_tool(self, server_id, tool, params, timeout_override=None):
        self.calls.append((tool, params))
        if tool == "oast_register":
            return _Resp("success", {"token": "abc123", "callback_url": "http://127.0.0.1:8099/abc123"})
        return _Resp("success", {"token": params["token"], "hit_count": 1,
                                 "interactions": [{"method": "GET"}]})


def test_register_returns_token_and_url():
    reg = _Registry()
    a = OASTAdapter(reg)
    token, url = asyncio.run(a.register("ssrf:test"))
    assert token == "abc123" and url.endswith("/abc123")


def test_poll_returns_interactions():
    reg = _Registry()
    a = OASTAdapter(reg)
    hits = asyncio.run(a.poll("abc123"))
    assert hits and hits[0]["method"] == "GET"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_oast_adapter_unit.py -q -p no:cacheprovider --no-cov`
Expected: FAIL (module `ai_osop.adapters.oast_mcp` does not exist).

- [ ] **Step 3: Write minimal implementation**

```python
# src/ai_osop/adapters/oast_mcp.py
"""OAST Interaction MCP Adapter.

Wraps the oast-mcp server so agents can mint correlation tokens and poll for
captured out-of-band callbacks through the standard MCPRegistry.
"""
from typing import Any, Dict, List, Tuple

from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.protocol import MCPRegistry


class OASTAdapter:
    SERVER_ID = "oast-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def register(self, label: str = "") -> Tuple[str, str]:
        """Mint a token; returns (token, callback_url)."""
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_register", {"label": label})
        if resp.status != "success":
            raise MCPException(f"OAST register failed: {resp.error}")
        r = resp.result or {}
        return r.get("token", ""), r.get("callback_url", "")

    async def poll(self, token: str) -> List[Dict[str, Any]]:
        """Return captured interactions for a token (empty if none yet)."""
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_poll", {"token": token})
        if resp.status != "success":
            raise MCPException(f"OAST poll failed: {resp.error}")
        return (resp.result or {}).get("interactions", []) or []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/test_oast_adapter_unit.py -q -p no:cacheprovider --no-cov`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/adapters/oast_mcp.py tests/test_oast_adapter_unit.py
git commit -m "feat(oast): OASTAdapter (register/poll over MCPRegistry)"
```

---

## Task 5: `ssrf_scan` task in vuln_agent

**Files:**
- Modify: `src/ai_osop/agents/vuln_agent.py` (import, `_setup_resources`, `_execute` dispatch, new handler)
- Test: `tests/test_ssrf_scan_unit.py`

- [ ] **Step 1: Write the failing test (offline, fake adapter + fake graph)**

```python
# tests/test_ssrf_scan_unit.py
import asyncio
from types import SimpleNamespace

from ai_osop.agents.vuln_agent import VulnAnalysisAgent


def _capture(store, v):
    store.append(v)
    async def _ok():
        return None
    return _ok()


class _FakeOAST:
    def __init__(self, hit):
        self._hit = hit
    async def initialize(self, *a, **k):
        return None
    async def register(self, label=""):
        return "tok123", "http://127.0.0.1:8099/tok123"
    async def poll(self, token):
        return [{"method": "GET", "path": "/tok123", "source_ip": "127.0.0.1"}] if self._hit else []


def _agent(oast, captured):
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.findings = {}
    a.oast = oast
    a.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-ssrf"),
        session_memory=SimpleNamespace(get_session_state=lambda _e: _none()),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )
    return a


async def _none():
    return None


def test_ssrf_confirmed_on_callback():
    captured = []
    agent = _agent(_FakeOAST(hit=True), captured)
    res = asyncio.run(agent._execute_ssrf_scan({
        "url": "http://t/profile/image/url", "body_field": "imageUrl",
        "engagement_id": "eng-ssrf", "poll_seconds": 0.1, "poll_interval": 0.05,
        "token": "x"}))
    assert res["confirmed"] is True and res["findings_count"] == 1
    v = captured[0]
    assert v.vuln_type.value == "ssrf" and v.validated is True
    assert v.cwe == "CWE-918" and v.is_simulated() is False


def test_ssrf_not_confirmed_without_callback():
    captured = []
    agent = _agent(_FakeOAST(hit=False), captured)
    res = asyncio.run(agent._execute_ssrf_scan({
        "url": "http://t/x?u=OASTINJECT", "param": "u",
        "engagement_id": "eng-ssrf", "poll_seconds": 0.1, "poll_interval": 0.05}))
    assert res["confirmed"] is False and res["findings_count"] == 0
    assert captured == []
```

Note: `test_ssrf_confirmed_on_callback` sends a real httpx request to `http://t/...` which will fail to connect — that is fine and expected; the handler must catch the send error and still proceed to poll (the callback is what confirms, not the response). Ensure the handler polls even when the triggering request raises.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ssrf_scan_unit.py -q -p no:cacheprovider --no-cov`
Expected: FAIL (`_execute_ssrf_scan` not defined).

- [ ] **Step 3a: Add import + adapter wiring**

In `src/ai_osop/agents/vuln_agent.py`, add the import next to the other adapter imports:

```python
from ai_osop.adapters.oast_mcp import OASTAdapter
```

In `_setup_resources`, after `self.browser_adapter = BrowserMCPAdapter(self.ctx.mcp_registry)`, add:

```python
        # oast-mcp lets ssrf_scan CONFIRM blind SSRF via a real out-of-band callback,
        # not a guess. No callback => no finding.
        self.oast = OASTAdapter(self.ctx.mcp_registry)
```

- [ ] **Step 3b: Add dispatch branch**

In `_execute`, after the `csrf_scan` branch, add:

```python
        elif task_type == "ssrf_scan":
            return await self._execute_ssrf_scan(payload)
```

- [ ] **Step 3c: Add the handler**

Insert before `_token_from_session`:

```python
    async def _execute_ssrf_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Confirm blind SSRF via a real out-of-band callback. Inject our OAST
        callback URL into a server-side URL-fetch sink (query param OR POST body
        field), trigger it, then poll the OAST server. A captured callback is proof
        the server made the request -> validated SSRF. No callback => no finding.

        Payload:
            url           the request URL sent to the target
            param         query parameter to inject into (GET URL-fetch sinks), OR
            body_field    JSON body field to set to the callback (POST/PUT sinks)
            base_body     other body fields for the request (with body_field)
            method        HTTP method (default GET, or POST when body_field set)
            token/cookie  auth credential
            poll_seconds  total poll window (default 15), poll_interval (default 1.5)
            engagement_id injected by _execute
        """
        url = payload.get("url") or payload.get("target_url") or payload.get("target")
        if not url:
            raise AgentException("ssrf_scan requires 'url'")
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("ssrf_scan: cannot determine engagement_id")

        param = payload.get("param")
        body_field = payload.get("body_field")
        method = payload.get("method", "POST" if body_field else "GET").upper()
        base_body = dict(payload.get("base_body") or {})
        auth_token = payload.get("token")
        cookie = payload.get("cookie")
        poll_seconds = float(payload.get("poll_seconds", 15))
        poll_interval = float(payload.get("poll_interval", 1.5))

        session = await self.ctx.session_memory.get_session_state(engagement_id)
        if session:
            await self.oast.initialize(session.scope, session.session_id)

        token, callback_url = await self.oast.register(label=f"ssrf:{url}")

        headers: Dict[str, str] = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
            headers["Cookie"] = f"token={auth_token}"
        if cookie:
            headers["Cookie"] = cookie

        # Trigger the sink. A connection error here does NOT abort the scan — the
        # OAST callback is the signal, not this response.
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as c:
                if body_field:
                    body = {**base_body, body_field: callback_url}
                    await c.request(method, url, json=body, headers=headers)
                else:
                    inj = self._inject_payload(url, callback_url, param)
                    await c.request(method, inj, headers=headers)
        except Exception as e:
            logger.warning("ssrf_trigger_request_failed", url=url, error=str(e))

        # Poll for the out-of-band callback.
        hits: List[Dict[str, Any]] = []
        waited = 0.0
        while waited < poll_seconds:
            try:
                hits = await self.oast.poll(token)
            except Exception as e:
                logger.warning("ssrf_poll_failed", token=token, error=str(e))
                break
            if hits:
                break
            await asyncio.sleep(poll_interval)
            waited += poll_interval

        if not hits:
            logger.info("ssrf_scan_clean", url=url)
            return {
                "status": "success", "tool": "ssrf_scan", "target": url,
                "confirmed": False, "findings_count": 0,
            }

        hit = hits[0]
        vuln = Vulnerability(
            cwe="CWE-918",
            vuln_type=VulnClass.SSRF,
            severity=Severity.HIGH,
            title=f"Blind SSRF via {body_field or param or 'parameter'}",
            description=(
                f"The server at {url} fetched an attacker-controlled URL; an out-of-band "
                f"callback was captured at the OAST server (source {hit.get('source_ip')}, "
                f"method {hit.get('method')}, path {hit.get('path')}), proving server-side "
                f"request forgery."
            ),
            evidence=[{
                "type": "ssrf_callback",
                "provenance": "oast",
                "url": url,
                "callback_url": callback_url,
                "injection": body_field or param,
                "interaction": hit,
            }],
            tool_source="oast_ssrf",
            confidence=0.97,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            logger.error("ssrf_scan_persist_failed", vuln_id=vuln.id, error=str(e))

        logger.info("ssrf_scan_confirmed", url=url, source_ip=hit.get("source_ip"))
        return {
            "status": "success", "tool": "ssrf_scan", "target": url,
            "confirmed": True, "findings_count": 1, "findings": [vuln.model_dump()],
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ssrf_scan_unit.py -q -p no:cacheprovider --no-cov`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/agents/vuln_agent.py tests/test_ssrf_scan_unit.py
git commit -m "feat(ssrf): ssrf_scan task — confirm blind SSRF via OAST callback"
```

---

## Task 6: Launch integration + live Juice Shop validation

**Files:**
- Modify: `launch_real.ps1`
- Create: `.runlogs/validate_ssrf_oast_e2e.py`

- [ ] **Step 1: Add oast-mcp to the launcher**

In `launch_real.ps1`, in the reality-status comment block add:

```
#   oast-mcp          8099  REAL  (Python: HTTP out-of-band interaction server; token-keyed
#                         callback capture for blind SSRF/XSS/SQLi confirmation)
```

And in the "Starting REAL MCP servers" section add a start line near the other Python servers:

```powershell
# oast-mcp (out-of-band callback capture) on :8099
Start-Process -FilePath $venvPy -ArgumentList "mcp-servers/python/oast_mcp.py --port 8099" -WindowStyle Hidden
```

- [ ] **Step 2: Start oast-mcp and confirm a cross-process callback is captured**

Run:
```bash
cd "C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop"
.venv/Scripts/python.exe mcp-servers/python/oast_mcp.py --port 8099 >.runlogs/oast.out 2>&1 &
sleep 3
curl -s -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:8099/health
# register a token, hit the callback URL out-of-band, poll it
TOK=$(curl -s -X POST http://127.0.0.1:8099/mcp/execute -H "Content-Type: application/json" \
  -d '{"request_id":"x","tool_name":"oast_register","parameters":{"label":"manual"}}' \
  | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['result']['token'])")
curl -s -o /dev/null "http://127.0.0.1:8099/$TOK/probe"
curl -s -X POST http://127.0.0.1:8099/mcp/execute -H "Content-Type: application/json" \
  -d "{\"request_id\":\"y\",\"tool_name\":\"oast_poll\",\"parameters\":{\"token\":\"$TOK\"}}"
```
Expected: `health 200` and the poll response shows `hit_count` ≥ 1 for the probe.

- [ ] **Step 3: Discover Juice Shop's SSRF sink**

The canonical Juice Shop SSRF is the profile-image-from-URL feature. Confirm the exact
endpoint/field empirically (it has historically been a form POST to `/profile/image/url`
with field `imageUrl`, using the logged-in **session cookie**, not the bearer token):

```bash
# Log in via the SPA to get a bearer token, then inspect the profile image URL flow.
# Confirm which request makes the server fetch a URL (watch oast.out while submitting
# a callback URL as the image URL). Record the exact method/path/field/auth.
```
Expected: identify `{method, url, field, auth}` such that submitting a URL causes a
server-side fetch. If the profile-image sink is not reachable in this Juice Shop build,
use any confirmed server-side-fetch endpoint; the OAST mechanism is identical.

- [ ] **Step 4: Write + run the live E2E harness**

```python
# .runlogs/validate_ssrf_oast_e2e.py
"""Live blind-SSRF E2E vs Juice Shop via the OAST server.
Fill TRIGGER from Task 6 Step 3 discovery (method/url/field/auth)."""
import asyncio
import json
import ssl
import urllib.request
from types import SimpleNamespace

from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.adapters.oast_mcp import OASTAdapter
from ai_osop.agents.vuln_agent import VulnAnalysisAgent

B = "http://localhost:3000"
_ctx = ssl.create_default_context(); _ctx.check_hostname = False; _ctx.verify_mode = ssl.CERT_NONE


def _post(path, obj):
    req = urllib.request.Request(B + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    r = urllib.request.urlopen(req, timeout=15, context=_ctx)
    return json.loads(r.read())


def _capture(store, v):
    store.append(v)
    async def _ok():
        return None
    return _ok()


async def main():
    # Auth (attacker's own account).
    email, pw = "osop_ssrf_e2e@test.local", "Passw0rd!23"
    try:
        _post("/api/Users", {"email": email, "password": pw, "passwordRepeat": pw,
                             "securityQuestion": {"id": 1}, "securityAnswer": "x"})
    except Exception:
        pass
    tok = _post("/rest/user/login", {"email": email, "password": pw})["authentication"]["token"]

    reg = MCPRegistry()
    await reg.register_server("oast-mcp", "127.0.0.1", 8099, connect_retries=2)
    oast = OASTAdapter(reg)
    await oast.initialize({"in_scope": ["localhost:3000"]}, "sess-ssrf")

    captured = []
    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.findings = {}
    agent.oast = oast
    agent.ctx = SimpleNamespace(
        current_task=SimpleNamespace(engagement_id="eng-ssrf-e2e"),
        session_memory=SimpleNamespace(get_session_state=lambda _e: _noneco()),
        graph_memory=SimpleNamespace(add_vulnerability=lambda v: _capture(captured, v)),
    )

    # TRIGGER discovered in Step 3 — example shape (adjust field/url/method/auth):
    result = await agent._execute_ssrf_scan({
        "url": f"{B}/profile/image/url",
        "body_field": "imageUrl",
        "method": "POST",
        "token": tok,
        "engagement_id": "eng-ssrf-e2e",
        "poll_seconds": 20, "poll_interval": 1.5,
    })
    print("SSRF result:", {k: result.get(k) for k in ("status", "confirmed", "findings_count")})
    assert result["status"] == "success"
    assert result["confirmed"] is True, "blind SSRF not confirmed — check the trigger sink"
    v = captured[0]
    print("FINDING:", v.vuln_type, v.severity, "validated=", v.validated, "cwe=", v.cwe,
          "simulated=", v.is_simulated())
    assert v.vuln_type.value == "ssrf" and v.validated and not v.is_simulated()
    print("\n*** E2E SSRF PASS: live out-of-band callback -> CONFIRMED validated finding ***")


async def _noneco():
    return None


if __name__ == "__main__":
    asyncio.run(main())
```

Run: `.venv/Scripts/python.exe .runlogs/validate_ssrf_oast_e2e.py`
Expected: `*** E2E SSRF PASS ...`. If the profile-image sink does not fetch, substitute the
endpoint discovered in Step 3; the assertion is that a real callback drove a validated finding.

- [ ] **Step 5: Commit**

```bash
git add launch_real.ps1
git commit -m "feat(oast): launch oast-mcp on :8099; live blind-SSRF validation"
```

---

## Task 7: Regression + reality-status doc update

**Files:**
- Modify: `BUG_BOUNTY_PLATFORM_AUDIT.md` (flip blind-SSRF/OAST gap to shipped)

- [ ] **Step 1: Run the full new + adjacent suite**

Run:
```bash
.venv/Scripts/python.exe -m pytest tests/test_oast_server_unit.py tests/test_oast_adapter_unit.py \
  tests/test_ssrf_scan_unit.py -q -p no:cacheprovider --no-cov -p no:warnings
```
Expected: all PASS.

- [ ] **Step 2: Confirm no import regressions in vuln_agent**

Run: `.venv/Scripts/python.exe -c "from ai_osop.agents.vuln_agent import VulnAnalysisAgent as V; print('ssrf wired ->', hasattr(V,'_execute_ssrf_scan'))"`
Expected: `ssrf wired -> True`

- [ ] **Step 3: Update the audit doc**

In `BUG_BOUNTY_PLATFORM_AUDIT.md`, change the OAST/blind-SSRF rows from ❌ to ✅ (shipped),
and note R1 delivered.

- [ ] **Step 4: Commit**

```bash
git add BUG_BOUNTY_PLATFORM_AUDIT.md
git commit -m "docs: mark R1 (OAST + blind SSRF) shipped"
```

---

## Self-Review notes

- **Spec coverage:** server (T1–T2), settings hybrid knob (T3), adapter (T4), ssrf_scan
  consumer with honest negative (T5), launch + live validation (T6), regression + docs (T7).
  DNS/async-correlation/metadata-chaining remain out of scope per spec.
- **Honesty invariant:** T5 mints a finding ONLY on a captured callback; `test_ssrf_not_confirmed_without_callback` locks the negative path.
- **Type consistency:** `OASTAdapter.register -> (token, callback_url)` and `.poll -> list[dict]`
  used identically in T4 tests and T5 handler. `VulnClass.SSRF`, `Severity.HIGH`, `Vulnerability`
  fields match existing usage in `vuln_agent.py`.
- **Known empirical step:** T6 Step 3 (exact Juice Shop sink) is discovery, not a placeholder —
  the mechanism and assertions are fully specified; only the target endpoint string is confirmed live.
```
