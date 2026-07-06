"""
Browser MCP Server
Stateful browser automation and identity management using Playwright.
Supports multi-session capture, workflow mapping, differential testing,
and evidence persistence (screenshot, HAR, DOM, trace).
"""

import asyncio
import json
import os
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, WebSocket
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from pydantic import BaseModel

app = FastAPI(title="Browser MCP Server")

# Evidence is written here so the workflow_agent and the API can find it.
EVIDENCE_ROOT = os.environ.get("OSOP_EVIDENCE_ROOT", os.path.abspath("evidence_vault"))

# ================= Models =================

class BrowserActionRequest(BaseModel):
    url: str
    action: str  # navigate, click, fill, capture_state, screenshot, dom_snapshot, flush_har
    selector: Optional[str] = None
    value: Optional[str] = None
    user_label: str = "guest"
    engagement_id: str

# ================= State Manager =================

def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in (s or "unknown"))


def _ensure_dir(p: str) -> str:
    os.makedirs(p, exist_ok=True)
    return p


def _evidence_dir(engagement_id: str, workflow_id: str = "") -> str:
    parts = [EVIDENCE_ROOT, _safe_name(engagement_id or "no-engagement")]
    if workflow_id:
        parts.append(_safe_name(workflow_id))
    return _ensure_dir(os.path.join(*parts))


class BrowserManager:
    def __init__(self):
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.contexts: Dict[str, BrowserContext] = {}  # label -> context
        self.pages: Dict[str, Page] = {}                # label -> page
        # Per-label metadata: { har_path, tracing_active, engagement_id }
        self.meta: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._started = False

    async def start(self):
        if self._started:
            return
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self._started = True

    async def get_context(
        self,
        label: str,
        engagement_id: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
    ) -> BrowserContext:
        async with self._lock:
            if label not in self.contexts:
                _ensure_dir(EVIDENCE_ROOT)
                eng_dir = _evidence_dir(engagement_id or "default")
                har_path = os.path.join(eng_dir, f"{_safe_name(label)}.har")
                ctx_kwargs: Dict[str, Any] = {
                    "user_agent": "Mozilla/5.0 AI-OSOP/V2 (Playwright)",
                    "record_har_path": har_path,
                    "record_har_content": "embed",
                }
                # Authenticated-session import (Phase 1 Bug Bounty Upgrade): when the
                # caller supplies a Playwright storage_state ({cookies, origins}) we
                # seed the context so navigation runs as the imported user.
                if storage_state:
                    ctx_kwargs["storage_state"] = storage_state
                self.contexts[label] = await self.browser.new_context(**ctx_kwargs)
                self.meta[label] = {
                    "har_path": har_path,
                    "engagement_id": engagement_id,
                    "tracing_active": False,
                }
                try:
                    await self.contexts[label].tracing.start(
                        screenshots=True, snapshots=True, sources=False
                    )
                    self.meta[label]["tracing_active"] = True
                except Exception as e:
                    self.meta[label]["tracing_error"] = str(e)
            return self.contexts[label]

    async def get_page(
        self,
        label: str,
        engagement_id: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
    ) -> Page:
        if label not in self.pages:
            context = await self.get_context(
                label, engagement_id=engagement_id, storage_state=storage_state
            )
            self.pages[label] = await context.new_page()
        return self.pages[label]

    async def screenshot(
        self, label: str, engagement_id: str, workflow_id: str = "", step_id: str = ""
    ) -> Dict[str, Any]:
        page = await self.get_page(label, engagement_id=engagement_id)
        eng_dir = _evidence_dir(engagement_id or "default", workflow_id)
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
        name = f"shot_{_safe_name(label)}_{_safe_name(step_id) or 'auto'}_{stamp}.png"
        path = os.path.join(eng_dir, name)
        try:
            await page.screenshot(path=path, full_page=True)
            return {"path": path, "url": page.url, "size_bytes": os.path.getsize(path)}
        except Exception as e:
            return {"path": "", "error": str(e), "url": page.url if page else ""}

    async def dom_snapshot(
        self, label: str, engagement_id: str, workflow_id: str = "", step_id: str = ""
    ) -> Dict[str, Any]:
        page = await self.get_page(label, engagement_id=engagement_id)
        eng_dir = _evidence_dir(engagement_id or "default", workflow_id)
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
        name = f"dom_{_safe_name(label)}_{_safe_name(step_id) or 'auto'}_{stamp}.html"
        path = os.path.join(eng_dir, name)
        try:
            content = await page.content()
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            return {"path": path, "url": page.url, "size_bytes": os.path.getsize(path)}
        except Exception as e:
            return {"path": "", "error": str(e), "url": page.url if page else ""}

    async def flush_har(self, label: str, workflow_id: str = "") -> Dict[str, Any]:
        """Close the context so Playwright flushes the HAR to disk, then return path."""
        meta = self.meta.get(label)
        if not meta:
            return {"path": "", "error": f"no context for label {label}"}
        har_path = meta.get("har_path", "")
        trace_path = ""
        try:
            ctx = self.contexts.pop(label, None)
            self.pages.pop(label, None)
            if ctx is not None:
                if meta.get("tracing_active"):
                    eng = meta.get("engagement_id", "default")
                    trace_dir = _evidence_dir(eng, workflow_id)
                    trace_path = os.path.join(
                        trace_dir,
                        f"trace_{_safe_name(label)}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.zip",
                    )
                    try:
                        await ctx.tracing.stop(path=trace_path)
                    except Exception as te:
                        meta["tracing_stop_error"] = str(te)
                        trace_path = ""
                await ctx.close()
            result = {
                "path": har_path,
                "trace_path": trace_path,
                "exists": os.path.exists(har_path) if har_path else False,
            }
            if har_path and os.path.exists(har_path):
                result["size_bytes"] = os.path.getsize(har_path)
            return result
        finally:
            # context was popped on success too; drop meta
            self.meta.pop(label, None)

    async def capture_state(self, label: str, engagement_id: str = "") -> Dict[str, Any]:
        context = await self.get_context(label, engagement_id=engagement_id)
        page = await self.get_page(label, engagement_id=engagement_id)

        cookies = await context.cookies()

        # Diagnostic capture
        try:
            diag = await page.evaluate(
                """
                () => ({
                    url: window.location.href,
                    origin: window.location.origin,
                    readyState: document.readyState,
                    title: document.title,
                    isMainFrame: window === window.top,
                    localStorageType: typeof localStorage,
                    localStorageKeys: localStorage ? Object.keys(localStorage) : null,
                    error: null
                })
                """
            )
        except Exception as e:
            diag = {"error": str(e)}

        state = {"cookies": cookies, "url": page.url, "diagnostics": diag}

        # Resilient capture per storage type — never abort workflow on storage errors.
        for storage_type in ["localStorage", "sessionStorage"]:
            try:
                data = await page.evaluate(
                    f"""
                    () => {{
                        const out = {{}};
                        try {{
                            for (let i = 0; i < {storage_type}.length; i++) {{
                                const k = {storage_type}.key(i);
                                out[k] = {storage_type}.getItem(k);
                            }}
                        }} catch (e) {{
                            return {{ __error: e.toString() }};
                        }}
                        return out;
                    }}
                    """
                )
                state[storage_type] = data
            except Exception as e:
                state[f"{storage_type}_error"] = str(e)

        return state

    async def stop(self):
        for label in list(self.contexts.keys()):
            try:
                await self.flush_har(label)
            except Exception:
                pass
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self._started = False

manager = BrowserManager()

# ================= Endpoints =================

@app.on_event("startup")
async def startup():
    # Durable interpreter provenance for tooling-reality audits: prove which
    # Python + which playwright package this server actually loaded (the API's
    # .venv vs system Python). Logged once at boot so reviewers don't have to
    # infer it from OS process metadata (Windows venv launchers re-exec the base
    # interpreter, making `wmic ExecutablePath` misleading).
    import sys

    try:
        import playwright as _pw

        _pw_file = getattr(_pw, "__file__", "unknown")
    except Exception as _e:  # pragma: no cover
        _pw_file = f"import-failed: {_e}"
    print(
        f"[browser-mcp provenance] python={sys.executable} "
        f"playwright={_pw_file} venv={'.venv' in (_pw_file or '').lower()}",
        flush=True,
    )
    await manager.start()

@app.on_event("shutdown")
async def shutdown():
    await manager.stop()

@app.get("/health")
async def health():
    # Mark not-ready until Playwright has actually started — closes the historical
    # startup race where the port bound before the browser was launchable.
    return {
        "status": "ready" if manager._started else "starting",
        "server": "browser-mcp",
        "playwright_started": manager._started,
    }

# ================= MCP Endpoints =================

class MCPInitializeRequest(BaseModel):
    server_id: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None

class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

@app.post("/mcp/initialize")
async def mcp_initialize(req: MCPInitializeRequest):
    if req.session_id:
        print(f"Initializing session: {req.session_id}")

    return {
        "server_id": "browser-mcp",
        "version": "1.1",
        "capabilities": ["browser", "stateful", "evidence"],
        "tools": [
            {
                "name": "execute",
                "description": "Execute browser action",
                "parameters": [
                    {"name": "url", "type": "string", "description": "Target URL", "required": False},
                    {"name": "action", "type": "string", "description": "Browser action", "required": True},
                    {"name": "user_label", "type": "string", "description": "Identity label", "required": True},
                ],
                "returns": {"status": "string", "result": "object"},
            }
        ],
    }

@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest):
    request_id = req.request_id or "req-" + str(uuid.uuid4())
    params = req.parameters or {}
    if req.tool_name != "execute":
        return {"request_id": request_id, "status": "error", "error": f"Unknown tool: {req.tool_name}"}

    action = params.get("action", "navigate")
    user_label = params.get("user_label", "guest")
    engagement_id = params.get("engagement_id", "")
    workflow_id = params.get("workflow_id", "")
    step_id = params.get("step_id", "")
    # Phase 1 Bug Bounty Upgrade: optional Playwright storage_state ({cookies, origins})
    # forwarded by the agent so the browser context runs as an authenticated user.
    storage_state = params.get("storage_state") or None

    try:
        page = await manager.get_page(
            user_label, engagement_id=engagement_id, storage_state=storage_state
        )

        if action == "navigate":
            url = params.get("url", "")
            await page.goto(url, wait_until="domcontentloaded", timeout=60000)
            # SPA settle: domcontentloaded fires before client-side XHR/fetch
            # (e.g. Angular /rest, /api calls) land. The HAR records the whole
            # context lifetime, so a bounded wait lets that initial API burst
            # be captured before flush_har closes the context. Bounded + swallowed
            # because sites with long-poll/websocket (socket.io) never go idle.
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
        elif action == "click":
            await page.click(params.get("selector"))
        elif action == "fill":
            await page.fill(params.get("selector"), params.get("value"))
        elif action == "capture_session" or action == "capture_state":
            state = await manager.capture_state(user_label, engagement_id=engagement_id)
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"state": state, "current_url": page.url},
                "timestamp": datetime.utcnow().isoformat(),
            }
        elif action == "eval":
            expression = params.get("expression")
            result = await page.evaluate(expression)
            return {
                "request_id": request_id,
                "status": "success",
                "result": {"result": result, "current_url": page.url},
                "timestamp": datetime.utcnow().isoformat(),
            }
        elif action == "screenshot":
            shot = await manager.screenshot(user_label, engagement_id, workflow_id, step_id)
            return {
                "request_id": request_id,
                "status": "success",
                "result": shot,
                "timestamp": datetime.utcnow().isoformat(),
            }
        elif action == "dom_snapshot":
            dom = await manager.dom_snapshot(user_label, engagement_id, workflow_id, step_id)
            return {
                "request_id": request_id,
                "status": "success",
                "result": dom,
                "timestamp": datetime.utcnow().isoformat(),
            }
        elif action == "flush_har":
            har = await manager.flush_har(user_label, workflow_id)
            return {
                "request_id": request_id,
                "status": "success",
                "result": har,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"Unknown action: {action}",
            }

        # Default tail for navigate / click / fill
        state = await manager.capture_state(user_label, engagement_id=engagement_id)
        return {
            "request_id": request_id,
            "status": "success",
            "result": {
                "current_url": page.url,
                "state": state,
                "timestamp": datetime.utcnow().isoformat(),
            },
        }
    except Exception as e:
        print(f"DEBUG: MCP Error: {e}")
        return {
            "request_id": request_id,
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__,
        }

if __name__ == "__main__":
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("OSOP_BROWSER_MCP_PORT", "8091")),
    )
    args = parser.parse_args()
    uvicorn.run(app, host="0.0.0.0", port=args.port)
