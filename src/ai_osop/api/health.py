"""Health and readiness endpoints for AI-OSOP.

Provides:
- /health — Liveness probe (always returns 200 if process is up).
- /ready — Readiness probe (verifies all critical dependencies are reachable).

The /ready endpoint is what Kubernetes uses to determine if the pod can receive traffic.
It checks Redis, Neo4j, Postgres, and MCP registry connectivity.

Sprint 8 enhancements:
- ai_osop_ready_status metric (1=ready, 0=not_ready, 0.5=degraded)
- Readiness history tracking (last 5 checks for flapping detection)
- Dependency-specific threshold reporting
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict

from fastapi import APIRouter, Depends, HTTPException, status

from ai_osop.api.deps import state
from ai_osop.core.metrics import READY_STATUS
from ai_osop.core.telemetry import RequestContext

router = APIRouter(tags=["health"])


@router.get("/health/mcp")
async def health_mcp():
    """Execution-level reality probe for the MCP tooling layer."""
    return await _check_tool_reality()


@router.get("/health/platform")
async def health_platform():
    """Liveness probe for internal platform services."""
    return {
        "redis": await _check_redis(),
        "postgres": await _check_postgres(),
        "neo4j": await _check_neo4j(),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/health/system")
async def health_system():
    """Unified system health check."""
    return {"platform": await health_platform(), "mcp": await health_mcp()}


@router.get("/health/metrics")
async def health_metrics():
    """Expose high-level platform performance and engagement metrics."""
    from ai_osop.core.metrics import (
        ACTIVE_ENGAGEMENTS,
        AGENT_SUCCESS_RATE,
        READY_STATUS,
        TASK_THROUGHPUT,
    )

    return {
        "active_engagements": ACTIVE_ENGAGEMENTS._value.get(),
        "task_throughput": TASK_THROUGHPUT._value.get(),
        "agent_success_rate": AGENT_SUCCESS_RATE._value.get(),
        "overall_readiness": READY_STATUS._value.get(),
    }


# Sprint 8: readiness history for flapping detection
_readiness_history: Deque[Dict[str, Any]] = deque(maxlen=5)


async def _check_redis() -> Dict[str, Any]:
    """Check Redis connectivity via the orchestrator's session_memory."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.session_memory:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        redis = orch.session_memory._redis
        if not redis:
            return {"status": "unhealthy", "error": "redis client not connected"}
        start = time.monotonic()
        await redis.ping()
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_neo4j() -> Dict[str, Any]:
    """Check Neo4j connectivity via the orchestrator's graph_memory."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.graph_memory:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        driver = orch.graph_memory._driver
        if not driver:
            return {"status": "unhealthy", "error": "neo4j driver not connected"}
        start = time.monotonic()
        await driver.verify_connectivity()
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_postgres() -> Dict[str, Any]:
    """Check PostgreSQL connectivity via the orchestrator's session_memory."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.session_memory:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        engine = orch.session_memory._pg_engine
        if not engine:
            return {"status": "unhealthy", "error": "postgres engine not initialized"}
        start = time.monotonic()
        from sqlalchemy import text

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_mcp_registry() -> Dict[str, Any]:
    """Check MCP registry health (how many servers completed a real initialize handshake).

    AIOSOP-HEALTH-002 (2026-07-03): previously a server was counted "healthy" whenever
    ``conn._session`` was non-None. But the client session is created at registration
    time (register_optional_mcp_servers uses connect_retries=0) and exists whether or not
    the remote is reachable, so /ready reported "healthy 10/10" while every MCP server was
    actually down — a false positive that contradicted /health/mcp and /system/mcp/health.
    Health now reflects a real MCP initialize handshake (``conn._initialized``), consistent
    with the reality probe and the circuit-breaker view.
    """
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.mcp_registry:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        registry = orch.mcp_registry
        servers = list(registry._servers.keys())
        healthy = 0
        errors = []
        for server_id in servers:
            conn = registry._servers.get(server_id)
            if conn is not None and getattr(conn, "_initialized", False):
                healthy += 1
            else:
                circuit = (
                    conn.get_circuit_state()
                    if conn is not None and hasattr(conn, "get_circuit_state")
                    else "unknown"
                )
                errors.append(f"{server_id}: not initialized (circuit={circuit})")
        total = len(servers)
        # Keep the established 3-value contract: healthy (all up or none registered)
        # vs degraded (any not initialized). The healthy/total counts carry the
        # precise severity; "unhealthy" stays reserved for the exception path below.
        status = "healthy" if (total == 0 or healthy == total) else "degraded"
        return {
            "status": status,
            "total_servers": total,
            "healthy_servers": healthy,
            "errors": errors,
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_tool_reality() -> Dict[str, Any]:
    """Execution-level reality probe for the MCP tooling layer (A-5).

    A plain /health check is not enough: a server can answer "ready", register
    realistic tool names, and still return hardcoded data (as recon-mcp's mock
    did — `nmap_scan` always returned 127.0.0.1:80,443). This probe therefore:

      1. Calls /mcp/initialize on every configured MCP server and counts tools.
         Zero tools  -> "stub".  Unreachable -> "down".
      2. For recon-mcp, additionally executes a *real* connect-scan of a known
         local open port (the API's own 8200) and verifies the result reflects
         reality. A mock that ignores inputs / returns canned ports is flagged
         "suspect_mock" even though it looks "ready".

    Best-effort and short-timeout so it never blocks startup. Hits MCP servers
    directly over HTTP, so it does not depend on the orchestrator being bound.
    """
    import asyncio

    import httpx

    from ai_osop.core.config import settings

    servers = {
        "burp-mcp": (settings.burp_mcp_host, settings.burp_mcp_port),
        "recon-mcp": (settings.recon_mcp_host, settings.recon_mcp_port),
        "payload-mcp": (settings.payload_mcp_host, settings.payload_mcp_port),
        "nuclei-mcp": (settings.nuclei_mcp_host, settings.nuclei_mcp_port),
        "shodan-mcp": (settings.shodan_mcp_host, settings.shodan_mcp_port),
        "threat-intel-mcp": (settings.threat_intel_mcp_host, settings.threat_intel_mcp_port),
        "security-bridge": (settings.security_bridge_host, settings.security_bridge_port),
        "source-map-mcp": (settings.source_map_mcp_host, settings.source_map_mcp_port),
        "cloud-mcp": (settings.cloud_mcp_host, settings.cloud_mcp_port),
        "turbo-intruder-mcp": (settings.turbo_intruder_mcp_host, settings.turbo_intruder_mcp_port),
    }

    per_server: Dict[str, Any] = {}

    async def probe(name: str, host: str, port: int) -> None:
        base = f"http://{host}:{port}"
        entry: Dict[str, Any] = {"endpoint": f"{host}:{port}"}
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                # Tool registration (POST first, GET fallback for stub variants).
                tools = []
                try:
                    r = await client.post(f"{base}/mcp/initialize", json={})
                    tools = (r.json() or {}).get("tools", []) if r.status_code == 200 else []
                except Exception:
                    r = await client.get(f"{base}/mcp/initialize")
                    tools = (r.json() or {}).get("tools", []) if r.status_code == 200 else []
                entry["tool_count"] = len(tools)
                entry["verdict"] = "tools_registered" if tools else "stub"

                # Execution-level reality check for recon-mcp.
                if name == "recon-mcp" and tools:
                    try:
                        rr = await client.post(
                            f"{base}/mcp/execute",
                            json={
                                "tool_name": "nmap_scan",
                                "parameters": {"targets": ["127.0.0.1"], "ports": "8200"},
                                "request_id": "reality-probe",
                            },
                        )
                        result = (rr.json() or {}).get("result", {})
                        hosts = result.get("hosts", [])
                        open_ports = [p.get("port") for h in hosts for p in h.get("ports", [])]
                        # The API itself listens on 8200, so a REAL scan must see it
                        # and must NOT report the mock's canned 80/443 for this input.
                        if 8200 in open_ports:
                            entry["verdict"] = "real_execution_verified"
                        elif open_ports in ([80, 443], [443, 80]):
                            entry["verdict"] = "suspect_mock"
                        entry["recon_probe_open_ports"] = open_ports
                    except Exception as e:
                        entry["recon_probe_error"] = str(e)
        except Exception as e:
            entry["verdict"] = "down"
            entry["error"] = str(e)
        per_server[name] = entry

    await asyncio.gather(*(probe(n, h, p) for n, (h, p) in servers.items()))

    real = sum(
        1
        for v in per_server.values()
        if v.get("verdict") in ("real_execution_verified", "tools_registered")
    )
    stubs = [n for n, v in per_server.items() if v.get("verdict") == "stub"]
    suspect = [n for n, v in per_server.items() if v.get("verdict") == "suspect_mock"]
    down = [n for n, v in per_server.items() if v.get("verdict") == "down"]

    overall = "healthy"
    if suspect:
        overall = "degraded"  # a mock masquerading as real is the worst case
    elif real == 0:
        overall = "unhealthy"
    elif stubs or down:
        overall = "degraded"

    return {
        "status": overall,
        "servers_with_tools": real,
        "stub_servers": stubs,
        "suspect_mock_servers": suspect,
        "down_servers": down,
        "detail": per_server,
    }


@router.get("/health/tooling", status_code=status.HTTP_200_OK)
async def tooling_reality() -> Dict[str, Any]:
    """Expose the execution-level MCP tooling-reality probe (A-5).

    Surfaces stub servers (zero tools) and — crucially — suspect mocks (servers
    that register tools but fail an execution reality check). Use this instead of
    trusting per-server /health, which a stub also passes.
    """
    return await _check_tool_reality()


async def _deep_probe() -> Dict[str, Any]:
    """Deep, execution-level capability verification of the 4 core channels.

    Unlike /health/tooling (which counts tools + a recon execute-probe), this opens
    a socket AND runs a real tool on every core channel, measures latency, and
    returns a per-channel `real_execution_verified` / `failed` / `down` verdict.

    Heavier than a liveness probe (a cold nuclei run compiles templates) — intended
    for on-demand operator/CI use, not k8s liveness.
    """
    import asyncio
    import time

    import httpx

    from ai_osop.core.config import settings

    recon = f"http://{settings.recon_mcp_host}:{settings.recon_mcp_port}"
    nuclei = f"http://{settings.nuclei_mcp_host}:{settings.nuclei_mcp_port}"
    browser = f"http://{settings.browser_mcp_host}:{settings.browser_mcp_port}"
    burp = f"http://{settings.burp_mcp_host}:{settings.burp_mcp_port}"

    channels: Dict[str, Any] = {}

    async def execute(client, base, tool, params, timeout):
        r = await client.post(
            f"{base}/mcp/execute",
            json={"tool_name": tool, "parameters": params, "request_id": "deep-probe"},
            timeout=timeout,
        )
        return r.json().get("result", {}) if r.status_code == 200 else {}

    async def probe(name, coro):
        start = time.monotonic()
        try:
            verdict, detail = await coro
        except Exception as e:  # noqa: BLE001
            verdict, detail = "down", {"error": str(e)}
        channels[name] = {
            "verdict": verdict,
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
            **detail,
        }

    async def recon_probe():
        async with httpx.AsyncClient() as c:
            # Scan the API's own port (8200, known-open) — proves real socket scan.
            res = await execute(
                c,
                recon,
                "nmap_scan",
                {"targets": ["127.0.0.1"], "ports": str(settings.mcp_server_port)},
                30.0,
            )
            open_ports = [p.get("port") for h in res.get("hosts", []) for p in h.get("ports", [])]
            ok = settings.mcp_server_port in open_ports
            return ("real_execution_verified" if ok else "failed", {"open_ports": open_ports})

    async def nuclei_probe():
        async with httpx.AsyncClient() as c:
            res = await execute(
                c,
                nuclei,
                "scan",
                {
                    "targets": [f"http://127.0.0.1:{settings.mcp_server_port}"],
                    "templates": ["http/misconfiguration/http-missing-security-headers.yaml"],
                },
                90.0,
            )
            findings = [f for f in res.get("findings", []) if str(f).strip()]
            return (
                "real_execution_verified" if findings else "failed",
                {"findings": len(findings)},
            )

    async def browser_probe():
        async with httpx.AsyncClient() as c:
            res = await execute(
                c,
                browser,
                "execute",
                {
                    "action": "navigate",
                    "url": f"http://127.0.0.1:{settings.mcp_server_port}/health",
                    "engagement_id": "deep-probe",
                },
                45.0,
            )
            ready = res.get("state", {}).get("diagnostics", {}).get("readyState")
            ok = res.get("current_url", "").startswith("http")
            return ("real_execution_verified" if ok else "failed", {"readyState": ready})

    async def burp_probe():
        # AIOSOP-BURP-PROBE-001 (2026-07-03): Burp's job in this pipeline is *scanning*,
        # so the deep verdict must reflect active-scan capability — not just HTTP. The
        # old probe only exercised send_http_request (proxy/repeater, present in every
        # Burp edition), so it reported real_execution_verified even when the active
        # scanner was unavailable (Community/unlicensed), masking a real capability gap.
        async with httpx.AsyncClient() as c:
            http_res = await execute(
                c,
                burp,
                "send_http_request",
                {"url": f"http://127.0.0.1:{settings.mcp_server_port}/health", "method": "GET"},
                20.0,
            )
            if http_res.get("status") != "success":
                return ("failed", {"stage": "http", "detail": http_res})
            # Active-scan capability check. scan_target on Community/unlicensed Burp
            # errors at Scanner.startAudit() (returns null) BEFORE any audit begins, so
            # this is a safe, side-effect-free capability probe against the local API.
            scan_res = await execute(
                c,
                burp,
                "scan_target",
                {"url": f"http://127.0.0.1:{settings.mcp_server_port}/health"},
                25.0,
            )
            scan_err = str(scan_res.get("error", "")) if isinstance(scan_res, dict) else ""
            if scan_res and not scan_err:
                return ("real_execution_verified", {"scan_capable": True, "http_verified": True})
            # HTTP works but the active scanner does not — honest, distinct verdict so
            # channels_verified no longer over-counts Burp as scan-ready.
            return (
                "scan_unavailable",
                {
                    "scan_capable": False,
                    "http_verified": True,
                    "reason": scan_err[:200]
                    or "active scanner unavailable (requires Burp Suite Professional)",
                },
            )

    await asyncio.gather(
        probe("recon", recon_probe()),
        probe("nuclei", nuclei_probe()),
        probe("browser", browser_probe()),
        probe("burp", burp_probe()),
    )

    verified = sum(1 for v in channels.values() if v["verdict"] == "real_execution_verified")
    overall = (
        "real_execution_verified"
        if verified == len(channels)
        else ("degraded" if verified > 0 else "unhealthy")
    )
    return {
        "status": overall,
        "channels_verified": f"{verified}/{len(channels)}",
        "recon": channels["recon"]["verdict"],
        "nuclei": channels["nuclei"]["verdict"],
        "browser": channels["browser"]["verdict"],
        "burp": channels["burp"]["verdict"],
        "detail": channels,
    }


@router.get("/health/tooling/deep", status_code=status.HTTP_200_OK)
async def tooling_reality_deep() -> Dict[str, Any]:
    """Deep execution-level capability verification of recon/nuclei/browser/burp.

    Opens a socket and runs a real tool on each channel, returning per-channel
    `real_execution_verified` plus latency. Heavier than /health/tooling; use
    on-demand (operator/CI), not as a liveness probe.
    """
    return await _deep_probe()


@router.get("/health", status_code=status.HTTP_200_OK)
async def health() -> Dict[str, Any]:
    """Liveness probe.

    Returns 200 if the process is alive. This is intentionally minimal — it
    does not verify dependencies. Kubernetes uses this to decide whether to
    restart the container.
    """
    # Diagnostic: check for duplicate module imports
    import sys as _sys

    import ai_osop.api.main as _m

    _mods = [k for k in _sys.modules if "ai_osop.api.main" in k]
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "diag": {
            "loaded_from": getattr(_m, "__file__", "unknown"),
            "modules_keys": _mods,
        },
    }


@router.get("/ready", status_code=status.HTTP_200_OK)
async def ready() -> Dict[str, Any]:
    """Readiness probe.

    Verifies all critical dependencies are reachable before returning 200.
    If any dependency is unhealthy, returns 503 with detailed breakdown.
    Kubernetes uses this to decide whether to send traffic to the pod.

    Sprint 8:
    - Emits ai_osop_ready_status metric (1/0/0.5)
    - Tracks last 5 checks for flapping detection
    - Reports degraded (not not_ready) when only non-critical deps are unhealthy
    """
    checks = {
        "redis": await _check_redis(),
        "neo4j": await _check_neo4j(),
        "postgres": await _check_postgres(),
        "mcp_registry": await _check_mcp_registry(),
    }

    # Critical dependencies: Redis, Neo4j, Postgres
    critical_unhealthy = any(
        c["status"] == "unhealthy"
        for name, c in checks.items()
        if name in ("redis", "neo4j", "postgres")
    )

    # Non-critical: MCP registry
    non_critical_degraded = any(
        c["status"] in ("degraded", "unhealthy")
        for name, c in checks.items()
        if name not in ("redis", "neo4j", "postgres")
    )

    if critical_unhealthy:
        READY_STATUS.set(0.0)
        _readiness_history.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "status": "not_ready",
                "checks": {name: c["status"] for name, c in checks.items()},
            }
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "timestamp": datetime.utcnow().isoformat(),
                "checks": checks,
                "history": list(_readiness_history),
            },
        )

    # Determine overall status
    if non_critical_degraded:
        overall_status = "degraded"
        READY_STATUS.set(0.5)
    else:
        overall_status = "ready"
        READY_STATUS.set(1.0)

    _readiness_history.append(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "status": overall_status,
            "checks": {name: c["status"] for name, c in checks.items()},
        }
    )

    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
        "history": list(_readiness_history),
    }


async def run_startup_self_test() -> Dict[str, Any]:
    """Run comprehensive startup self-test (Sprint 6.5).

    Checks all infrastructure layers with PASS/FAIL/LATENCY/ERROR details.
    Critical failures (Redis, Postgres, Neo4j) must block startup.
    """
    import time

    results: Dict[str, Any] = {}
    checks_passed = 0
    checks_failed = 0

    async def _check(name: str, checker, critical: bool = False) -> None:
        nonlocal checks_passed, checks_failed
        start = time.monotonic()
        try:
            result = await checker()
            result["latency_ms"] = round((time.monotonic() - start) * 1000, 2)
            result["critical"] = critical
        except Exception as e:
            result = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": critical,
            }
        if result.get("status") in ("healthy", "ready", "PASS"):
            checks_passed += 1
        else:
            checks_failed += 1
        results[name] = result

    # Critical dependencies
    await _check("redis", _check_redis, critical=True)
    await _check("postgres", _check_postgres, critical=True)
    await _check("neo4j", _check_neo4j, critical=True)
    await _check("mcp_registry", _check_mcp_registry, critical=False)

    # Extended checks via orchestrator
    orch = state.get("orchestrator")
    if orch:
        # Task Queue
        start = time.monotonic()
        try:
            task_queue_len = len(orch._tasks) if hasattr(orch, "_tasks") else 0
            results["task_queue"] = {
                "status": "PASS",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "task_count": task_queue_len,
                "critical": False,
            }
            checks_passed += 1
        except Exception as e:
            results["task_queue"] = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": False,
            }
            checks_failed += 1

        # Session Store
        start = time.monotonic()
        try:
            session_store = state.get("session_store")
            results["session_store"] = {
                "status": "PASS" if session_store is not None else "degraded",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "initialized": session_store is not None,
                "critical": False,
            }
            if session_store is not None:
                checks_passed += 1
            else:
                checks_failed += 1
        except Exception as e:
            results["session_store"] = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": False,
            }
            checks_failed += 1

        # Approval Store
        start = time.monotonic()
        try:
            has_approval_store = (
                hasattr(orch, "approval_coordinator") and orch.approval_coordinator is not None
            )
            results["approval_store"] = {
                "status": "PASS" if has_approval_store else "degraded",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "initialized": has_approval_store,
                "critical": False,
            }
            if has_approval_store:
                checks_passed += 1
            else:
                checks_failed += 1
        except Exception as e:
            results["approval_store"] = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": False,
            }
            checks_failed += 1

        # Graph Layer
        start = time.monotonic()
        try:
            graph_ok = orch.graph_memory is not None and orch.graph_memory._driver is not None
            results["graph_layer"] = {
                "status": "PASS" if graph_ok else "FAIL",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "initialized": graph_ok,
                "critical": False,
            }
            if graph_ok:
                checks_passed += 1
            else:
                checks_failed += 1
        except Exception as e:
            results["graph_layer"] = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": False,
            }
            checks_failed += 1

        # Tracing Layer
        start = time.monotonic()
        try:
            from opentelemetry import trace

            tracer = trace.get_tracer_provider()
            tracing_ok = tracer is not None
            results["tracing_layer"] = {
                "status": "PASS" if tracing_ok else "degraded",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "initialized": tracing_ok,
                "critical": False,
            }
            if tracing_ok:
                checks_passed += 1
            else:
                checks_failed += 1
        except Exception as e:
            results["tracing_layer"] = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": False,
            }
            checks_failed += 1

        # Metrics Layer
        start = time.monotonic()
        try:
            from prometheus_client import REGISTRY

            # Use internal registry mapping to check if any collectors are registered
            metrics_ok = (
                len(REGISTRY._names_to_collectors) > 0 or len(REGISTRY._collector_to_names) > 0
            )
            results["metrics_layer"] = {
                "status": "PASS" if metrics_ok else "degraded",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "initialized": metrics_ok,
                "collector_count": len(REGISTRY._names_to_collectors),
                "critical": False,
            }
            if metrics_ok:
                checks_passed += 1
            else:
                checks_failed += 1
        except Exception as e:
            results["metrics_layer"] = {
                "status": "FAIL",
                "error": str(e),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
                "critical": False,
            }
            checks_failed += 1
    else:
        for name in [
            "task_queue",
            "session_store",
            "approval_store",
            "graph_layer",
            "tracing_layer",
            "metrics_layer",
        ]:
            results[name] = {
                "status": "FAIL",
                "error": "orchestrator not initialized",
                "critical": False,
            }
            checks_failed += 1

    # A-5: execution-level tooling-reality probe (informational)
    try:
        tool_reality = await _check_tool_reality()
    except Exception as e:
        tool_reality = {"status": "unknown", "error": str(e)}
    results["tool_reality"] = tool_reality

    # Critical failures block startup
    critical_failures = any(
        r.get("status") in ("FAIL", "unhealthy") and r.get("critical") for r in results.values()
    )

    return {
        "status": "healthy" if not critical_failures else "unhealthy",
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "tool_reality_status": tool_reality.get("status"),
        "results": results,
    }


@router.get("/health/startup", status_code=status.HTTP_200_OK)
async def health_startup() -> Dict[str, Any]:
    """Expose startup self-test results (Sprint 6.5).

    Returns PASS/FAIL/LATENCY/ERROR for every dependency layer.
    """
    return await run_startup_self_test()
