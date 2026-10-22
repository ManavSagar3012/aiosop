"""
AI-OSOP Safety and Environment Self-Test Suite.
Evaluates local cryptographic keys, database reachability, Docker runtime,
and scope enforcement before platform startup.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import shutil
import sys
import time
from typing import Any, Dict, List

import structlog

from ai_osop.core.config import settings
from ai_osop.core.models import ScopeDefinition
from ai_osop.safety.scope import ScopeEnforcer

logger = structlog.get_logger("ai_osop.safety.self_test")


class SafetySelfTest:
    """Preflight diagnostic suite verifying platform safety and dependencies."""

    def __init__(self, timeout_seconds: float = 3.0):
        self.timeout = timeout_seconds

    def check_cryptographic_primitives(self) -> Dict[str, Any]:
        """Verify HMAC-SHA256, hash generation, and secret key configurations."""
        start = time.monotonic()
        try:
            # 1. Basic HMAC-SHA256 operation
            test_key = os.urandom(32)
            test_msg = b"AI-OSOP-CRYPTOGRAPHIC-SELF-TEST"
            signature = hmac.new(test_key, test_msg, hashlib.sha256).digest()
            if len(signature) != 32:
                return {
                    "status": "FAIL",
                    "error": "HMAC-SHA256 output length invalid",
                    "latency_ms": round((time.monotonic() - start) * 1000, 2),
                }

            # 2. Check settings secret keys
            jwt_secret = getattr(settings, "JWT_SECRET", None)
            master_key = getattr(settings, "MASTER_KEY", None)

            warnings: List[str] = []
            if not jwt_secret or jwt_secret in ("changeme", "default", "secret"):
                warnings.append("JWT_SECRET is using an insecure or default value")
            if not master_key or len(str(master_key)) < 16:
                warnings.append("MASTER_KEY is short or missing; ensure strong 32+ character key")

            return {
                "status": "WARN" if warnings else "PASS",
                "warnings": warnings,
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }
        except Exception as exc:
            return {
                "status": "FAIL",
                "error": str(exc),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }

    def check_scope_enforcement_logic(self) -> Dict[str, Any]:
        """Verify ScopeEnforcer correctly allows in-scope and blocks out-of-scope targets."""
        start = time.monotonic()
        try:
            scope_def = ScopeDefinition(
                engagement_id="eng-selftest",
                domains=["target.local", "lab.example.com"],
                ips=["10.10.10.0/24"],
                exclusions=["restricted.lab.example.com", "10.10.10.5"],
            )
            enforcer = ScopeEnforcer(scope_def)

            # In-scope checks
            if not enforcer.validate_target("https://target.local/api/v1"):
                return {"status": "FAIL", "error": "Failed to validate exact in-scope domain"}
            if not enforcer.validate_target("https://api.lab.example.com/data"):
                return {"status": "FAIL", "error": "Failed to validate wildcard in-scope domain"}
            if not enforcer.validate_target("http://10.10.10.20:8080"):
                return {"status": "FAIL", "error": "Failed to validate in-scope CIDR IP"}

            # Out-of-scope exclusion checks
            try:
                enforcer.validate_target("https://restricted.lab.example.com/secret")
                return {"status": "FAIL", "error": "Failed to block explicitly excluded domain"}
            except Exception:
                pass  # expected rejection

            try:
                enforcer.validate_target("http://10.10.10.5/admin")
                return {"status": "FAIL", "error": "Failed to block explicitly excluded IP"}
            except Exception:
                pass  # expected rejection

            return {
                "status": "PASS",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }
        except Exception as exc:
            return {
                "status": "FAIL",
                "error": str(exc),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }

    def check_container_runtime(self) -> Dict[str, Any]:
        """Verify presence of Docker CLI or container runtime."""
        start = time.monotonic()
        docker_path = shutil.which("docker")
        compose_path = shutil.which("docker-compose")
        if not docker_path:
            return {
                "status": "WARN",
                "warning": (
                    "Docker binary not found in PATH; "
                    "container execution will require remote runner"
                ),
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }

        return {
            "status": "PASS",
            "docker_binary": docker_path,
            "docker_compose": compose_path or "plugin",
            "latency_ms": round((time.monotonic() - start) * 1000, 2),
        }

    async def check_redis_connectivity(self) -> Dict[str, Any]:
        """Verify Redis reachability if REDIS_URL is configured."""
        start = time.monotonic()
        redis_url = getattr(settings, "REDIS_URL", None)
        if not redis_url:
            return {"status": "WARN", "warning": "REDIS_URL not configured"}

        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(redis_url, socket_timeout=self.timeout)
            async with asyncio.timeout(self.timeout):
                await client.ping()
                await client.aclose()
            return {
                "status": "PASS",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }
        except Exception as exc:
            return {
                "status": "WARN",
                "warning": f"Redis connection unavailable: {exc}",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }

    async def check_postgres_connectivity(self) -> Dict[str, Any]:
        """Verify PostgreSQL reachability if DATABASE_URL/POSTGRES_URL is configured."""
        start = time.monotonic()
        db_url = getattr(settings, "DATABASE_URL", None) or getattr(settings, "POSTGRES_URL", None)
        if not db_url:
            return {"status": "WARN", "warning": "DATABASE_URL not configured"}

        try:
            from sqlalchemy import text
            from sqlalchemy.ext.asyncio import create_async_engine

            async_engine = create_async_engine(
                db_url,
                connect_args={"timeout": self.timeout} if "sqlite" not in db_url else {},
            )
            async with asyncio.timeout(self.timeout):
                async with async_engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
            await async_engine.dispose()
            return {
                "status": "PASS",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }
        except Exception as exc:
            return {
                "status": "WARN",
                "warning": f"Database connection unavailable: {exc}",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }

    async def run_all(self) -> Dict[str, Any]:
        """Run all safety and environment checks and return aggregate diagnostic."""
        crypto_res = self.check_cryptographic_primitives()
        scope_res = self.check_scope_enforcement_logic()
        runtime_res = self.check_container_runtime()
        redis_res = await self.check_redis_connectivity()
        pg_res = await self.check_postgres_connectivity()

        results = {
            "cryptography": crypto_res,
            "scope_enforcer": scope_res,
            "container_runtime": runtime_res,
            "redis": redis_res,
            "postgres": pg_res,
        }

        overall = "PASS"
        if any(r.get("status") == "FAIL" for r in results.values()):
            overall = "FAIL"
        elif any(r.get("status") == "WARN" for r in results.values()):
            overall = "WARN"

        return {
            "overall_status": overall,
            "timestamp": time.time(),
            "checks": results,
        }


async def run_safety_self_test() -> Dict[str, Any]:
    """Helper entry point for external callers."""
    tester = SafetySelfTest()
    return await tester.run_all()


if __name__ == "__main__":
    tester = SafetySelfTest()
    report = asyncio.run(tester.run_all())
    print(f"[self_test] Overall Status: {report['overall_status']}")
    for name, res in report["checks"].items():
        st = res.get("status")
        msg = res.get("error") or res.get("warning") or f"{res.get('latency_ms', 0)}ms"
        print(f"  - {name}: {st} ({msg})")

    if report["overall_status"] == "FAIL":
        sys.exit(1)
    sys.exit(0)
