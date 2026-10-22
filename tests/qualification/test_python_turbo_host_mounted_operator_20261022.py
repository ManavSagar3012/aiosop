"""Mounted senior API + REAL owned disabled Turbo Python process, no attack."""

import hashlib
import sys
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.api.routers import python_inert_turbo as router
from ai_osop.core.config import settings
from ai_osop.mcp.python_inert_host_supervisor import PythonInertHostSupervisor, _SOURCE

SECRET = "private-fixture-only-inert-turbo-jwt"
ROOT = "/system/python-inert-turbo"


def bearer(role: str = "senior_operator", expired: bool = False) -> dict[str, str]:
    now = int(time.time())
    return {
        "Authorization": "Bearer "
        + jwt.encode(
            {
                "sub": "senior-owned-fixture",
                "role": role,
                "iat": now - 2,
                "exp": now - 2 if expired else now + 120,
            },
            SECRET,
            algorithm="HS256",
        )
    }


@pytest.fixture
def isolated(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    app = FastAPI()
    app.include_router(router.router)
    return app


@pytest.mark.asyncio
async def test_actual_main_registers_exact_routes_default_senior_deny(isolated):
    assert sum(item.path == ROOT + "/status" for item in main.app.routes) == 1
    assert sum(item.path == ROOT + "/start" for item in main.app.routes) == 1
    assert sum(item.path == ROOT + "/stop" for item in main.app.routes) == 1
    transport = ASGITransport(app=isolated, client=("127.0.0.1", 43876))
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        for headers, statuses in (
            ({}, {401, 403}),
            (bearer("operator"), {403}),
            (bearer(expired=True), {401, 403}),
        ):
            result = await client.get(ROOT + "/status", headers=headers)
            assert result.status_code in statuses
        missing = await client.get(ROOT + "/status", headers=bearer())
        assert missing.status_code == 200
        assert missing.json()["lifecycle"] == "host_unconfigured"
        assert missing.json()["native_execution_enabled"] is False
        denied = await client.post(ROOT + "/start", headers=bearer())
        assert denied.status_code == 503
        bad_body = await client.post(ROOT + "/start", headers=bearer(), json={"port": 8098})
        assert bad_body.status_code in {415, 422}
        bad_origin = await client.get(
            ROOT + "/status", headers={**bearer(), "Origin": "https://other.invalid"}
        )
        assert bad_origin.status_code == 403


@pytest.mark.asyncio
async def test_mounted_real_disabled_process_start_read_stop_requires_host_pins(isolated):
    sha = hashlib.sha256(_SOURCE.read_bytes()).hexdigest()
    controller = PythonInertHostSupervisor(
        reviewed_source_sha256=sha,
        reviewed_interpreter_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        reviewed_runtime_sha256=hashlib.sha256(
            Path(getattr(sys, "_base_executable", sys.executable)).read_bytes()
        ).hexdigest(),
        explicitly_opted_in=True,
    )
    router.install_host_python_inert_turbo(isolated, controller)
    transport = ASGITransport(app=isolated, client=("127.0.0.1", 43877))
    try:
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            pending = await client.get(ROOT + "/status", headers=bearer())
            assert pending.status_code == 200
            assert pending.json()["lifecycle"] == "stopped"
            started = await client.post(ROOT + "/start", headers=bearer())
            assert started.status_code == 200, started.text
            assert started.json()["lifecycle"] == "running_disabled_unavailable"
            assert started.json()["mcp_initialized"] is False
            assert started.json()["signed_action_verified"] is False
            assert started.json()["production_certified"] is False
            assert started.json()["independent_target_effect_verified"] is False
            assert started.json()["native_execution_enabled"] is False
            again = await client.post(ROOT + "/start", headers=bearer())
            assert again.status_code == 503
            observed = await client.get(ROOT + "/status", headers=bearer())
            assert observed.status_code == 200
            assert observed.json()["listener_owned"] is True
            stopped = await client.post(ROOT + "/stop", headers=bearer())
            assert stopped.status_code == 200
            assert stopped.json()["lifecycle"] == "stopped"
            assert "secret" not in stopped.text and ".py" not in started.text
    finally:
        await router.shutdown_host_python_inert_turbo(isolated)
        assert controller._child is None
