"""In-process test suite for the multi-tenant lab target."""

import sys
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

# Add lab-target directory to sys.path
lab_dir = Path(__file__).parent.parent / "docker" / "lab-target"
sys.path.insert(0, str(lab_dir))

from app import app


@pytest.mark.asyncio
async def test_lab_target_public_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health
        res = await client.get("/api/v1/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

        # 2. System info
        res = await client.get("/api/v1/system/info")
        assert res.status_code == 200
        assert res.json()["environment"] == "isolated-lab"


@pytest.mark.asyncio
async def test_lab_target_bola_idor_flaw():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Anonymous access fails with 401
        res = await client.get("/api/v1/documents/doc-101")
        assert res.status_code == 401

        # Alice (owner) accesses her own doc
        alice_headers = {"Authorization": "Bearer token-alice-secret-key-101"}
        res = await client.get("/api/v1/documents/doc-101", headers=alice_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["document"]["id"] == "doc-101"
        assert data["document"]["tenant_id"] == "tenant-alpha"

        # Bob (attacker, tenant-beta) accesses Alice's doc (tenant-alpha)
        # Should succeed due to BOLA vulnerability
        bob_headers = {"Authorization": "Bearer token-bob-secret-key-202"}
        res = await client.get("/api/v1/documents/doc-101", headers=bob_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["caller_user"] == "bob"
        assert data["caller_tenant"] == "tenant-beta"
        assert data["document"]["id"] == "doc-101"
        assert data["document"]["tenant_id"] == "tenant-alpha"


@pytest.mark.asyncio
async def test_lab_target_sqli_flaw():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        alice_headers = {"Authorization": "Bearer token-alice-secret-key-101"}

        # Normal query
        res = await client.post(
            "/api/v1/analytics/query",
            headers=alice_headers,
            json={"filter_expr": "amount > 1000"},
        )
        assert res.status_code == 200
        assert res.json().get("sqli_detected") is None

        # SQL Injection payload
        res = await client.post(
            "/api/v1/analytics/query",
            headers=alice_headers,
            json={"filter_expr": "' OR '1'='1"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["sqli_detected"] is True
        assert len(data["leaked_rows"]) >= 2


@pytest.mark.asyncio
async def test_lab_target_admin_authorization():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bob_headers = {"Authorization": "Bearer token-bob-secret-key-202"}
        admin_headers = {"Authorization": "Bearer token-admin-secret-key-999"}

        # Regular user denied 403
        res = await client.post(
            "/api/v1/admin/users",
            headers=bob_headers,
            json={"username": "eve", "tenant_id": "tenant-gamma"},
        )
        assert res.status_code == 403

        # Admin user succeeds
        res = await client.post(
            "/api/v1/admin/users",
            headers=admin_headers,
            json={"username": "charlie", "tenant_id": "tenant-gamma"},
        )
        assert res.status_code == 200
        assert res.json()["created_user"] == "charlie"


@pytest.mark.asyncio
async def test_lab_target_soft_denial_response():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bob_headers = {"Authorization": "Bearer token-bob-secret-key-202"}

        # Soft denial returns HTTP 200 with error body
        res = await client.get("/api/v1/restricted/feature", headers=bob_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "error"
        assert data["authorized"] is False
        assert "Access Denied" in data["message"]
