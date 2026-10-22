"""Read-only provider routing catalog must not imply live verification."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers.provider_invoices import read_provider_capabilities


@pytest.mark.asyncio
async def test_owned_senior_receives_uncertified_configured_routes():
    operator = {"role": "senior_operator", "sub": "owner"}
    routes = [{"model": "local-model", "provider_catalog_verified": False}]

    class Config:
        def capability_report(self):
            return routes

    with (
        patch(
            "ai_osop.api.routers.provider_invoices._owned_ledger", new_callable=AsyncMock
        ) as owned,
        patch("ai_osop.core.provider_routing.configured_routes", return_value=Config()),
    ):
        response = Response()
        result = await read_provider_capabilities("engagement", response, operator)
    owned.assert_awaited_once_with("engagement", operator)
    assert result["routes"] == routes
    assert result["provider_currently_available_verified"] is False
    assert result["provider_native_cost_ceiling_verified"] is False
    assert result["signed_budget_admission_still_required"] is True
    assert response.headers["Cache-Control"] == "private, no-store"


@pytest.mark.asyncio
async def test_missing_authoritative_owner_never_reads_provider_config():
    with patch(
        "ai_osop.api.routers.provider_invoices._owned_ledger",
        new_callable=AsyncMock,
        side_effect=HTTPException(403),
    ):
        with patch("ai_osop.core.provider_routing.configured_routes") as configured:
            with pytest.raises(HTTPException) as error:
                await read_provider_capabilities("other-tenant", Response(), {"sub": "not-owner"})
    assert error.value.status_code == 403
    configured.assert_not_called()


@pytest.mark.asyncio
async def test_bad_local_catalog_denied_without_availability_claim():
    with (
        patch("ai_osop.api.routers.provider_invoices._owned_ledger", new_callable=AsyncMock),
        patch(
            "ai_osop.core.provider_routing.configured_routes",
            side_effect=ValueError("private config"),
        ),
    ):
        with pytest.raises(HTTPException) as error:
            await read_provider_capabilities("engagement", Response(), {"sub": "owner"})
    assert error.value.status_code == 503
    assert "private config" not in str(error.value.detail)
