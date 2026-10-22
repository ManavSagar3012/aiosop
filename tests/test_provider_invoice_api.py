"""Senior JWT, durable owner binding and safe invoice attestation responses."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.deps import state
from ai_osop.api.routers import provider_invoices
from ai_osop.memory.supervision_store import SupervisionConflict


def _invoice():
    return {
        "expected_task_id": "task-1",
        "expected_model": "openai/gpt-test",
        "expected_operation": "completion",
        "expected_authorization_version": 7,
        "provider": "openai",
        "invoice_reference": "inv-123",
        "invoice_line_id": "line-001",
        "invoice_sha256": "a" * 64,
        "billed_cost_usd": "0.01500000",
        "input_tokens": 120,
        "output_tokens": 8,
    }


def _adjustment():
    payload = _invoice()
    del payload["billed_cost_usd"]
    del payload["input_tokens"]
    del payload["output_tokens"]
    payload.update(adjustment_id="adjust-1", cost_delta_usd="-0.00200000")
    return payload


RECONCILE = "/supervision/engagements/eng-1/model-usage/calls/call-1/invoice/reconcile"
ADJUST = "/supervision/engagements/eng-1/model-usage/calls/call-1/invoice/adjust"
HEADERS = {"Authorization": "Bearer individually-signed-token"}


class _OwnerDB:
    def __init__(self, owner="senior-1"):
        self.owner = owner
        self.last_query = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def execute(self, query):
        self.last_query = query
        return SimpleNamespace(scalar_one_or_none=lambda: self.owner)


@pytest.fixture
def harness(monkeypatch):
    database = _OwnerDB()
    memory = SimpleNamespace(_async_session=lambda: database)
    orch = SimpleNamespace(session_memory=memory)
    monkeypatch.setitem(state, "orchestrator", orch)

    ledger = SimpleNamespace(
        reconcile_provider_invoice=AsyncMock(return_value=True),
        adjust_provider_invoice=AsyncMock(return_value=True),
    )
    factory = MagicMock(return_value=ledger)
    monkeypatch.setattr(provider_invoices, "ModelUsageLedger", factory)
    monkeypatch.setattr(
        provider_invoices,
        "settings",
        SimpleNamespace(jwt_secret="test-jwt-secret"),
    )
    identity = {
        "sub": "senior-1",
        "role": "senior_operator",
        "claims": {"exp": int(datetime.now(timezone.utc).timestamp()) + 3600},
    }
    verify = AsyncMock(return_value=identity)
    monkeypatch.setattr(provider_invoices, "verify_token", verify)
    app = FastAPI()
    app.include_router(provider_invoices.router)
    client = TestClient(app)
    return SimpleNamespace(
        client=client,
        database=database,
        memory=memory,
        ledger=ledger,
        factory=factory,
        verify=verify,
        identity=identity,
    )


def test_reconcile_uses_only_verified_senior_subject_and_owner(harness):
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert reply.status_code == 200
    assert reply.json() == {
        "call_id": "call-1",
        "status": "reconciled",
        "source": "operator_attested",
        "provider_verified": False,
        "execution_outcome": "unknown",
        "safe_to_retry": False,
    }
    assert "invoice_reference" not in reply.text
    assert "invoice_sha256" not in reply.text
    assert "billed_cost_usd" not in reply.text
    assert "WHERE session_states.session_id =" in str(harness.database.last_query)
    assert "eng-1" in harness.database.last_query.compile().params.values()
    harness.factory.assert_called_once_with(harness.memory)
    harness.verify.assert_awaited_once()
    assert harness.verify.await_args.kwargs["token"] is None
    harness.ledger.reconcile_provider_invoice.assert_awaited_once_with(
        "eng-1",
        "call-1",
        **_invoice(),
        actor_id="senior-1",
        actor_role="senior_operator",
    )


def test_adjustment_is_attested_only_with_exact_ledger_contract(harness):
    reply = harness.client.post(ADJUST, headers=HEADERS, json=_adjustment())
    assert reply.status_code == 200
    assert reply.json()["status"] == "recorded"
    assert reply.json()["source"] == "operator_attested"
    assert reply.json()["provider_verified"] is False
    harness.ledger.adjust_provider_invoice.assert_awaited_once_with(
        "eng-1",
        "call-1",
        **_adjustment(),
        actor_id="senior-1",
        actor_role="senior_operator",
    )


@pytest.mark.parametrize(
    "route, method_name",
    [
        (RECONCILE, "reconcile_provider_invoice"),
        (ADJUST, "adjust_provider_invoice"),
    ],
)
def test_duplicate_attestation_result_is_idempotent_not_provider_proof(
    harness,
    route,
    method_name,
):
    getattr(harness.ledger, method_name).return_value = False
    payload = _invoice() if route == RECONCILE else _adjustment()
    reply = harness.client.post(route, headers=HEADERS, json=payload)
    assert reply.status_code == 200
    assert reply.json()["status"] in {"already_reconciled", "already_recorded"}
    assert reply.json()["provider_verified"] is False
    assert reply.json()["execution_outcome"] == "unknown"


@pytest.mark.parametrize("role", ["operator", "viewer", "admin", "senior-operator"])
def test_non_senior_roles_denied_before_store(harness, role):
    harness.verify.return_value = {**harness.identity, "role": role}
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert reply.status_code == 403
    harness.factory.assert_not_called()


@pytest.mark.parametrize("subject", ["", None, "other-user"])
def test_anonymous_or_foreign_senior_is_not_ledger_owner(harness, subject):
    harness.verify.return_value = {**harness.identity, "sub": subject}
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert reply.status_code == 403
    harness.factory.assert_not_called()


def test_senior_global_access_does_not_override_invoice_ownership(harness):
    harness.database.owner = "another-operator"
    reply = harness.client.post(ADJUST, headers=HEADERS, json=_adjustment())
    assert reply.status_code == 403
    harness.factory.assert_not_called()


def test_missing_engagement_and_database_outage_fail_closed(harness, monkeypatch):
    harness.database.owner = None
    missing = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert missing.status_code == 404
    monkeypatch.setitem(state, "orchestrator", None)
    outage = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert outage.status_code == 503
    harness.factory.assert_not_called()


@pytest.mark.parametrize(
    "credentials, query",
    [
        ({}, ""),
        ({}, "?token=signed-token"),
        (HEADERS, "?actor_role=senior_operator"),
    ],
)
def test_bearer_header_is_required_with_no_query_credentials(
    harness,
    credentials,
    query,
):
    reply = harness.client.post(RECONCILE + query, headers=credentials, json=_invoice())
    assert reply.status_code == 403
    harness.verify.assert_not_awaited()
    harness.factory.assert_not_called()


def test_shared_api_token_cannot_be_senior_invoice_identity(harness, monkeypatch):
    monkeypatch.setattr(provider_invoices, "settings", SimpleNamespace(jwt_secret=None))
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert reply.status_code == 503
    harness.verify.assert_not_awaited()
    harness.factory.assert_not_called()


@pytest.mark.parametrize(
    "role,expected",
    [
        ("senior_operator", 200),
        ("operator", 403),
    ],
)
def test_real_signed_jwt_claim_not_request_body_assigns_senior_role(
    harness,
    monkeypatch,
    role,
    expected,
):
    secret = "invoice-jwt-signing-test-key"
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(
            environment="production",
            jwt_secret=secret,
            jwt_algorithm="HS256",
            jwt_audience=None,
            jwt_issuer=None,
            api_token=None,
        ),
    )
    monkeypatch.setattr(
        provider_invoices,
        "settings",
        SimpleNamespace(jwt_secret=secret),
    )
    monkeypatch.setattr(provider_invoices, "verify_token", deps.verify_token)
    token = jwt.encode(
        {
            "sub": "senior-1",
            "role": role,
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        },
        secret,
        algorithm="HS256",
    )
    response = harness.client.post(
        RECONCILE,
        headers={"Authorization": "Bearer " + token},
        json=_invoice(),
    )
    assert response.status_code == expected
    if expected == 200:
        harness.ledger.reconcile_provider_invoice.assert_awaited_once()
    else:
        harness.ledger.reconcile_provider_invoice.assert_not_awaited()


@pytest.mark.parametrize("expiry", [None, True, 0, 1, "9999999999"])
def test_missing_or_expired_verified_jwt_cannot_attest(harness, expiry):
    harness.verify.return_value = {
        **harness.identity,
        "claims": {"exp": expiry},
    }
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert reply.status_code == 401
    harness.factory.assert_not_called()


@pytest.mark.parametrize(
    "malformed",
    [
        {"actor_role": "senior_operator"},
        {"actor_id": "senior-1"},
        {"invoice_pdf": "raw-invoice-confidential"},
        {"provider_verified": True},
        {"expected_authorization_version": True},
        {"invoice_sha256": "a" * 63},
        {"billed_cost_usd": "0.000000001"},
        {"billed_cost_usd": "-0.02"},
        {"input_tokens": -1},
    ],
)
def test_invoice_payload_denies_spoofed_identity_and_raw_documents(harness, malformed):
    payload = {**_invoice(), **malformed}
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=payload)
    assert reply.status_code == 422
    assert reply.json() == {"detail": "Invalid invoice metadata"}
    assert "raw-invoice-confidential" not in reply.text
    harness.factory.assert_not_called()


def test_no_raw_invoice_body_allowed_or_reflected(harness):
    body = "SECRET_INVOICE_BINARY_PAYLOAD_" * 300
    reply = harness.client.post(
        RECONCILE,
        headers={**HEADERS, "Content-Type": "application/pdf"},
        content=body,
    )
    assert reply.status_code == 415
    assert body[:30] not in reply.text
    reply = harness.client.post(
        RECONCILE,
        headers={**HEADERS, "Content-Type": "application/json"},
        content="x" * 4200,
    )
    assert reply.status_code == 413
    harness.factory.assert_not_called()


@pytest.mark.parametrize(
    "failure,expected",
    [
        (SupervisionConflict("secret invoice number"), 409),
        (PermissionError("signed key retired"), 409),
        (ValueError("raw provider payload"), 422),
        (ConnectionError("pg://user:password@db"), 503),
    ],
)
def test_store_errors_are_redacted_and_fail_closed(harness, failure, expected):
    harness.ledger.reconcile_provider_invoice.side_effect = failure
    reply = harness.client.post(RECONCILE, headers=HEADERS, json=_invoice())
    assert reply.status_code == expected
    assert all(
        value not in reply.text
        for value in (
            "secret invoice number",
            "signed key retired",
            "raw provider payload",
            "pg://user:password@db",
        )
    )


def test_unexpected_ledger_reply_cannot_claim_confirmation(harness):
    harness.ledger.adjust_provider_invoice.return_value = {
        "verified": True,
    }
    reply = harness.client.post(ADJUST, headers=HEADERS, json=_adjustment())
    assert reply.status_code == 503
    assert "verified" not in reply.text
