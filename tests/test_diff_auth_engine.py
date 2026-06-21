from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.models import DiffAuthFinding, Resource


def _finding(evidence_diff):
    return DiffAuthFinding(
        category="horizontal_pe",
        resource_id="r",
        test_identity_id="user_b",
        expected_result="403 Forbidden",
        observed_result="200 OK",
        evidence_diff=evidence_diff,
        confidence=0.9,
        engagement_id="e",
    )


@pytest.fixture
def mock_session_memory():
    return AsyncMock()


@pytest.fixture
def engine(mock_session_memory):
    return DifferentialAuthEngine(session_memory=mock_session_memory)


@pytest.mark.asyncio
async def test_compare_unauthorized_success(engine) -> None:
    # Setup
    resource = Resource(
        id="res-1",
        type="invoice",
        value="INV-100",
        owner_identity_id="user_a",
        discovery_step_id="step-1",
        engagement_id="eng-1",
    )

    evidence_a = {
        "status_code": 200,
        "body": {"id": "INV-100", "amount": 50},
        "user_label": "user_a",
    }
    evidence_b = {
        "status_code": 200,
        "body": {"id": "INV-100", "amount": 50},
        "user_label": "user_b",
    }

    # Act: user_b should NOT have access
    finding = await engine.compare(evidence_a, evidence_b, resource, expected_allowed=False)

    # Assert
    assert finding is not None
    assert finding.category == "horizontal_pe"
    assert finding.confidence > 0.8
    assert "200" in finding.observed_result


@pytest.mark.asyncio
async def test_compare_data_leakage(engine) -> None:
    # Setup
    resource = Resource(
        id="res-1",
        type="profile",
        value="USER-100",
        owner_identity_id="user_a",
        discovery_step_id="step-1",
        engagement_id="eng-1",
    )

    evidence_a = {"status_code": 200, "body": {"name": "User A"}, "user_label": "user_a"}
    # user_b gets more data than expected (e.g. email, balance, and resource value reflection)
    evidence_b = {
        "status_code": 200,
        "body": {"name": "User A", "email": "a@test.com", "balance": 1000, "ref": "USER-100"},
        "user_label": "user_b",
    }

    # Act
    finding = await engine.compare(evidence_a, evidence_b, resource, expected_allowed=True)

    # Assert
    assert finding is not None
    assert finding.category == "pii_leakage"
    assert "email" in finding.evidence_diff["json_diff"]["added"]


@pytest.mark.asyncio
async def test_compare_semantic_divergence(engine) -> None:
    # Setup
    resource = Resource(
        id="res-1",
        type="dashboard",
        value="DASH-1",
        owner_identity_id="admin",
        discovery_step_id="step-1",
        engagement_id="eng-1",
    )

    evidence_a = {"status_code": 200, "semantics": ["view_only"], "user_label": "user_a"}
    evidence_b = {
        "status_code": 200,
        "semantics": ["view_only", "delete_button"],
        "user_label": "user_b",
    }

    # Act: user_b is a guest, should NOT see delete button
    finding = await engine.compare(evidence_a, evidence_b, resource, expected_allowed=False)

    # Assert
    assert finding is not None
    assert finding.category == "unauthorized_action_visibility"
    assert "delete_button" in finding.evidence_diff["semantic_divergence"]


# ---- AIOSOP-AUDIT-2026-06-16: precision layer ----


@pytest.mark.asyncio
async def test_public_resource_identical_to_anon_is_suppressed(engine) -> None:
    """B's 2xx that is identical to an anonymous client's response, with no
    ownership proof, is a public resource — must NOT be flagged."""
    resource = Resource(
        id="res-1",
        type="endpoint",
        value="/css/app.css",
        owner_identity_id="user_a",
        engagement_id="eng-1",
    )
    evidence_a = {"status_code": 200, "body": {"public": "data"}, "user_label": "user_a"}
    evidence_b = {"status_code": 200, "body": {"public": "data"}, "user_label": "user_b"}
    anon = {"status_code": 200, "body": {"public": "data"}}

    finding = await engine.compare(
        evidence_a, evidence_b, resource, expected_allowed=False, anonymous_evidence=anon
    )
    assert finding is None


@pytest.mark.asyncio
async def test_genuine_idor_with_ownership_proof_high_confidence(engine) -> None:
    """B receives A's owned object (resource value reflected) and anon is denied —
    real cross-account access, high confidence."""
    resource = Resource(
        id="res-1",
        type="invoice",
        value="INV-100",
        owner_identity_id="user_a",
        engagement_id="eng-1",
    )
    evidence_a = {
        "status_code": 200,
        "body": {"id": "INV-100", "amount": 50},
        "user_label": "user_a",
    }
    evidence_b = {
        "status_code": 200,
        "body": {"id": "INV-100", "amount": 50},
        "user_label": "user_b",
    }
    anon = {"status_code": 403, "body": {}}

    finding = await engine.compare(
        evidence_a, evidence_b, resource, expected_allowed=False, anonymous_evidence=anon
    )
    assert finding is not None
    assert finding.category == "horizontal_pe"
    assert finding.confidence == 0.9
    assert finding.evidence_diff["ownership_proof"] is True
    assert finding.evidence_diff["shared_with_anonymous"] is False


@pytest.mark.asyncio
async def test_bare_2xx_without_proof_is_low_confidence_unconfirmed(engine) -> None:
    """B gets a 2xx but the response carries no proof it holds A's data — flagged,
    but at low confidence and marked for manual confirmation, not 0.9."""
    resource = Resource(
        id="res-1",
        type="endpoint",
        value="/api/items",
        owner_identity_id="user_a",
        engagement_id="eng-1",
    )
    evidence_a = {"status_code": 200, "body": {"items": ["a"]}, "user_label": "user_a"}
    evidence_b = {"status_code": 200, "body": {"items": []}, "user_label": "user_b"}

    finding = await engine.compare(evidence_a, evidence_b, resource, expected_allowed=False)
    assert finding is not None
    assert finding.confidence == 0.5
    assert finding.category.endswith("_unconfirmed")
    assert finding.evidence_diff["needs_manual_confirmation"] is True


# ---- AIOSOP-AUDIT-2026-06-16: verification stage + read-only safety ----


def test_is_safe_method(engine) -> None:
    assert engine.is_safe_method("GET")
    assert engine.is_safe_method("HEAD")
    assert engine.is_safe_method(None)  # default GET
    assert not engine.is_safe_method("POST")
    assert not engine.is_safe_method("delete")
    assert not engine.is_safe_method("PUT")


def test_assert_distinct_identities(engine) -> None:
    assert (
        engine.assert_distinct_identities({"user_label": "user_a"}, {"user_label": "user_b"})
        is True
    )
    assert engine.assert_distinct_identities({"user_label": "x"}, {"user_label": "x"}) is False
    # self-identity markers are decisive over labels
    assert (
        engine.assert_distinct_identities(
            {"user_label": "a"}, {"user_label": "b"}, {"body": {"id": 1}}, {"body": {"id": 2}}
        )
        is True
    )
    assert (
        engine.assert_distinct_identities(
            {"user_label": "a"}, {"user_label": "b"}, {"body": {"id": 7}}, {"body": {"id": 7}}
        )
        is False
    )  # same account behind diff labels


def test_verify_finding_real_is_verified(engine) -> None:
    f = _finding(
        {"ownership_proof": True, "shared_with_anonymous": False, "semantic_divergence": []}
    )
    v = engine.verify_finding(f, {"user_label": "user_a"}, {"user_label": "user_b"})
    assert v["verified"] is True
    assert v["distinct_identities"] is True
    assert v["reasons"] == []


def test_verify_finding_public_resource_rejected(engine) -> None:
    f = _finding(
        {"ownership_proof": False, "shared_with_anonymous": True, "semantic_divergence": []}
    )
    v = engine.verify_finding(f, {"user_label": "user_a"}, {"user_label": "user_b"})
    assert v["verified"] is False
    assert "identical_to_anonymous_public_resource" in v["reasons"]


def test_verify_finding_same_identity_rejected(engine) -> None:
    f = _finding(
        {"ownership_proof": True, "shared_with_anonymous": False, "semantic_divergence": []}
    )
    v = engine.verify_finding(f, {"user_label": "same"}, {"user_label": "same"})
    assert v["verified"] is False
    assert "identities_not_confirmed_distinct" in v["reasons"]
