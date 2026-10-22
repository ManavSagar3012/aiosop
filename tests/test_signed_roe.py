"""Dev-only Ed25519 signing fixtures; production code only verifies public keys."""

import base64
import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.models import ScopeDefinition
from ai_osop.safety.signed_roe import (
    SignedROEError,
    VerifiedPolicy,
    canonical_json_bytes,
    verify_signed_roe,
)


NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)


def utc(hours: int) -> str:
    return (NOW + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def example_policy():
    return {
        "engagement_id": "eng-real-session-001",
        "created_by": "alice@example.com",
        "domains": ["example.test", "api.example.test"],
        "ips": ["10.7.0.0/24"],
        "exclusions": ["internal.example.test"],
        "allowed_techniques": ["recon", "vuln_scan"],
        "restrictions": ["no-write"],
        "approval_required_for": ["sqli", "rce"],
        "testing_window_start": utc(-2),
        "testing_window_end": utc(2),
        "roe": {
            "llm_call_budget_total": 7,
            "llm_cost_budget_usd": 0.75,
            "max_depth": 5,
            "allow_automated_exploitation": False,
        },
        "issued_at": utc(-24),
        "not_before": utc(-3),
        "expires_at": utc(3),
        "version": 5,
        "authorization_id": "auth-real-123",
        "key_id": "key-prod-2026",
    }


def signed_policy(private: Ed25519PrivateKey, policy: dict, version=None) -> dict:
    signature = private.sign(canonical_json_bytes(policy))
    return {
        "version": policy["version"] if version is None else version,
        "policy": copy.deepcopy(policy),
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }


@pytest.fixture
def signed_fixture(monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON",
        json.dumps({"key-prod-2026": base64.b64encode(public).decode("ascii")}),
    )
    policy = example_policy()
    scope = ScopeDefinition(
        engagement_id=policy["engagement_id"],
        domains=list(policy["domains"]),
        ips=list(policy["ips"]),
        exclusions=list(policy["exclusions"]),
        allowed_techniques=list(policy["allowed_techniques"]),
        restrictions=list(policy["restrictions"]),
        approval_required_for=list(policy["approval_required_for"]),
        testing_window_start=datetime.fromisoformat(
            policy["testing_window_start"].replace("Z", "+00:00")
        ),
        testing_window_end=datetime.fromisoformat(
            policy["testing_window_end"].replace("Z", "+00:00")
        ),
        authorization_ref=policy["authorization_id"],
    )

    def verify(envelope=None, **kwargs):
        return verify_signed_roe(
            signed_policy(private, policy) if envelope is None else envelope,
            kwargs.get("engagement_id", policy["engagement_id"]),
            kwargs.get("owner", policy["created_by"]),
            kwargs.get("scope", scope),
            kwargs.get("roe", copy.deepcopy(policy["roe"])),
            kwargs.get("now", NOW),
        )

    return {
        "private": private,
        "public": public,
        "policy": policy,
        "scope": scope,
        "verify": verify,
    }


def test_canonical_bytes_are_sorted_utf8_unescaped_and_reject_nan():
    assert canonical_json_bytes({"é": "🚀", "a": [True, None, 7]}) == (
        '{"a":[true,null,7],"é":"🚀"}'.encode("utf-8")
    )
    assert canonical_json_bytes({"b": 1, "a": 2}) == canonical_json_bytes({"a": 2, "b": 1})
    for invalid in ({"v": float("nan")}, {"v": float("inf")}, {1: "value"}, {"v": {1, 2}}):
        with pytest.raises(SignedROEError):
            canonical_json_bytes(invalid)


def test_valid_policy_matches_exact_durable_session_and_returns_detached_immutable_receipt(
    signed_fixture,
):
    verify = signed_fixture["verify"]
    envelope = signed_policy(signed_fixture["private"], signed_fixture["policy"])
    result = verify(envelope)
    assert isinstance(result, VerifiedPolicy)
    assert result.engagement_id == "eng-real-session-001"
    assert result.created_by == "alice@example.com"
    assert result.authorization_id == "auth-real-123"
    assert result.kid == "key-prod-2026"
    assert result.signature == envelope["signature"]
    assert isinstance(result.signature, str) and len(result.signature) == 86
    assert result.version == 5
    assert (
        result.policy_digest
        == hashlib.sha256(canonical_json_bytes(signed_fixture["policy"])).hexdigest()
    )
    assert result.scope["engagement_id"] == result.engagement_id
    assert result.scope["authorization_ref"] == result.authorization_id
    assert result.roe["llm_call_budget_total"] == 7
    with pytest.raises(FrozenInstanceError):
        result.kid = "evil"
    scope = result.scope
    scope["domains"].append("evil.example.test")
    roe = result.roe
    roe["llm_call_budget_total"] = 9999
    envelope["policy"]["domains"].append("evil.example.test")
    assert result.scope["domains"] == ["example.test", "api.example.test"]
    assert result.roe["llm_call_budget_total"] == 7
    replay = {
        "version": result.version,
        "policy": json.loads(result.canonical_bytes),
        "signature": result.signature,
    }
    assert verify(replay).policy_digest == result.policy_digest


@pytest.mark.parametrize(
    "mutation",
    [
        lambda e: e.update({"extra": True}),
        lambda e: e.pop("policy"),
        lambda e: e.pop("signature"),
        lambda e: e.update({"version": 6}),
        lambda e: e.update({"version": True}),
        lambda e: e["policy"].update({"unexpected": 99}),
        lambda e: e["policy"].pop("created_by"),
        lambda e: e["policy"].update({"version": 0}),
        lambda e: e["policy"].update({"version": 6}),
        lambda e: e["policy"].update({"key_id": "untrusted"}),
        lambda e: e["policy"].update({"engagement_id": "eng-other"}),
        lambda e: e["policy"].update({"created_by": "mallory"}),
        lambda e: e["policy"]["domains"].append("evil.example.test"),
        lambda e: e["policy"]["roe"].update({"llm_call_budget_total": 1000}),
        lambda e: e["policy"]["roe"].update({"llm_cost_budget_usd": float("inf")}),
        lambda e: e["policy"].update({"authorization_id": "auth-tampered"}),
        lambda e: e["policy"].update({"testing_window_start": utc(3)}),
    ],
)
def test_envelope_tampering_fails_closed(signed_fixture, mutation):
    signed = signed_policy(signed_fixture["private"], signed_fixture["policy"])
    mutation(signed)
    with pytest.raises(SignedROEError):
        signed_fixture["verify"](signed)


@pytest.mark.parametrize(
    "value",
    ["", "?", "A" * 86, "A" * 85, "A" * 87, "A" * 86 + "=", "A" * 83 + "+XX", None],
)
def test_strict_detached_base64url_rejects_noncanonical_signature(signed_fixture, value):
    envelope = signed_policy(signed_fixture["private"], signed_fixture["policy"])
    envelope["signature"] = value
    with pytest.raises(SignedROEError):
        signed_fixture["verify"](envelope)


def test_wrong_private_key_or_untrusted_kid_cannot_verify(signed_fixture):
    policy = signed_fixture["policy"]
    with pytest.raises(SignedROEError):
        signed_fixture["verify"](signed_policy(Ed25519PrivateKey.generate(), policy))
    changed = {**policy, "key_id": "removed-key"}
    with pytest.raises(SignedROEError, match="Unknown|revoked"):
        signed_fixture["verify"](signed_policy(signed_fixture["private"], changed))


@pytest.mark.parametrize(
    "when",
    [
        NOW - timedelta(hours=25),
        NOW - timedelta(hours=4),
        NOW + timedelta(hours=2),
        NOW + timedelta(hours=4),
    ],
)
def test_expired_not_before_future_issued_and_closed_testing_window(signed_fixture, when):
    with pytest.raises(SignedROEError):
        signed_fixture["verify"](now=when)


@pytest.mark.parametrize(
    "change",
    [
        {"issued_at": utc(1)},
        {"expires_at": utc(-1)},
        {"not_before": utc(4)},
        {"expires_at": utc(-4)},
        {"testing_window_start": utc(2)},
        {"testing_window_end": utc(-1)},
        {"issued_at": "2026-10-14T12:00:00+00:00"},
        {"issued_at": "2026-02-30T12:00:00Z"},
        {"testing_window_start": None},
    ],
)
def test_resigned_invalid_dates_still_fail_policy_validation(signed_fixture, change):
    policy = {**signed_fixture["policy"], **change}
    envelope = signed_policy(signed_fixture["private"], policy)
    with pytest.raises(SignedROEError):
        signed_fixture["verify"](envelope)


def test_refuses_mutated_original_scope_and_spending_budget(signed_fixture):
    scope = signed_fixture["scope"].model_copy(deep=True)
    scope.domains.append("extra.example.test")
    with pytest.raises(SignedROEError, match="persisted domains"):
        signed_fixture["verify"](scope=scope)
    with pytest.raises(SignedROEError, match="ROE"):
        signed_fixture["verify"](roe={"llm_call_budget_total": 1000})
    with pytest.raises(SignedROEError, match="owner"):
        signed_fixture["verify"](owner="mallory")
    with pytest.raises(SignedROEError, match="engagement"):
        signed_fixture["verify"](engagement_id="eng-other")
    scope = signed_fixture["scope"].model_copy(deep=True)
    scope.engagement_id = "client-alias"
    with pytest.raises(SignedROEError, match="scope engagement"):
        signed_fixture["verify"](scope=scope)
    scope = signed_fixture["scope"].model_copy(deep=True)
    scope.authorization_ref = "auth-other"
    with pytest.raises(SignedROEError, match="authorization reference"):
        signed_fixture["verify"](scope=scope)


def test_missing_revoked_or_invalid_trust_config_fails_closed(signed_fixture, monkeypatch):
    monkeypatch.delenv("OSOP_ROE_TRUSTED_KEYS_JSON")
    with pytest.raises(SignedROEError, match="not configured"):
        signed_fixture["verify"]()
    for invalid in ("not-json", "{}", '{"key-prod-2026":"AA=="}', "[]"):
        monkeypatch.setenv("OSOP_ROE_TRUSTED_KEYS_JSON", invalid)
        with pytest.raises(SignedROEError):
            signed_fixture["verify"]()
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON",
        '{"key-prod-2026":"AA==","key-prod-2026":"AA=="}',
    )
    with pytest.raises(SignedROEError, match="Duplicate"):
        signed_fixture["verify"]()


def test_key_rotation_reloaded_on_every_verify(signed_fixture, monkeypatch):
    assert signed_fixture["verify"]().kid == "key-prod-2026"
    new_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    )
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON",
        json.dumps({"key-prod-2026": base64.b64encode(new_key).decode("ascii")}),
    )
    with pytest.raises(SignedROEError, match="signature"):
        signed_fixture["verify"]()


def test_accepted_timezone_aware_now_only(signed_fixture):
    with pytest.raises(SignedROEError, match="timezone-aware"):
        signed_fixture["verify"](now=NOW.replace(tzinfo=None))
    assert signed_fixture["verify"](
        now=NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))
    ).kid == ("key-prod-2026")


def test_rejects_invalid_signed_quotas_and_lists_even_if_signed(signed_fixture):
    for roe in (
        {"llm_call_budget_total": 0},
        {"llm_call_budget_total": True},
        {"llm_call_budget_total": -1},
        {"llm_cost_budget_usd": 0},
    ):
        policy = {**signed_fixture["policy"], "roe": roe}
        with pytest.raises(SignedROEError):
            signed_fixture["verify"](signed_policy(signed_fixture["private"], policy), roe=roe)
    for field, invalid in (
        ("domains", []),
        ("domains", ["*.example.test"]),
        ("domains", ["EXAMPLE.TEST"]),
        ("ips", ["not-an-ip"]),
        ("allowed_techniques", ["recon", "recon"]),
    ):
        policy = copy.deepcopy(signed_fixture["policy"])
        policy[field] = invalid
        with pytest.raises(SignedROEError):
            signed_fixture["verify"](signed_policy(signed_fixture["private"], policy))


def test_no_private_signer_exposed_from_production_module():
    import ai_osop.safety.signed_roe as production

    assert not hasattr(production, "sign_roe")
    assert not hasattr(production, "Ed25519PrivateKey")
