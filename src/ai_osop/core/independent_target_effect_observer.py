"""Independent production *receipt* observer, never an autonomous target probe.

This module ONLY retrieves an already recorded, separately admitted target-side
audit snapshot from an independently operated witness API. It NEVER sends GETs
to an application target, borrows an application session or runs a replay.
The witness operators must have separately administered, out-of-band provisioned
Ed25519 owner-ledger and access-event keys (different keys and operators).

Operational prerequisites outside AI-OSOP:
  * The owner signer uses a real authoritative owner-of-record DB.
  * The independent access signer uses actual approved one-shot task events,
    authenticates current source/target sessions, observes a separately
    admitted anonymous DENIAL and confirms private object disclosure.
  * The caller revalidates live PostgreSQL ROE/Flow/Tasks, source provenance
    and review, and durably fences nonce/one-shot admission in its *same*
    PostgreSQL transaction. This module CANNOT fulfill those callbacks.
  * `OSOP_INDEPENDENT_EFFECT_OBSERVER_JSON` is provisioned by trusted
    deployment control, never from model/MCP/user/target responses.

Without those independent LIVE sources it fails closed. Even a successful
verdict is typed evidence pending separate transactional review; this module
NEVER grants a VERIFIED finding, a report release or a target operation.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core.models import FlowRecord, Task
from ai_osop.core.target_authority_proof import (
    TargetAuthorityDenied,
    _canonical,
    _endpoint,
    _strict_json,
    _task_lineage,
)

_REGISTRY = "OSOP_INDEPENDENT_EFFECT_OBSERVER_JSON"
_OWNER_DOMAIN = b"AI-OSOP-LIVE-TARGET-OWNER-OF-RECORD-V1\x00"
_EFFECT_DOMAIN = b"AI-OSOP-LIVE-INDEPENDENT-EFFECT-V1\x00"
_FQDN = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_FINDING = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._-]{1,58}\Z")
_REVIEW = re.compile(r"vfdec-[0-9a-f]{32}\Z")
_QUALIFICATION = re.compile(r"teqa-[0-9a-f]{32}\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_MAX_REGISTRY = 8192
_MAX_CLAIMS = 8192
_MAX_ENVELOPE = 14000
_ENDPOINT = "/v1/approved-task-effects/"
_OWNER_FIELDS = frozenset(
    {
        "schema",
        "key_id",
        "operator_id",
        "nonce",
        "observed_at",
        "engagement_id",
        "flow_id",
        "finding_id",
        "endpoint_url",
        "resource_id",
        "owner_identity",
        "visibility",
        "revision",
        "record_sha256",
        "private_content_sha256",
        "production_owner_ledger",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "schema",
        "key_id",
        "operator_id",
        "nonce",
        "issued_at",
        "expires_at",
        "binding",
        "finding_id",
        "review_decision_id",
        "review_decision_sha256",
        "qualification_id",
        "qualification_sha256",
        "qualification_revision",
        "proof_sha256",
        "audit_sha256",
        "resource_id",
        "owner_claims_b64url",
        "owner_signature_b64url",
        "owner_record_sha256",
        "observations",
        "live_session_store",
        "durable_approved_task_events",
        "target_private_effect_observed",
        "synthetic",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "identity",
        "task_id",
        "event_id",
        "method",
        "endpoint_url",
        "resource_id",
        "request_sha256",
        "response_sha256",
        "session_sha256",
        "session_current",
        "session_generation",
        "http_status",
        "redirected",
        "access_allowed",
        "private_record_disclosed",
    }
)
_SERVICE_FIELDS = frozenset(
    {
        "engagement_id",
        "flow_id",
        "version",
        "enabled",
        "deployment",
        "generation",
        "not_before",
        "not_after",
        "origin",
        "pinned_public_ipv4",
        "allowed_hosts",
        "observer_key_id",
        "observer_operator_id",
        "observer_public_key_b64",
        "owner_key_id",
        "owner_operator_id",
        "owner_public_key_b64",
    }
)


class IndependentEffectUnavailable(PermissionError):
    """Missing independent observer or untrusted/stale target-side audit."""


@dataclass(frozen=True)
class LiveIndependentEffectEvidence:
    """Verifiable read-only observation, NOT verified/releasable finding state."""

    observer_claims_json: bytes
    observer_signature_b64url: str
    observation_sha256: str
    engagement_id: str
    flow_id: str
    flow_revision: int
    finding_id: str
    original_source_task_id: str
    source_task_id: str
    target_task_id: str
    authorization_id: str
    authorization_version: int
    authorization_sha256: str
    endpoint_url: str
    review_decision_id: str
    review_decision_sha256: str
    qualification_id: str
    qualification_sha256: str
    qualification_revision: int
    proof_sha256: str
    audit_sha256: str
    resource_id: str
    owner_identity: str
    private_content_sha256: str
    anonymous_task_id: str
    source_event_id: str
    target_event_id: str
    anonymous_event_id: str
    source_identity: str
    target_identity: str
    source_request_sha256: str
    target_request_sha256: str
    anonymous_request_sha256: str
    source_session_sha256: str
    target_session_sha256: str
    source_response_sha256: str
    target_response_sha256: str
    anonymous_response_sha256: Optional[str]
    source_http_status: int
    target_http_status: int
    anonymous_http_status: int
    issued_at: int
    expires_at: int
    redirects_seen: bool
    public_resource: bool
    observer_key_id: str
    owner_key_id: str
    nonce: str
    evidence_origin: str = "separately_operated_live_target_receipts"
    validation_state: str = "independent_observation_pending_durable_admission"
    finding_verified: bool = False
    authorization_violation_verified: bool = False
    report_release_approved: bool = False


def _valid(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _b64raw(value: Any, *, max_len: int) -> bytes:
    if (
        type(value) is not str
        or not 2 <= len(value) <= max_len
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise IndependentEffectUnavailable("Untrusted witness evidence encoding")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
            raise ValueError("Noncanonical")
        return raw
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise IndependentEffectUnavailable("Noncanonical witness evidence") from exc


def _key(raw: Any) -> tuple[Ed25519PublicKey, bytes]:
    if type(raw) is not str or len(raw) != 44:
        raise IndependentEffectUnavailable("Out-of-band witness public key required")
    try:
        key_raw = base64.b64decode(raw, validate=True)
        if len(key_raw) != 32 or base64.b64encode(key_raw).decode() != raw:
            raise ValueError("Noncanonical key")
        return Ed25519PublicKey.from_public_bytes(key_raw), key_raw
    except (ValueError, TypeError, binascii.Error) as exc:
        raise IndependentEffectUnavailable("Invalid independent witness key") from exc


def _load_trust(
    engagement_id: str, flow_id: str, *, now: Optional[int] = None
) -> tuple[Dict[str, Any], Ed25519PublicKey, Ed25519PublicKey, str]:
    """Every verification re-reads this independently provisioned LIVE trust root."""
    raw = os.environ.get(_REGISTRY, "")
    if not 1 <= len(raw.encode("utf-8")) <= _MAX_REGISTRY:
        raise IndependentEffectUnavailable("Production witness trust not configured")
    try:
        config = _strict_json(raw.encode(), max_bytes=_MAX_REGISTRY)
        if set(config) != _SERVICE_FIELDS:
            raise ValueError("Unrecognized witness trust fields")
        url = config["origin"]
        endpoint, origin = _endpoint(url + "/")
        uri = urlsplit(url)
        ip = ipaddress.ip_address(config["pinned_public_ipv4"])
        if (
            origin != url
            or endpoint != url + "/"
            or uri.scheme != "https"
            or uri.netloc != uri.hostname
            or type(config["allowed_hosts"]) is not list
            or not 2 <= len(config["allowed_hosts"]) <= 16
            or len(set(config["allowed_hosts"])) != len(config["allowed_hosts"])
            or any(
                not _valid(_FQDN, host) or host != host.lower() for host in config["allowed_hosts"]
            )
            or uri.hostname not in config["allowed_hosts"]
            or ip.version != 4
            or not ip.is_global
            or type(config["version"]) is not int
            or config["version"] != 1
            or type(config["enabled"]) is not bool
            or not config["enabled"]
            or config["deployment"] != "production"
            or type(config["generation"]) is not int
            or config["generation"] < 1
            or type(config["not_before"]) is not int
            or type(config["not_after"]) is not int
            or not config["not_before"] < config["not_after"]
            or not config["not_before"]
            <= (int(time.time()) if now is None else now)
            < config["not_after"]
            or config["engagement_id"] != engagement_id
            or config["flow_id"] != flow_id
            or any(
                not _valid(_ID, config[name])
                for name in (
                    "observer_key_id",
                    "owner_key_id",
                    "observer_operator_id",
                    "owner_operator_id",
                )
            )
            or config["observer_key_id"] == config["owner_key_id"]
            or config["observer_operator_id"] == config["owner_operator_id"]
        ):
            raise ValueError("Witness scope, public route, key revocation or rotation invalid")
        access, access_raw = _key(config["observer_public_key_b64"])
        owner, owner_raw = _key(config["owner_public_key_b64"])
        if hmac.compare_digest(access_raw, owner_raw):
            raise ValueError("Owner and access trust must be independently operated")
        return config, access, owner, hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except (
        KeyError,
        ValueError,
        TypeError,
        AttributeError,
        UnicodeError,
        TargetAuthorityDenied,
    ) as exc:
        raise IndependentEffectUnavailable(
            "Independently authorized production witness unavailable"
        ) from exc


def _check_detached(claim: bytes, signature: Any, key: Ed25519PublicKey, domain: bytes) -> None:
    if not _valid(_SIG, signature):
        raise IndependentEffectUnavailable("Canonical detached witness signature required")
    decoded = _b64raw(signature, max_len=86)
    if len(decoded) != 64:
        raise IndependentEffectUnavailable("Witness detached signature invalid")
    try:
        key.verify(decoded, domain + claim)
    except InvalidSignature as exc:
        raise IndependentEffectUnavailable("Independent witness signature failed") from exc


async def _trusted(callback: Callable[..., Awaitable[bool]], *args: Any) -> bool:
    """A failed, timed-out or broken authoritative recheck never grants access."""
    try:
        return await callback(*args) is True
    except Exception:
        return False


def _safe_event(
    row: Any, *, role: str, expected: Dict[str, Any], resource_id: str
) -> Optional[str]:
    if type(row) is not dict or set(row) != _EVENT_FIELDS:
        raise IndependentEffectUnavailable("Unsigned or malformed target access event")
    source = role == "source"
    target = role == "target"
    expected_id = (
        expected["source_identity"] if source else (expected["target_identity"] if target else None)
    )
    expected_task = (
        expected["source_task_id"] if source else (expected["target_task_id"] if target else None)
    )
    expected_request = (
        expected["source_request_sha256"]
        if source
        else (expected["target_request_sha256"] if target else None)
    )
    expected_session = (
        expected["source_session_sha256"]
        if source
        else (expected["target_session_sha256"] if target else None)
    )
    expected_response = (
        expected["source_response_sha256"]
        if source
        else (expected["target_response_sha256"] if target else None)
    )
    if (
        row["identity"] != expected_id
        or (
            row["task_id"] != expected_task
            if source or target
            else not _valid(_TASK, row["task_id"])
        )
        or not _valid(_ID, row["event_id"])
        or row["method"] != "GET"
        or row["endpoint_url"] != expected["endpoint_url"]
        or row["resource_id"] != resource_id
        or (
            row["request_sha256"] != expected_request
            if source or target
            else not _valid(_SHA, row["request_sha256"])
        )
        or (
            row["response_sha256"] != expected_response
            if source or target
            else (row["response_sha256"] is not None and not _valid(_SHA, row["response_sha256"]))
        )
        or (
            row["session_sha256"] != expected_session
            if source or target
            else row["session_sha256"] is not None
        )
        or row["session_current"] is not (source or target)
    ):
        raise IndependentEffectUnavailable("Independent event does not match approved live Task")
    if (
        (type(row["session_generation"]) is not int or row["session_generation"] <= 0)
        if source or target
        else row["session_generation"] is not None
    ):
        raise IndependentEffectUnavailable("Current authenticating session generation required")
    if (
        type(row["http_status"]) is not int
        or row["redirected"] is not False
        or row["access_allowed"] is not source
        or row["private_record_disclosed"] is not (source or target)
        or (
            row["http_status"] != 200
            if source or target
            else row["http_status"] not in (401, 403, 404)
        )
    ):
        raise IndependentEffectUnavailable("No independently verified private unauthorized access")
    return row["task_id"]


async def verify_independent_target_effect_claims(
    *,
    observer_claims_json: bytes,
    observer_signature_b64url: str,
    expected_nonce: str,
    engagement_id: str,
    flow: FlowRecord,
    signed_authorization: Any,
    original_source_task: Task,
    source_task: Task,
    target_task: Task,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    qualification_id: str,
    qualification_sha256: str,
    qualification_revision: int,
    proof_sha256: str,
    audit_sha256: str,
    trusted_current_authority_check: Callable[[], Awaitable[bool]],
    trusted_current_review_check: Callable[[str, str], Awaitable[bool]],
    trusted_current_qualification_check: Callable[[str, str, str, int], Awaitable[bool]],
    trusted_one_shot_admission_check: Callable[[str, str, str], Awaitable[bool]],
) -> LiveIndependentEffectEvidence:
    """Verify out-of-band LIVE owner+effect receipts, NEVER release a finding.

    Caller MUST hold the original PG transaction and revalidate the signed
    owner/ROE/Flow, source+target+anonymous one-shot admissions/current sessions
    and immutable review from its authoritative stores inside the callbacks.
    `expected_nonce` MUST have been independently generated/issued by the
    verifier, never accepted from arbitrary target/MCP/provider/client evidence.
    The witness merely reads pre-existing Task effects; no remote replay here.
    """
    if not (
        isinstance(flow, FlowRecord)
        and _valid(_NONCE, expected_nonce)
        and _valid(_FINDING, finding_id)
        and _valid(_REVIEW, review_decision_id)
        and _valid(_SHA, review_decision_sha256)
        and _valid(_QUALIFICATION, qualification_id)
        and _valid(_SHA, qualification_sha256)
        and type(qualification_revision) is int
        and qualification_revision > 0
        and _valid(_SHA, proof_sha256)
        and _valid(_SHA, audit_sha256)
        and callable(trusted_current_authority_check)
        and callable(trusted_current_review_check)
        and callable(trusted_current_qualification_check)
        and callable(trusted_one_shot_admission_check)
    ):
        raise IndependentEffectUnavailable("Live independently approved source required")
    now = int(time.time())
    config, access_key, owner_key, trust_hash = _load_trust(engagement_id, flow.id, now=now)
    try:
        expected = _task_lineage(
            source=source_task,
            target=target_task,
            original=original_source_task,
            flow=flow,
            signed=signed_authorization,
            engagement_id=engagement_id,
        )
    except (TargetAuthorityDenied, ValueError, TypeError) as exc:
        raise IndependentEffectUnavailable("Signed original/source/target lineage invalid") from exc
    if (
        not await _trusted(trusted_current_authority_check)
        or not await _trusted(trusted_current_review_check, finding_id, review_decision_sha256)
        or not await _trusted(
            trusted_current_qualification_check,
            finding_id,
            qualification_id,
            qualification_sha256,
            qualification_revision,
        )
    ):
        raise IndependentEffectUnavailable("Current signed owner, ROE or review revoked")
    try:
        claims = _strict_json(observer_claims_json, max_bytes=_MAX_CLAIMS)
        _check_detached(observer_claims_json, observer_signature_b64url, access_key, _EFFECT_DOMAIN)
        if set(claims) != _CLAIM_FIELDS:
            raise ValueError("Unrecognized independent effect fields")
        if not (
            claims["schema"] == "ai-osop.independent-target-effect.v1"
            and claims["key_id"] == config["observer_key_id"]
            and claims["operator_id"] == config["observer_operator_id"]
            and claims["nonce"] == expected_nonce
            and type(claims["issued_at"]) is int
            and type(claims["expires_at"]) is int
            and now - 30 <= claims["issued_at"] <= now + 5
            and claims["issued_at"] < claims["expires_at"] <= claims["issued_at"] + 90
            and now < claims["expires_at"]
            and claims["binding"] == expected
            and claims["finding_id"] == finding_id
            and claims["review_decision_id"] == review_decision_id
            and claims["review_decision_sha256"] == review_decision_sha256
            and claims["qualification_id"] == qualification_id
            and claims["qualification_sha256"] == qualification_sha256
            and type(claims["qualification_revision"]) is int
            and claims["qualification_revision"] == qualification_revision
            and claims["proof_sha256"] == proof_sha256
            and claims["audit_sha256"] == audit_sha256
            and _valid(_RESOURCE, claims["resource_id"])
            and claims["synthetic"] is False
            and claims["live_session_store"] is True
            and claims["durable_approved_task_events"] is True
            and claims["target_private_effect_observed"] is True
        ):
            raise ValueError("Witness binding or live observation invalid")
        resource = claims["resource_id"]
        # Object must be the exact object named in the approved HTTPS URL;
        # no unrelated private owner-of-record can be spliced into a replay.
        path_leaf = urlsplit(expected["endpoint_url"]).path.rstrip("/").split("/")[-1]
        if resource != path_leaf:
            raise ValueError("Owner record is not the approved endpoint resource")
        owner_bytes = _b64raw(claims["owner_claims_b64url"], max_len=11500)
        owner = _strict_json(owner_bytes, max_bytes=4096)
        _check_detached(owner_bytes, claims["owner_signature_b64url"], owner_key, _OWNER_DOMAIN)
        if (
            set(owner) != _OWNER_FIELDS
            or owner["schema"] != "ai-osop.live-target-owner-of-record.v1"
            or owner["key_id"] != config["owner_key_id"]
            or owner["operator_id"] != config["owner_operator_id"]
            or owner["nonce"] != expected_nonce
            or type(owner["observed_at"]) is not int
            or not now - 30 <= owner["observed_at"] <= now + 5
            or owner["engagement_id"] != engagement_id
            or owner["flow_id"] != flow.id
            or owner["finding_id"] != finding_id
            or owner["endpoint_url"] != expected["endpoint_url"]
            or owner["resource_id"] != resource
            or owner["owner_identity"] != expected["source_identity"]
            or owner["visibility"] != "private"
            or type(owner["revision"]) is not int
            or owner["revision"] < 1
            or not _valid(_SHA, owner["record_sha256"])
            or owner["private_content_sha256"] != expected["source_response_sha256"]
            or owner["production_owner_ledger"] is not True
            or claims["owner_record_sha256"]
            != hashlib.sha256(_OWNER_DOMAIN + owner_bytes).hexdigest()
        ):
            raise ValueError("Separately signed live private owner-of-record invalid")
        observations = claims["observations"]
        if type(observations) is not dict or set(observations) != {"source", "target", "anonymous"}:
            raise ValueError("Three live role events required")
        anonymous_task = None
        for role in ("source", "target", "anonymous"):
            task = _safe_event(
                observations[role], role=role, expected=expected, resource_id=resource
            )
            if role == "anonymous":
                anonymous_task = task
        if (
            len({observations[r]["event_id"] for r in observations}) != 3
            or observations["source"]["session_sha256"] == observations["target"]["session_sha256"]
            or anonymous_task in {expected["source_task_id"], expected["target_task_id"]}
        ):
            raise ValueError("Distinct independently approved role observations required")
    except (ValueError, KeyError, TypeError, AttributeError, TargetAuthorityDenied) as exc:
        raise IndependentEffectUnavailable(
            "Live target owner/access evidence missing, public, synthetic or stale"
        ) from exc
    # Every await may permit expiry, signed ROE revocation or separately
    # provisioned witness key rotation. All are rechecked before a verdict.
    if not (
        await _trusted(
            trusted_one_shot_admission_check,
            finding_id,
            anonymous_task,
            expected_nonce,
        )
        and await _trusted(trusted_current_authority_check)
        and await _trusted(trusted_current_review_check, finding_id, review_decision_sha256)
        and await _trusted(
            trusted_current_qualification_check,
            finding_id,
            qualification_id,
            qualification_sha256,
            qualification_revision,
        )
    ):
        raise IndependentEffectUnavailable("Current one-shot audit or signed review revoked")
    updated, _, _, updated_hash = _load_trust(engagement_id, flow.id)
    try:
        current_lineage = _task_lineage(
            source=source_task,
            target=target_task,
            original=original_source_task,
            flow=flow,
            signed=signed_authorization,
            engagement_id=engagement_id,
        )
    except (ValueError, TypeError, TargetAuthorityDenied) as exc:
        raise IndependentEffectUnavailable("Original signed replay lineage revoked") from exc
    if (
        updated_hash != trust_hash
        or updated["generation"] != config["generation"]
        or int(time.time()) >= claims["expires_at"]
        or current_lineage != expected
    ):
        raise IndependentEffectUnavailable("Observer key rotated or original Task lineage changed")
    return LiveIndependentEffectEvidence(
        observer_claims_json=observer_claims_json,
        observer_signature_b64url=observer_signature_b64url,
        observation_sha256=hashlib.sha256(
            _EFFECT_DOMAIN + observer_claims_json + _b64raw(observer_signature_b64url, max_len=86)
        ).hexdigest(),
        engagement_id=engagement_id,
        flow_id=flow.id,
        flow_revision=flow.revision,
        finding_id=finding_id,
        original_source_task_id=expected["original_source_task_id"],
        source_task_id=expected["source_task_id"],
        target_task_id=expected["target_task_id"],
        authorization_id=expected["authorization_id"],
        authorization_version=expected["authorization_version"],
        authorization_sha256=expected["authorization_sha256"],
        endpoint_url=expected["endpoint_url"],
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        qualification_revision=qualification_revision,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        resource_id=resource,
        owner_identity=owner["owner_identity"],
        private_content_sha256=owner["private_content_sha256"],
        anonymous_task_id=anonymous_task,
        source_event_id=observations["source"]["event_id"],
        target_event_id=observations["target"]["event_id"],
        anonymous_event_id=observations["anonymous"]["event_id"],
        source_identity=expected["source_identity"],
        target_identity=expected["target_identity"],
        source_request_sha256=observations["source"]["request_sha256"],
        target_request_sha256=observations["target"]["request_sha256"],
        anonymous_request_sha256=observations["anonymous"]["request_sha256"],
        source_session_sha256=observations["source"]["session_sha256"],
        target_session_sha256=observations["target"]["session_sha256"],
        source_response_sha256=observations["source"]["response_sha256"],
        target_response_sha256=observations["target"]["response_sha256"],
        anonymous_response_sha256=observations["anonymous"]["response_sha256"],
        source_http_status=observations["source"]["http_status"],
        target_http_status=observations["target"]["http_status"],
        anonymous_http_status=observations["anonymous"]["http_status"],
        issued_at=claims["issued_at"],
        expires_at=claims["expires_at"],
        redirects_seen=False,
        public_resource=False,
        observer_key_id=config["observer_key_id"],
        owner_key_id=config["owner_key_id"],
        nonce=expected_nonce,
    )


async def _fetch_pinned_audit(*, origin: str, pinned_ip: str, nonce: str) -> tuple[bytes, str]:
    """TLS 1.2+ SNI/CA, pinned public IP, fixed AUDIT path, no DNS/proxy/redirect.

    No arbitrary HTTP client, target URL, caller headers or bearer sessions
    cross this boundary. Bounded HTTP/1.1 response; a DNS rebinding cannot
    redirect the socket because TLS connects to the preapproved numeric IP.
    """
    host = urlsplit(origin).hostname
    if not _valid(_NONCE, nonce) or not _valid(_FQDN, host):
        raise IndependentEffectUnavailable("Unsafe production witness route")
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=pinned_ip,
                port=443,
                ssl=ssl_ctx,
                server_hostname=host,
                limit=4096,
            ),
            timeout=3.0,
        )
        query = (
            f"GET {_ENDPOINT}{nonce} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(query)
        await asyncio.wait_for(writer.drain(), timeout=3.0)
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3.0)
        if len(headers) > 4096 or not headers.startswith(b"HTTP/1.1 200\r\n"):
            raise ValueError("Audit endpoint denied or redirected")
        parsed: Dict[bytes, bytes] = {}
        for line in headers[:-4].split(b"\r\n")[1:]:
            if b":" not in line:
                raise ValueError("Invalid header")
            key, value = (part.strip() for part in line.split(b":", 1))
            key = key.lower()
            if key in parsed or not re.fullmatch(rb"[a-z0-9-]+", key):
                raise ValueError("Duplicate/untrusted header")
            parsed[key] = value
        if (
            b"location" in parsed
            or b"transfer-encoding" in parsed
            or b"content-encoding" in parsed
            or parsed.get(b"content-type") != b"application/json"
            or not re.fullmatch(rb"[1-9][0-9]{0,4}", parsed.get(b"content-length", b""))
        ):
            raise ValueError("Unsafe audit transport headers")
        size = int(parsed[b"content-length"])
        if not 1 <= size <= _MAX_ENVELOPE:
            raise ValueError("Oversized witness response")
        body = await asyncio.wait_for(reader.readexactly(size), timeout=3.0)
        envelope = _strict_json(body, max_bytes=_MAX_ENVELOPE)
        if set(envelope) != {"observer_claims_b64url", "observer_signature_b64url"}:
            raise ValueError("Detached signed witness envelope required")
        return (
            _b64raw(envelope["observer_claims_b64url"], max_len=11500),
            envelope["observer_signature_b64url"],
        )
    except (
        OSError,
        ValueError,
        TypeError,
        UnicodeError,
        TimeoutError,
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
    ) as exc:
        raise IndependentEffectUnavailable("Independent HTTPS effect witness unavailable") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (OSError, TimeoutError):
                pass


async def fetch_independent_target_effect_signed_receipt(
    *,
    engagement_id: str,
    flow: FlowRecord,
    expected_nonce: str,
) -> tuple[bytes, str]:
    """Transport ONLY, returns UNTRUSTED signed bytes for 0022 PG admission.

    Issuing a PostgreSQL one-shot nonce and authorizing this request are
    exclusively the caller's responsibility. No application target, session or
    replay is accessed. The result MUST go through
    `verify_independent_target_effect_claims` with same-transaction live
    signed ROE/Task/review/qualification/nonce checks before any admission.
    Never treat this tuple or the HTTP status as verified.
    """
    if (
        not isinstance(flow, FlowRecord)
        or not _valid(_ID, engagement_id)
        or flow.engagement_id != engagement_id
        or not _valid(_NONCE, expected_nonce)
    ):
        raise IndependentEffectUnavailable("PG-issued observer challenge and Flow required")
    config, _, _, initial_hash = _load_trust(engagement_id, flow.id)
    raw, signature = await _fetch_pinned_audit(
        origin=config["origin"],
        pinned_ip=config["pinned_public_ipv4"],
        nonce=expected_nonce,
    )
    # Source operators can revoke or rotate keys between challenge admission
    # and fetch completion. This detects a transport-level epoch change; the
    # ledger MUST separately verify the signature and current authority.
    _, _, _, fresh_hash = _load_trust(engagement_id, flow.id)
    if initial_hash != fresh_hash:
        raise IndependentEffectUnavailable("Witness trust changed during receipt fetch")
    return raw, signature


async def fetch_independent_target_effect_observation(
    *,
    engagement_id: str,
    flow: FlowRecord,
    signed_authorization: Any,
    original_source_task: Task,
    source_task: Task,
    target_task: Task,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    qualification_id: str,
    qualification_sha256: str,
    qualification_revision: int,
    expected_nonce: str,
    proof_sha256: str,
    audit_sha256: str,
    trusted_current_authority_check: Callable[[], Awaitable[bool]],
    trusted_current_review_check: Callable[[str, str], Awaitable[bool]],
    trusted_current_qualification_check: Callable[[str, str, str, int], Awaitable[bool]],
    trusted_one_shot_admission_check: Callable[[str, str, str], Awaitable[bool]],
) -> LiveIndependentEffectEvidence:
    """Read-only approved Task audit snapshot from ONE preconfigured LIVE API.

    Does not cause new source/target/anonymous requests. Use ONLY when separate
    signed one-shot admissions exist; witness absent or failed => UNKNOWN.
    """
    claims, signature = await fetch_independent_target_effect_signed_receipt(
        engagement_id=engagement_id,
        flow=flow,
        expected_nonce=expected_nonce,
    )
    return await verify_independent_target_effect_claims(
        observer_claims_json=claims,
        observer_signature_b64url=signature,
        expected_nonce=expected_nonce,
        engagement_id=engagement_id,
        flow=flow,
        signed_authorization=signed_authorization,
        original_source_task=original_source_task,
        source_task=source_task,
        target_task=target_task,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        qualification_revision=qualification_revision,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        trusted_current_authority_check=trusted_current_authority_check,
        trusted_current_review_check=trusted_current_review_check,
        trusted_current_qualification_check=trusted_current_qualification_check,
        trusted_one_shot_admission_check=trusted_one_shot_admission_check,
    )
