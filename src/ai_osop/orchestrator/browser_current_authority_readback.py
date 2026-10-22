"""Read-only current central authority for an original 0027/0034 Browser capture.

This is an intentionally unregistered *host-side* contract. A caller must use
the real central FlowMCPActionStore/AsyncSession and independently authenticate
its transport. Neither a browser provider receipt nor a HAR digest grants
authorization, permits another navigation, or proves a target-side effect.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import text

from ai_osop.memory.authorization_store import (
    _policy_binding_matches,
    _validated_policy_window,
    _verify_persisted_signature,
)
from ai_osop.memory.browser_source_authority import (
    DOMAIN as SOURCE_DOMAIN,
    _CLAIM_FIELDS as SOURCE_FIELDS,
    _canonical,
    exact_origin,
    BrowserSourceAuthorityStore,
)
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.safety.approval_binding import matches_pinned_payload
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets
from ai_osop.safety.signed_roe import verify_signed_roe


CURRENT_DOMAIN = b"ai-osop/browser-current-central-authority/v1\x00"
EVIDENCE_DOMAIN = b"ai-osop/browser-reviewed-evidence/v1\x00"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}\Z")
_SOURCE_ID = re.compile(r"nbp-[a-f0-9]{32}\Z")
_CURRENT_ID = re.compile(r"bca-[a-f0-9]{32}\Z")
_CURRENT_FIELDS = frozenset({
    "version", "check_id", "request_id", "engagement_id", "flow_id",
    "task_id", "subtask_id", "action_id", "owner_id", "preflight_id",
    "authorization_sha256", "original_intent_sha256", "source_claims_sha256",
    "url_sha256", "origin", "evidence_attestation_sha256", "checked_at",
    "expires_at", "authority_current", "artifact_bytes_verified",
    "target_effect_verified", "purpose",
})
_EVIDENCE_FIELDS = frozenset({
    "version", "request_id", "engagement_id", "task_id", "server_id",
    "source_preflight_id", "action_id", "authorization_sha256",
    "evidence_mode", "artifacts", "issued_at",
})


class BrowserCurrentAuthorityDenied(RuntimeError):
    """Current corroboration unavailable; never authorize execution on error."""


def _deny() -> None:
    raise BrowserCurrentAuthorityDenied("Current Browser central authority unavailable")


def _canonical_limited(claims: Any) -> bytes:
    try:
        data = _canonical(claims)
    except Exception as exc:
        raise BrowserCurrentAuthorityDenied("Invalid Browser corroboration") from exc
    if not 2 <= len(data) <= 4096:
        _deny()
    return data


def _roots(env_name: str) -> dict[str, bytes]:
    try:
        raw = os.environ[env_name]
        if not 2 <= len(raw) <= 8192:
            _deny()

        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            values: dict[str, Any] = {}
            for name, value in pairs:
                if name in values:
                    _deny()
                values[name] = value
            return values

        listed = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(listed) is not dict or not 1 <= len(listed) <= 16:
            _deny()
        keys = {}
        for kid, encoded in listed.items():
            if type(kid) is not str or not _KID.fullmatch(kid) or type(encoded) is not str:
                _deny()
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32 or base64.b64encode(key).decode("ascii") != encoded:
                _deny()
            keys[kid] = key
        return keys
    except BrowserCurrentAuthorityDenied:
        raise
    except Exception as exc:
        raise BrowserCurrentAuthorityDenied("Independent trust roots unavailable") from exc


def _verify(envelope: Any, roots: Mapping[str, bytes], domain: bytes,
            fields: frozenset[str]) -> dict[str, Any]:
    if (type(envelope) is not dict or set(envelope) != {"claims", "kid", "signature"}
            or type(envelope["claims"]) is not dict
            or set(envelope["claims"]) != fields
            or type(envelope["kid"]) is not str or envelope["kid"] not in roots):
        _deny()
    signature = envelope["signature"]
    if (type(signature) is not str or
            re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None):
        _deny()
    try:
        signature_raw = base64.urlsafe_b64decode(signature + "==")
        if (len(signature_raw) != 64 or
                base64.urlsafe_b64encode(signature_raw).decode("ascii").rstrip("=") != signature):
            _deny()
        Ed25519PublicKey.from_public_bytes(roots[envelope["kid"]]).verify(
            signature_raw, domain + _canonical_limited(envelope["claims"])
        )
    except BrowserCurrentAuthorityDenied:
        raise
    except Exception as exc:
        raise BrowserCurrentAuthorityDenied("Untrusted Browser corroboration signature") from exc
    return envelope["claims"]


def _provider_roots() -> dict[str, bytes]:
    try:
        source = os.environ["OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON"]
        if len(source) > 16384:
            _deny()
        listed = json.loads(source)
        provider = listed["browser-mcp"]
        if type(provider) is not dict or not 1 <= len(provider) <= 16:
            _deny()
        return {
            kid: base64.b64decode(value, validate=True)
            for kid, value in provider.items()
            if type(kid) is str and _KID.fullmatch(kid) and type(value) is str
        }
    except BrowserCurrentAuthorityDenied:
        raise
    except Exception as exc:
        raise BrowserCurrentAuthorityDenied("Provider evidence roots unavailable") from exc


def _central_signer(source_roots: Mapping[str, bytes],
                    provider_roots: Mapping[str, bytes]) -> tuple[str, Ed25519PrivateKey]:
    roots = _roots("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON")
    try:
        kid = os.environ["OSOP_BROWSER_CURRENT_AUTHORITY_SIGNING_KID"]
        raw = base64.b64decode(
            os.environ["OSOP_BROWSER_CURRENT_AUTHORITY_PRIVATE_KEY_B64"], validate=True
        )
        if type(kid) is not str or not _KID.fullmatch(kid) or len(raw) != 32:
            _deny()
        key = Ed25519PrivateKey.from_private_bytes(raw)
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if (kid not in roots or not hmac.compare_digest(public, roots[kid])
                or public in source_roots.values() or public in provider_roots.values()):
            _deny()
        return kid, key
    except BrowserCurrentAuthorityDenied:
        raise
    except Exception as exc:
        raise BrowserCurrentAuthorityDenied("Independent central signer unavailable") from exc


def verify_current_browser_authority(proof: Any, expected: Mapping[str, str],
                                     *, now: Optional[int] = None) -> dict[str, Any]:
    """Consumer verifier; roots must be installed separately from the provider."""
    roots = _roots("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON")
    claims = _verify(proof, roots, CURRENT_DOMAIN, _CURRENT_FIELDS)
    clock = int(time.time()) if now is None else now
    if (type(clock) is not int or type(claims["version"]) is not int
            or claims["version"] != 1 or type(claims["checked_at"]) is not int
            or type(claims["expires_at"]) is not int
            or not clock - 2 <= claims["checked_at"] <= clock
            or not clock < claims["expires_at"] <= claims["checked_at"] + 5
            or type(claims["check_id"]) is not str
            or not _CURRENT_ID.fullmatch(claims["check_id"])
            or claims["authority_current"] is not True
            or claims["artifact_bytes_verified"] is not False
            or claims["target_effect_verified"] is not False
            or claims["purpose"] != "current_authority_readback_only"
            or any(type(claims[k]) is not str or not _SHA.fullmatch(claims[k])
                   for k in ("authorization_sha256", "original_intent_sha256",
                             "source_claims_sha256", "url_sha256", "evidence_attestation_sha256"))
            or type(claims["preflight_id"]) is not str
            or not _SOURCE_ID.fullmatch(claims["preflight_id"])):
        _deny()
    for name in ("request_id", "engagement_id", "flow_id", "task_id",
                 "subtask_id", "action_id", "owner_id", "preflight_id"):
        if name not in expected or type(expected[name]) is not str or claims[name] != expected[name]:
            _deny()
    if any(claims[key] != value for key, value in expected.items() if key in claims):
        _deny()
    return claims


async def _read(db: Any, query: str, **params: Any) -> Mapping[str, Any]:
    record = (await db.execute(text(query), params)).mappings().one_or_none()
    if record is None:
        _deny()
    return dict(record)


class BrowserCurrentAuthorityReadback:
    """Host-only read from a current central session; never reissues 0034."""

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny()
        self._actions = actions

    async def corroborate(self, source_proof: Any, provider_evidence: Any) -> dict[str, Any]:
        """Sign five-second current state after a PostgreSQL READ ONLY snapshot."""
        source_roots = _roots("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
        provider_roots = _provider_roots()
        kid, signer = _central_signer(source_roots, provider_roots)
        source = _verify(source_proof, source_roots, SOURCE_DOMAIN, SOURCE_FIELDS)
        evidence = _verify(provider_evidence, provider_roots, EVIDENCE_DOMAIN,
                           _EVIDENCE_FIELDS)
        now = int(time.time())
        if (source.get("version") != 1 or source.get("server_id") != "browser-mcp"
                or source.get("tool_name") != "execute" or source.get("action") != "navigate"
                or source.get("evidence_mode") != "screenshot_dom_har"
                or type(source.get("issued_at")) is not int
                or type(source.get("expires_at")) is not int
                or not 0 < source["expires_at"] - source["issued_at"] <= 10
                or source["issued_at"] > now
                or type(evidence.get("issued_at")) is not int
                or not now - 120 <= evidence["issued_at"] <= now + 2
                or evidence.get("version") != 1
                or evidence.get("evidence_mode") != "screenshot_dom_har"
                or evidence.get("server_id") != "browser-mcp"
                or any(evidence.get(key) != source.get(key)
                       for key in ("request_id", "engagement_id", "task_id",
                                   "action_id", "authorization_sha256"))
                or evidence.get("source_preflight_id") != source.get("preflight_id")
                or type(evidence.get("artifacts")) is not dict
                or set(evidence["artifacts"]) != {"screenshot", "dom", "har"}):
            _deny()
        for name, suffix in (("screenshot", "png"), ("dom", "html"), ("har", "har")):
            item = evidence["artifacts"][name]
            if (type(item) is not dict or set(item) != {"path", "sha256", "size_bytes"}
                    or type(item["path"]) is not str
                    or not re.fullmatch(r"captures/[a-f0-9]{32}\." + suffix, item["path"])
                    or type(item["sha256"]) is not str or not _SHA.fullmatch(item["sha256"])
                    or type(item["size_bytes"]) is not int or not 0 < item["size_bytes"] <= 4 * 1024 * 1024):
                _deny()
        if type(source["request_id"]) is not str or not re.fullmatch(r"req-[a-f0-9]{48}", source["request_id"]):
            _deny()
        if any(type(source[k]) is not str or not _IDENT.fullmatch(source[k])
               for k in ("engagement_id", "flow_id", "task_id", "subtask_id", "owner_id")):
            _deny()
        if (not source["engagement_id"].startswith("eng-") or
                not source["task_id"].startswith("task-")):
            _deny()

        try:
            async with self._actions._sessions()() as db:
                async with db.begin():
                    # Every query below is SELECT; the DB transaction also
                    # prohibits writes, row updates and replay by construction.
                    await db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
                    action = await _read(db,
                        "SELECT * FROM flow_mcp_action_dispatches WHERE request_id=:request",
                        request=source["request_id"])
                    BrowserSourceAuthorityStore._original_intent(action)
                    if (action.get("status") != "unknown" or action.get("cancel_requested") is not False
                            or action.get("receipt_sha256") is not None or
                            action.get("side_effect_class") != "RECON_ACTIVE" or
                            any(action.get(k) != source.get(k) for k in (
                                "request_id", "engagement_id", "flow_id", "task_id",
                                "subtask_id", "action_id", "owner_id", "server_id",
                                "tool_name", "approval_id", "lease_id", "authorization_version",
                                "authorization_sha256"))):
                        _deny()
                    event = await _read(db,
                        "SELECT action_id,intent_sha256 FROM flow_mcp_action_dispatch_events "
                        "WHERE action_id=:action AND kind='dispatch_attempted' AND status='unknown'",
                        action=action["action_id"])
                    if event["intent_sha256"] != action["intent_sha256"]:
                        _deny()
                    issued = await _read(db,
                        "SELECT * FROM native_browser_source_preflights WHERE action_id=:action "
                        "AND request_id=:request AND engagement_id=:eng AND task_id=:task",
                        action=action["action_id"], request=action["request_id"],
                        eng=action["engagement_id"], task=action["task_id"])
                    if (issued.get("committed_at") is None
                            or issued.get("kid") != source_proof["kid"]
                            or any(issued.get(k) != source.get(k) for k in SOURCE_FIELDS)
                            or not hmac.compare_digest(issued.get("claims_sha256", ""),
                                                       hashlib.sha256(_canonical_limited(source)).hexdigest())
                            or not hmac.compare_digest(issued.get("signature_sha256", ""),
                                                       hashlib.sha256(base64.urlsafe_b64decode(
                                                           source_proof["signature"] + "==")).hexdigest())):
                        _deny()
                    original = action.get("safe_parameters")
                    if (type(original) is not dict or set(original) !=
                            {"action", "url", "user_label", "evidence_mode"}
                            or original["action"] != "navigate" or
                            original["evidence_mode"] != "screenshot_dom_har" or
                            original["user_label"] != source["user_label"] or
                            hashlib.sha256(original["url"].encode()).hexdigest() != source["url_sha256"] or
                            exact_origin(original["url"]) != source["origin"] or
                            FlowMCPActionStore.parameters_sha256(original) != action["parameters_sha256"]):
                        _deny()
                    declaration = self._actions._declaration("browser-mcp", "execute")
                    if (declaration.side_effect_class is not SideEffectClass.RECON_ACTIVE
                            or declaration.scope_check is not True
                            or declaration.requires_approval is not True
                            or self._actions.declaration_sha256(declaration, "browser-mcp")
                            != action["declaration_sha256"]):
                        _deny()

                    session = await _read(db,
                        "SELECT session_id,scope,roe,created_by,phase FROM session_states "
                        "WHERE session_id=:eng", eng=action["engagement_id"])
                    auth = await _read(db,
                        "SELECT * FROM signed_authorizations WHERE session_id=:eng "
                        "ORDER BY version DESC LIMIT 1", eng=action["engagement_id"])
                    policy = auth.get("canonical_policy")
                    if (session.get("created_by") != action["owner_id"]
                            or session.get("phase") in {"halted", "completed"}
                            or auth.get("status") != "active" or auth.get("revoked_at") is not None
                            or auth.get("version") != action["authorization_version"]
                            or auth.get("authorization_id") != action["authorization_id"]
                            or auth.get("policy_sha256") != action["authorization_sha256"]
                            or type(policy) is not dict
                            or not _policy_binding_matches(policy, action["engagement_id"],
                                                           session["scope"], session["roe"], session["created_by"])
                            or hashlib.sha256(_canonical_limited(policy)).hexdigest() != auth["policy_sha256"]):
                        _deny()
                    _verify_persisted_signature(policy, auth["signature"], auth["kid"])
                    verify_signed_roe(
                        {"version": auth["version"], "policy": policy, "signature": auth["signature"]},
                        expected_engagement_id=action["engagement_id"],
                        expected_owner=action["owner_id"],
                        expected_scope=session["scope"], expected_roe=session["roe"],
                        now=datetime.now(timezone.utc))
                    _validated_policy_window(policy)
                    scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
                    scope.validate_time_window()
                    validate_payload_targets(scope, original, require_target=True)
                    restrictions = {str(item).lower() for item in scope.scope.restrictions}
                    allowed = {str(item).lower() for item in scope.scope.allowed_techniques}
                    if (session["roe"].get("allow_active_scanning") is False
                            or restrictions.intersection({
                                "no_active_scanning", "passive_only", "no_scans",
                                "no_intrusive_scanning", "no_side_effects", "no_exploitation",
                            }) or (allowed and not allowed.intersection({
                                "execute", "browser-mcp.execute", "active_scanning",
                                "automated_scanning",
                            }))):
                        _deny()
                    flow = await _read(db,
                        "SELECT engagement_id,revision,status FROM execution_flows WHERE id=:flow",
                        flow=action["flow_id"])
                    if (flow.get("engagement_id") != action["engagement_id"]
                            or flow.get("revision") != action["flow_revision"]
                            or flow.get("status") not in {"pending", "running"}):
                        _deny()
                    task = await _read(db,
                        "SELECT * FROM tasks WHERE id=:task AND engagement_id=:eng",
                        task=action["task_id"], eng=action["engagement_id"])
                    subtask = await _read(db,
                        "SELECT * FROM execution_subtasks WHERE id=:step AND engagement_id=:eng",
                        step=action["subtask_id"], eng=action["engagement_id"])
                    payload = task.get("payload")
                    if (type(payload) is not dict or task.get("flow_id") != action["flow_id"]
                            or task.get("subtask_id") != action["subtask_id"]
                            or task.get("status") != "running"
                            or type(task.get("assigned_agent_id")) is not str
                            or not task["assigned_agent_id"]
                            or not isinstance(task.get("started_at"), datetime)
                            or task.get("completed_at") is not None
                            or task.get("scope_check") is not True
                            or task.get("approval_required") is not True
                            or payload.get("mcp_action_id") != action["action_id"]
                            or payload.get("_authorization_version") != action["authorization_version"]
                            or payload.get("mcp_flow_revision") != action["flow_revision"]
                            or payload.get("mcp_server_id") != "browser-mcp"
                            or payload.get("mcp_tool_name") != "execute"
                            or payload.get("mcp_parameters_sha256") != action["parameters_sha256"]
                            or payload.get("mcp_declaration_sha256") != action["declaration_sha256"]
                            or payload.get("operator_approved") is not True
                            or payload.get("approval_id") != action["approval_id"]
                            or subtask.get("execution_task_id") != action["task_id"]
                            or subtask.get("flow_id") != action["flow_id"]
                            or subtask.get("status") not in {"running", "dispatched"}
                            or subtask.get("approval_required") is not True
                            or subtask.get("task_type") == "operator_mcp_capability_review"):
                        _deny()
                    approval = await _read(db,
                        "SELECT * FROM approval_requests WHERE id=:approval AND engagement_id=:eng "
                        "AND task_id=:task", approval=action["approval_id"],
                        eng=action["engagement_id"], task=action["task_id"])
                    if (approval.get("status") != "approved"
                            or approval.get("action_type") != task.get("type")
                            or approval.get("target") != original["url"]
                            or approval.get("responded_at") is None
                            or not matches_pinned_payload(approval.get("evidence"), payload)
                            or approval.get("operator_id") in {None, action["owner_id"]}):
                        _deny()
                    for principal in (action["owner_id"], approval["operator_id"]):
                        control = await _read(db,
                            "SELECT disabled FROM operator_subject_controls WHERE actor_id=:actor",
                            actor=principal)
                        if control.get("disabled") is not False:
                            _deny()
                    lease = await _read(db,
                        "SELECT lease_id,owner_id,state,expires_at FROM supervision_execution_leases "
                        "WHERE task_id=:task AND engagement_id=:eng",
                        task=action["task_id"], eng=action["engagement_id"])
                    if (lease.get("lease_id") != action["lease_id"]
                            or lease.get("owner_id") != action["lease_owner_id"]
                            or lease.get("state") != "dispatched"
                            or not isinstance(lease.get("expires_at"), datetime)
                            or lease["expires_at"].replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)):
                        _deny()
                    checked = int(time.time())
                    if checked < now or checked > now + 2:
                        _deny()
                    claims = {
                        "version": 1,
                        "check_id": "bca-" + uuid.uuid4().hex,
                        **{name: source[name] for name in (
                            "request_id", "engagement_id", "flow_id", "task_id", "subtask_id",
                            "action_id", "owner_id", "preflight_id", "authorization_sha256",
                            "url_sha256", "origin")},
                        "original_intent_sha256": action["intent_sha256"],
                        "source_claims_sha256": issued["claims_sha256"],
                        "evidence_attestation_sha256": hashlib.sha256(
                            _canonical_limited(provider_evidence)).hexdigest(),
                        "checked_at": checked,
                        "expires_at": checked + 5,
                        "authority_current": True,
                        "artifact_bytes_verified": False,
                        "target_effect_verified": False,
                        "purpose": "current_authority_readback_only",
                    }
            return {"claims": claims, "kid": kid, "signature": base64.urlsafe_b64encode(
                signer.sign(CURRENT_DOMAIN + _canonical_limited(claims))
            ).decode("ascii").rstrip("=")}
        except BrowserCurrentAuthorityDenied:
            raise
        except Exception as exc:
            raise BrowserCurrentAuthorityDenied("Central Browser readback UNKNOWN") from exc
