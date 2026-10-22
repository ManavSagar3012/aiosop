"""Single-use central native MCP grant for the inert authority_status builtin.

Issuance follows original 0027 mark_dispatched and redemption occurs before
the native handler. Both transitions recheck original PostgreSQL source truth.
No network, target operation or handler is implemented here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text

from ai_osop.core.config import settings
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
    _ACTION,
    _NAME,
    _SHA,
    _SUBJECT,
    _binding,
    _id,
    _safe_parameters,
)
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

DOMAIN = b"ai-osop/native-grant/v1\x00"
# Separately authenticated supervisor testimony. Never accept a Go worker
# self-report or a duplicated service bearer as a substitute for this proof.
# The mounted native HTTP ingress does NOT presently transport this proof:
# staged grants intentionally fail closed there until a genuine independent
# supervisor transport is implemented.
SUPERVISOR_REDEEM_DOMAIN = b"ai-osop/native-grant-worker-redemption/v1\x00"
_SUPERVISOR_REDEEM_FIELDS = frozenset(
    {
        "version",
        "grant_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "worker_id",
        "container_id",
        "supervisor_id",
        "epoch",
        "revision",
        "approval_id",
        "lease_id",
        "authorization_sha256",
        "claims_sha256",
        "resource_sha256",
        "nonce",
        "issued_at",
        "expires_at",
    }
)
_WORKER_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,95}\Z")
_CONTAINER_ID = re.compile(r"[a-f0-9]{64}\Z")
_NONCE = re.compile(r"[a-f0-9]{32}\Z")
_GRANT = re.compile(r"ngr-[0-9a-f]{32}\Z")
# Match the public FastAPI native issuer verifier, not only the local signer.
# Otherwise the database can durably issue a capability that redemption rejects.
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_REQUEST = re.compile(r"req-[0-9a-f]{48}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_CLAIMS = frozenset(
    (
        "version",
        "grant_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "server_id",
        "tool_name",
        "parameters_sha256",
        "manifest_sha256",
        "authorization_version",
        "authorization_sha256",
        "lease_id",
        "resource_sha256",
        "issued_at",
        "expires_at",
        "side_effect_class",
    )
)
_ORIGINAL_FIELDS = (
    "action_id",
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "owner_id",
    "flow_revision",
    "authorization_id",
    "authorization_version",
    "authorization_sha256",
    "approval_id",
    "lease_id",
    "lease_owner_id",
    "server_id",
    "tool_name",
    "side_effect_class",
    "parameters_sha256",
    "intent_sha256",
)
_NATIVE_BUILTIN = {
    "name": "authority_status",
    "description": "Inert native authority redemption status; no target, scan or provider execution.",
    "parameters": [],
    "returns": {"status": "string"},
    "timeout_seconds": 5,
    "requires_approval": True,
    "scope_check": True,
    "side_effect_class": "READ_ONLY",
}

# 0036 expands ONLY the database representation; it does not enable a native
# SourceMap issuer, reviewed original-byte offering or independent host stage.
# A 0035 SourceMap preflight cannot substitute for a one-use 0029 grant/0030
# offer/0033 supervised worker. Keep the six existing Go status services intact
# and deny every other pair at the original PostgreSQL source boundary.
_ADMITTED_INERT_SERVERS = frozenset(
    {
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
    }
)


class NativeMCPGrantDenied(MCPActionDenied):
    """Redacted failure at central grant boundary."""


def _deny(code: int = 409, message: str = "Native MCP grant unavailable") -> None:
    raise NativeMCPGrantDenied(code, message)


def _require_operational_pair(server_id: Any, tool_name: Any, effect: Any) -> None:
    """Enforce deployable 0029 behavior, which is intentionally narrower than 0036.

    SourceMap's signed original SHA/metadata permit uses an independently
    approved `resource_*` Task source. This grant store/0030 offering instead
    requires `mcp_resource_sha256` and a separately admitted native worker
    stage. Until a coordinated SourceMap offer/supervisor implementation exists,
    even a valid original 0027/0035 SourceMap Action MUST NOT mint a grant.
    """
    if server_id == "source-map-mcp":
        _deny(409, "SourceMap native grant requires independent original resource offering")
    if (
        type(server_id) is not str
        or server_id not in _ADMITTED_INERT_SERVERS
        or tool_name != "authority_status"
        or effect != "READ_ONLY"
    ):
        _deny(403, "Native grant server and tool pair is not operationally admitted")


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise NativeMCPGrantDenied(403, "Invalid canonical native grant") from exc
    if len(raw) > 4096:
        _deny(403, "Native grant exceeds bounds")
    return raw


def _native_manifest_sha256(server_id: str) -> str:
    """Match Go's AuthorityStatusManifestSHA256ForServer and original 0027."""
    _id(server_id, _NAME)
    declaration = {**_NATIVE_BUILTIN, "required_permissions": [], "version": "1.0.0"}
    return hashlib.sha256(
        _canonical({"server_id": server_id, "declaration": declaration})
    ).hexdigest()


def _decode64(value: Any, size: int) -> bytes:
    if type(value) is not str or len(value) > 256:
        _deny(403, "Invalid native grant credential encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NativeMCPGrantDenied(403, "Invalid native grant credential") from exc
    if len(raw) != size:
        _deny(403, "Invalid native grant key size")
    return raw


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _signature(value: Any) -> bytes:
    if type(value) is not str or _SIGNATURE.fullmatch(value) is None:
        _deny(403, "Invalid native grant signature")
    try:
        raw = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NativeMCPGrantDenied(403, "Invalid native grant signature") from exc
    if len(raw) != 64 or _b64url(raw) != value:
        _deny(403, "Noncanonical native grant signature")
    return raw


def _signers() -> tuple[str, dict[str, Ed25519PrivateKey]]:
    try:
        active = os.environ["OSOP_NATIVE_MCP_GRANT_ACTIVE_KID"]
        config = json.loads(os.environ["OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON"])
        if (
            type(config) is not dict
            or not 1 <= len(config) <= 8
            or type(active) is not str
            or _KID.fullmatch(active) is None
            or active not in config
        ):
            _deny(503, "Native grant signing authority unavailable")
        keys = {}
        for kid, encoded in config.items():
            if type(kid) is not str or _KID.fullmatch(kid) is None:
                _deny(503, "Native grant signing authority unavailable")
            keys[kid] = Ed25519PrivateKey.from_private_bytes(_decode64(encoded, 32))
        return active, keys
    except (KeyError, TypeError, ValueError, NativeMCPGrantDenied) as exc:
        raise NativeMCPGrantDenied(503, "Native grant signing authority unavailable") from exc


def _authenticate_server(server_id: Any, secret: Any) -> None:
    _id(server_id, _NAME)
    if type(secret) is not str or not 20 <= len(secret) <= 512:
        _deny(403, "Independent native server credential required")
    try:
        configured = json.loads(os.environ["OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON"])
    except (KeyError, ValueError, TypeError) as exc:
        raise NativeMCPGrantDenied(503, "Native server trust configuration unavailable") from exc
    if type(configured) is not dict or not 1 <= len(configured) <= 32:
        _deny(503, "Native server trust configuration unavailable")
    expected = configured.get(server_id)
    if (
        type(expected) is not str
        or not 20 <= len(expected) <= 512
        or not hmac.compare_digest(
            hashlib.sha256(secret.encode("utf-8")).digest(),
            hashlib.sha256(expected.encode("utf-8")).digest(),
        )
    ):
        _deny(403, "Native server credential rejected")


def _validate_claims(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _CLAIMS:
        _deny(403, "Native grant claim set differs")
    if type(value["version"]) is not int or value["version"] != 1:
        _deny(403, "Unsupported native grant version")
    _id(value["grant_id"], _GRANT)
    _id(value["request_id"], _REQUEST)
    for field, prefix in (
        ("engagement_id", "eng-"),
        ("flow_id", "flow-"),
        ("task_id", "task-"),
        ("subtask_id", "subtask-"),
        ("lease_id", "lease-"),
    ):
        if not _id(value[field]).startswith(prefix):
            _deny(403, "Native grant identifier family mismatch")
    _id(value["action_id"], _ACTION)
    _id(value["server_id"], _NAME)
    if value["tool_name"] != "authority_status" or value["side_effect_class"] != "READ_ONLY":
        _deny(403, "Native grant cannot authorize this tool")
    for field in ("parameters_sha256", "manifest_sha256", "authorization_sha256"):
        _id(value[field], _SHA)
    if value["parameters_sha256"] != hashlib.sha256(b"{}").hexdigest() or value[
        "manifest_sha256"
    ] != _native_manifest_sha256(value["server_id"]):
        _deny(403, "Go native builtin parameters or manifest changed")
    if value["resource_sha256"] is not None:
        _id(value["resource_sha256"], _SHA)
    if (
        type(value["authorization_version"]) is not int
        or value["authorization_version"] < 1
        or type(value["issued_at"]) is not int
        or type(value["expires_at"]) is not int
        or not 0 < value["expires_at"] - value["issued_at"] <= 60
    ):
        _deny(403, "Native grant expiry or authorization version invalid")
    _canonical(value)
    return value


def _verify(token: Any) -> tuple[dict[str, Any], str, str, str]:
    if type(token) is not dict or set(token) != {"claims", "kid", "signature"}:
        _deny(403, "Complete native grant token required")
    claims = _validate_claims(token["claims"])
    # Historical 0029 claim syntax was broader than 0036's exact server/tool
    # table pairing. Never interpret a syntactically valid signed token from
    # an unsupported pair as executable authority (including native resources
    # and 0033 supervisor paths which call this verifier independently).
    _require_operational_pair(claims["server_id"], claims["tool_name"], claims["side_effect_class"])
    kid = _id(token["kid"], _KID)
    signature = _signature(token["signature"])
    _, signers = _signers()
    signer = signers.get(kid)
    if signer is None:
        _deny(403, "Native grant signing key is no longer trusted")
    try:
        signer.public_key().verify(signature, DOMAIN + _canonical(claims))
    except InvalidSignature as exc:
        raise NativeMCPGrantDenied(403, "Native grant signature rejected") from exc
    return (
        claims,
        kid,
        hashlib.sha256(_canonical(claims)).hexdigest(),
        hashlib.sha256(signature).hexdigest(),
    )


def _supervisor_public_key(supervisor_id: str, kid: str) -> Ed25519PublicKey:
    """Read independently configured 0033 supervisor trust, not Go credentials.

    The supervisor's separate authentication secret is used by 0033.record;
    this proof verifier requires custody of its *Ed25519 private key*. A native
    worker provisioned only with per-service bearer and issuer public keys
    cannot mint the proof. No operator/provider-supplied trust roots accepted.
    """
    if (
        type(supervisor_id) is not str
        or _WORKER_ID.fullmatch(supervisor_id) is None
        or type(kid) is not str
        or _KID.fullmatch(kid) is None
    ):
        _deny(403, "Independent worker supervisor identity invalid")
    try:
        raw = os.environ["OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"]
        if not 2 <= len(raw) <= 8192:
            raise ValueError()
        registry = json.loads(raw)
        if type(registry) is not dict or not 1 <= len(registry) <= 8:
            raise ValueError()
        trusted = registry[supervisor_id]
        if type(trusted) is not dict or set(trusted) != {"kid", "public_key", "secret_sha256"}:
            raise ValueError()
        if trusted["kid"] != kid or not _SHA.fullmatch(trusted["secret_sha256"]):
            raise ValueError()
        encoded = trusted["public_key"]
        if type(encoded) is not str or len(encoded) != 43:
            raise ValueError()
        public = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
        if len(public) != 32 or _b64url(public) != encoded:
            raise ValueError()
        # A grant issuer cannot impersonate its independently configured
        # supervisor, even if maliciously provisioned under a different KID.
        _, issuers = _signers()
        if any(
            hmac.compare_digest(
                public, signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            )
            for signer in issuers.values()
        ):
            raise ValueError()
        return Ed25519PublicKey.from_public_bytes(public)
    except (KeyError, ValueError, TypeError, AttributeError, base64.binascii.Error):
        _deny(503, "Independent 0033 supervisor trust unavailable")


def _supervisor_redeem_proof(
    proof: Any, supervisor: Mapping[str, Any], grant: Mapping[str, Any], now: int
) -> None:
    """Verify strict, one-grant, time-bounded, independently signed proof.

    The 0033 durable source is locked independently by the caller; the proof
    binds a freshly observed container to its globally fenced epoch/revision.
    Merely knowing/copying an 0029 service bearer cannot satisfy this boundary.
    """
    if (
        type(proof) is not dict
        or set(proof) != {"claims", "kid", "signature"}
        or type(proof["claims"]) is not dict
        or set(proof["claims"]) != _SUPERVISOR_REDEEM_FIELDS
    ):
        _deny(403, "Separate signed worker redemption proof is required")
    claims = proof["claims"]
    for field, expected in (
        ("version", 1),
        ("grant_id", grant["grant_id"]),
        ("request_id", grant["request_id"]),
        ("engagement_id", grant["engagement_id"]),
        ("flow_id", grant["flow_id"]),
        ("task_id", grant["task_id"]),
        ("subtask_id", grant["subtask_id"]),
        ("action_id", grant["action_id"]),
        ("owner_id", grant["owner_id"]),
        ("server_id", grant["server_id"]),
        ("worker_id", supervisor["worker_id"]),
        ("supervisor_id", supervisor["supervisor_id"]),
        ("epoch", supervisor["epoch"]),
        ("revision", supervisor["revision"]),
        ("approval_id", grant["approval_id"]),
        ("lease_id", grant["lease_id"]),
        ("authorization_sha256", grant["authorization_sha256"]),
        ("claims_sha256", grant["claims_sha256"]),
        ("resource_sha256", grant["resource_sha256"]),
    ):
        if type(claims.get(field)) is not type(expected) or claims[field] != expected:
            _deny(403, "Supervisor worker source or revision mismatch")
    if (
        type(claims["container_id"]) is not str
        or _CONTAINER_ID.fullmatch(claims["container_id"]) is None
        or claims["container_id"] != supervisor.get("container_id")
        or type(claims["nonce"]) is not str
        or _NONCE.fullmatch(claims["nonce"]) is None
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not now - 5 <= claims["issued_at"] <= now
        or not now < claims["expires_at"] <= claims["issued_at"] + 10
        or claims["expires_at"] > grant["expires_at"]
        or proof["kid"] != supervisor["supervisor_kid"]
    ):
        _deny(403, "Supervisor container proof absent, expired or untrusted")
    public = _supervisor_public_key(supervisor["supervisor_id"], proof["kid"])
    signature = _signature(proof["signature"])
    try:
        public.verify(signature, SUPERVISOR_REDEEM_DOMAIN + _canonical(claims))
    except InvalidSignature as exc:
        raise NativeMCPGrantDenied(403, "Independent worker proof signature rejected") from exc


class NativeMCPExecutionGrantStore:
    """PostgreSQL source of truth for native one-time execution permission."""

    def __init__(self, action_store: FlowMCPActionStore) -> None:
        if not isinstance(action_store, FlowMCPActionStore):
            _deny(503, "Production original MCP Action store required")
        self.actions = action_store

    @staticmethod
    async def _now(db: Any) -> int:
        value = (
            await db.execute(text("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint"))
        ).scalar_one()
        if type(value) is not int or value <= 0:
            _deny(503, "Independent PostgreSQL grant clock unavailable")
        return value

    @staticmethod
    async def _original(db: Any, action_id: str) -> dict[str, Any]:
        row = await FlowMCPActionStore._row(db, action_id, lock=True)
        if (
            row is None
            or row.get("status") != "unknown"
            or row.get("cancel_requested") is not False
            or row.get("tool_name") != "authority_status"
            or row.get("side_effect_class") != "READ_ONLY"
        ):
            if (
                row is not None
                and row.get("status") == "unknown"
                and row.get("cancel_requested") is False
                and row.get("server_id") == "source-map-mcp"
            ):
                _require_operational_pair(
                    row["server_id"], row["tool_name"], row["side_effect_class"]
                )
            _deny(409, "Original committed native dispatch is unavailable")
        _require_operational_pair(
            row.get("server_id"), row.get("tool_name"), row.get("side_effect_class")
        )
        event = (
            await db.execute(
                text(
                    "SELECT 1 FROM flow_mcp_action_dispatch_events "
                    "WHERE action_id=:action AND engagement_id=:eng AND flow_id=:flow "
                    "AND kind='dispatch_attempted' AND status='unknown' "
                    "AND intent_sha256=:intent LIMIT 1 FOR SHARE"
                ),
                {
                    "action": action_id,
                    "eng": row["engagement_id"],
                    "flow": row["flow_id"],
                    "intent": row["intent_sha256"],
                },
            )
        ).scalar_one_or_none()
        if event != 1:
            _deny(409, "Original durable dispatch event not recorded")
        return row

    async def _source(
        self, db: Any, binding: dict[str, Any], owner: str, action_id: str
    ) -> dict[str, Any]:
        session = await self.actions._authority(db, binding, owner, dispatch=True)
        row = await self._original(db, action_id)
        self.actions._same(row, binding, owner)
        declaration = self.actions._declaration(row["server_id"], row["tool_name"])
        if (
            declaration.side_effect_class is not SideEffectClass.READ_ONLY
            or declaration.model_dump(mode="json", exclude={"version", "required_permissions"})
            != _NATIVE_BUILTIN
            or declaration.version != "1.0.0"
            or declaration.required_permissions != []
            or self.actions.declaration_sha256(declaration, row["server_id"])
            != row["declaration_sha256"]
        ):
            _deny(409, "Native MCP declaration changed")
        parameters = _safe_parameters(row["safe_parameters"], declaration)
        if self.actions.parameters_sha256(parameters) != row["parameters_sha256"]:
            _deny(409, "Native MCP parameters changed")
        scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
        scope.validate_time_window()
        validate_payload_targets(scope, parameters, require_target=False)
        approved = await self.actions._approved_task(
            db,
            binding,
            owner,
            row["task_id"],
            row["subtask_id"],
            row["server_id"],
            row["tool_name"],
            row["declaration_sha256"],
            row["parameters_sha256"],
            "READ_ONLY",
            scope,
        )
        if any(
            approved.get(k) != row[k]
            for k in ("action_id", "approval_id", "lease_id", "lease_owner_id")
        ):
            _deny(409, "Independent Task approval or live lease changed")
        return row

    @staticmethod
    async def _resources(db: Any, row: Mapping[str, Any], digest: Optional[str]) -> None:
        # This helper is also invoked by resource offering and stage receipt
        # paths. A null generic digest must never let a SourceMap Action skip
        # its different original artifact/manifest/stage requirements.
        _require_operational_pair(
            row.get("server_id"), row.get("tool_name"), row.get("side_effect_class")
        )
        # A null resource digest means the inert authority_status consumes none.
        if digest is None:
            return
        _id(digest, _SHA)
        # This digest must be part of the original, independently human-approved
        # full Task payload. Calling issue cannot add a resource after review.
        source_task = (
            (
                await db.execute(
                    text(
                        "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:eng "
                        "AND flow_id=:flow FOR SHARE"
                    ),
                    {
                        "task": row["task_id"],
                        "eng": row["engagement_id"],
                        "flow": row["flow_id"],
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            source_task is None
            or not isinstance(source_task.get("payload"), dict)
            or source_task["payload"].get("mcp_resource_sha256") != digest
        ):
            _deny(409, "Resource digest missing from independently approved Task")
        from ai_osop.memory.flow_resource_exports import MAX_EXPORT_FILES, make_manifest

        artifacts = (
            (
                await db.execute(
                    text(
                        "SELECT id,flow_id,name,size_bytes,sha256,flow_revision,"
                        "authorization_version,authorization_sha256,content "
                        "FROM flow_artifacts WHERE engagement_id=:eng AND flow_id=:flow "
                        "AND owner_id=:owner ORDER BY created_at,id LIMIT :limit FOR SHARE"
                    ),
                    {
                        "eng": row["engagement_id"],
                        "flow": row["flow_id"],
                        "owner": row["owner_id"],
                        "limit": MAX_EXPORT_FILES + 1,
                    },
                )
            )
            .mappings()
            .all()
        )
        if not artifacts or len(artifacts) > MAX_EXPORT_FILES:
            _deny(409, "Immutable resource manifest unavailable")
        verified = []
        for item in artifacts:
            data = dict(item)
            if (
                data["flow_id"] != row["flow_id"]
                or data["flow_revision"] != row["flow_revision"]
                or data["authorization_version"] != row["authorization_version"]
                or data["authorization_sha256"] != row["authorization_sha256"]
                or not isinstance(data["content"], bytes)
            ):
                _deny(409, "Original Flow resource lineage changed")
            review = (
                (
                    await db.execute(
                        text(
                            "SELECT uploader_sub,reviewer_sub,reviewer_role,decision,"
                            "artifact_sha256,flow_revision,authorization_id,"
                            "authorization_version,authorization_sha256 "
                            "FROM flow_artifact_reviews WHERE artifact_id=:id "
                            "AND engagement_id=:eng AND flow_id=:flow FOR SHARE"
                        ),
                        {"id": data["id"], "eng": row["engagement_id"], "flow": row["flow_id"]},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                review is None
                or review["decision"] != "approve"
                or review["reviewer_role"] != "senior_operator"
                or review["uploader_sub"] != row["owner_id"]
                or review["reviewer_sub"] == row["owner_id"]
                or review["artifact_sha256"] != data["sha256"]
                or review["flow_revision"] != row["flow_revision"]
                or review["authorization_version"] != row["authorization_version"]
                or review["authorization_id"] != row["authorization_id"]
                or review["authorization_sha256"] != row["authorization_sha256"]
            ):
                _deny(409, "Independently reviewed Flow resource unavailable")
            reviewer = (
                (
                    await db.execute(
                        text(
                            "SELECT disabled FROM operator_subject_controls WHERE actor_id=:id FOR SHARE"
                        ),
                        {"id": review["reviewer_sub"]},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (reviewer is None and settings.operator_revocation_required) or (
                reviewer is not None and reviewer["disabled"] is not False
            ):
                _deny(409, "Resource reviewer no longer authorized")
            verified.append((data, data["content"]))
        current = make_manifest(
            row["flow_id"], row["flow_revision"], row["authorization_version"], verified
        )
        if not hmac.compare_digest(current["manifest_sha256"], digest):
            _deny(409, "Immutable reviewed resource digest changed")

    @staticmethod
    async def _grant(db: Any, grant_id: str, *, lock: bool) -> Optional[dict[str, Any]]:
        result = await db.execute(
            text(
                "SELECT * FROM native_mcp_execution_grants WHERE grant_id=:id "
                # The initial lookup is identity discovery only; taking FOR SHARE
                # there would deadlock concurrent redeemers acquiring original
                # Action FOR UPDATE before upgrading the grant row to FOR UPDATE.
                + ("FOR UPDATE" if lock else "")
            ),
            {"id": grant_id},
        )
        found = result.mappings().one_or_none()
        return dict(found) if found is not None else None

    @staticmethod
    async def _event(db: Any, row: Mapping[str, Any], kind: str) -> None:
        await db.execute(
            text(
                "INSERT INTO native_mcp_execution_grant_events "
                "(id,grant_id,engagement_id,flow_id,action_id,request_id,"
                "revision,kind,status,claims_sha256) VALUES "
                "(:id,:grant_id,:engagement_id,:flow_id,:action_id,:request_id,"
                ":revision,:kind,:status,:claims_sha256)"
            ),
            {
                "id": "evt-" + uuid.uuid4().hex,
                "kind": kind,
                **{
                    key: row[key]
                    for key in (
                        "grant_id",
                        "engagement_id",
                        "flow_id",
                        "action_id",
                        "request_id",
                        "revision",
                        "status",
                        "claims_sha256",
                    )
                },
            },
        )

    @staticmethod
    async def _supervised_staged_redeem(
        db: Any,
        grant: Mapping[str, Any],
        *,
        worker_proof: Any,
        now: int,
    ) -> None:
        """Inspect immutable 0033 supervisor admission under 0029 grant lock.

        0033 is first provisioned AFTER grant issuance but BEFORE execution.
        State 'running' is not valid yet: 0033 itself requires successful
        redemption before its running transition. No production bypass when
        0033 / per-container proof / independent trust are unavailable.
        """
        if worker_proof is None:
            _deny(403, "Staged native grant requires independent worker proof")
        supervisor_result = await db.execute(
            text("SELECT * FROM native_mcp_worker_supervisions " "WHERE grant_id=:grant FOR SHARE"),
            {"grant": grant["grant_id"]},
        )
        observed = supervisor_result.mappings().one_or_none()
        if observed is None:
            _deny(409, "Staged native grant lacks durable 0033 supervision")
        supervisor = dict(observed)
        for name in (
            "grant_id",
            "request_id",
            "engagement_id",
            "flow_id",
            "task_id",
            "subtask_id",
            "action_id",
            "owner_id",
            "server_id",
            "approval_id",
            "lease_id",
            "lease_owner_id",
            "flow_revision",
            "authorization_id",
            "authorization_version",
            "authorization_sha256",
            "claims_sha256",
            "resource_sha256",
        ):
            source = "grant_claims_sha256" if name == "claims_sha256" else name
            if type(supervisor.get(source)) is not type(grant.get(name)) or (
                supervisor[source] != grant[name]
            ):
                _deny(409, "Native worker 0033 tenant or original Task changed")
        if (
            supervisor.get("state") != "provisioned"
            or type(supervisor.get("container_id")) is not str
            or _CONTAINER_ID.fullmatch(supervisor["container_id"]) is None
            or type(supervisor.get("worker_id")) is not str
            or _WORKER_ID.fullmatch(supervisor["worker_id"]) is None
            or type(supervisor.get("epoch")) is not int
            or supervisor["epoch"] < 1
            or type(supervisor.get("revision")) is not int
            or supervisor["revision"] != 1
            or type(supervisor.get("supervisor_kid")) is not str
            or _KID.fullmatch(supervisor["supervisor_kid"]) is None
        ):
            _deny(409, "Native worker 0033 not in current initial provision")
        event = await db.execute(
            text(
                "SELECT 1 FROM native_mcp_worker_supervision_events "
                "WHERE grant_id=:grant AND epoch=:epoch AND revision=:revision "
                "AND state='provisioned' AND supervisor_id=:supervisor AND kid=:kid "
                "LIMIT 1 FOR SHARE"
            ),
            {
                "grant": grant["grant_id"],
                "epoch": supervisor["epoch"],
                "revision": supervisor["revision"],
                "supervisor": supervisor["supervisor_id"],
                "kid": supervisor["supervisor_kid"],
            },
        )
        if event.scalar_one_or_none() != 1:
            _deny(409, "Immutable 0033 supervisor source event unavailable")
        _supervisor_redeem_proof(worker_proof, supervisor, grant, now)

    @staticmethod
    def _same(grant: Mapping[str, Any], original: Mapping[str, Any]) -> None:
        if any(grant.get(key) != original.get(key) for key in _ORIGINAL_FIELDS) or grant.get(
            "manifest_sha256"
        ) != original.get("declaration_sha256"):
            _deny(409, "Original dispatch differs from native grant")

    @staticmethod
    def _signed(claims: Mapping[str, Any], grant: Mapping[str, Any]) -> None:
        if any(
            claims.get(key) != grant.get(key)
            for key in _CLAIMS - {"version", "grant_id", "issued_at", "expires_at"}
        ) or any(
            claims.get(key) != grant.get(key) for key in ("grant_id", "issued_at", "expires_at")
        ):
            _deny(403, "Native signed claim differs from committed grant")

    async def issue(
        self,
        binding: dict[str, Any],
        actor_id: str,
        action_id: str,
        request_id: str,
        *,
        resource_sha256: Optional[str] = None,
        ttl_seconds: int = 30,
    ) -> dict[str, Any]:
        b = _binding(binding)
        _id(actor_id, _SUBJECT)
        _id(action_id, _ACTION)
        _id(request_id, _REQUEST)
        if resource_sha256 is not None:
            _id(resource_sha256, _SHA)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 60:
            _deny(422, "Native grant lifetime exceeds limit")
        kid, keys = _signers()
        try:
            async with self.actions._sessions()() as db:
                async with db.begin():
                    original = await self._source(db, b, actor_id, action_id)
                    if original["request_id"] != request_id:
                        _deny(409, "Original native request changed")
                    await self._resources(db, original, resource_sha256)
                    issued = await self._now(db)
                    claims = _validate_claims(
                        {
                            "version": 1,
                            "grant_id": "ngr-" + uuid.uuid4().hex,
                            "request_id": original["request_id"],
                            "engagement_id": original["engagement_id"],
                            "flow_id": original["flow_id"],
                            "task_id": original["task_id"],
                            "subtask_id": original["subtask_id"],
                            "action_id": original["action_id"],
                            "server_id": original["server_id"],
                            "tool_name": original["tool_name"],
                            "parameters_sha256": original["parameters_sha256"],
                            "manifest_sha256": original["declaration_sha256"],
                            "authorization_version": original["authorization_version"],
                            "authorization_sha256": original["authorization_sha256"],
                            "lease_id": original["lease_id"],
                            "resource_sha256": resource_sha256,
                            "issued_at": issued,
                            "expires_at": issued + ttl_seconds,
                            "side_effect_class": "READ_ONLY",
                        }
                    )
                    signature = keys[kid].sign(DOMAIN + _canonical(claims))
                    stored = {
                        **{k: original[k] for k in _ORIGINAL_FIELDS},
                        "manifest_sha256": original["declaration_sha256"],
                        "grant_id": claims["grant_id"],
                        "resource_sha256": resource_sha256,
                        "kid": kid,
                        "claims_sha256": hashlib.sha256(_canonical(claims)).hexdigest(),
                        "signature_sha256": hashlib.sha256(signature).hexdigest(),
                        "issued_at": issued,
                        "expires_at": issued + ttl_seconds,
                        "status": "issued",
                        "revision": 1,
                    }
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_mcp_execution_grants ("
                                + ",".join(stored)
                                + ") VALUES ("
                                + ",".join(":" + k for k in stored)
                                + ") ON CONFLICT DO NOTHING RETURNING grant_id"
                            ),
                            stored,
                        )
                    ).scalar_one_or_none()
                    if inserted != stored["grant_id"]:
                        _deny(409, "Original native action already granted")
                    await self._event(db, stored, "issued")
                    token = {"claims": claims, "kid": kid, "signature": _b64url(signature)}
                    return {
                        "grant_id": claims["grant_id"],
                        "status": "issued",
                        "revision": 1,
                        "token": token,
                        "native_grant_header": _b64url(_canonical(token)),
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(503, "Durable native grant issue unavailable") from exc

    async def redeem(
        self,
        token: dict[str, Any],
        *,
        server_id: Optional[str] = None,
        server_secret: Optional[str] = None,
        worker_proof: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        # Native service authentication is mandatory even for an independently
        # signed grant. A copied short-lived capability by itself cannot be
        # redeemed from a browser, another MCP, or another service identity.
        if type(server_id) is not str or type(server_secret) is not str:
            _deny(403, "Independent native server identity required")
        _authenticate_server(server_id, server_secret)
        claims, kid, claims_hash, signature_hash = _verify(token)
        if claims["server_id"] != server_id:
            _deny(403, "Native server differs from signed grant")
        try:
            async with self.actions._sessions()() as db:
                async with db.begin():
                    observed = await self._grant(db, claims["grant_id"], lock=False)
                    if observed is None or observed["status"] != "issued":
                        _deny(409, "Native grant already consumed or unavailable")
                    self._signed(claims, observed)
                    if (
                        observed["kid"] != kid
                        or observed["claims_sha256"] != claims_hash
                        or observed["signature_sha256"] != signature_hash
                    ):
                        _deny(403, "Native grant signature changed after issue")
                    b = _binding(
                        {
                            "engagement_id": observed["engagement_id"],
                            "flow_id": observed["flow_id"],
                            "revision": observed["flow_revision"],
                            "version": observed["authorization_version"],
                            "authorization_id": observed["authorization_id"],
                            "authorization_sha256": observed["authorization_sha256"],
                        }
                    )
                    original = await self._source(
                        db, b, observed["owner_id"], observed["action_id"]
                    )
                    row = await self._grant(db, claims["grant_id"], lock=True)
                    if row is None or row["status"] != "issued":
                        _deny(409, "Native grant consumed concurrently")
                    self._same(row, original)
                    self._signed(claims, row)
                    if (
                        row["kid"] != kid
                        or row["claims_sha256"] != claims_hash
                        or row["signature_sha256"] != signature_hash
                    ):
                        _deny(403, "Native grant signer changed")
                    now = await self._now(db)
                    if now < row["issued_at"] or now >= row["expires_at"]:
                        _deny(409, "Native grant expired")
                    await self._resources(db, original, row["resource_sha256"])
                    if row["resource_sha256"] is not None:
                        # Prior inert no-resource 0029 flows remain one-shot.
                        # For resource-bound 0031/0032, a copied per-service
                        # bearer never authorizes the original bytes: demand
                        # both CURRENT durable 0033 source and an independent
                        # supervisor signature bound to this one worker.
                        # The current Go/API transport cannot supply this
                        # proof and therefore staged redemption is DENIED,
                        # never silently treated as a legacy inert call.
                        await self._supervised_staged_redeem(
                            db, row, worker_proof=worker_proof, now=now
                        )
                    next_revision = (
                        await db.execute(
                            text(
                                "UPDATE native_mcp_execution_grants SET status='redeemed',"
                                "revision=revision+1,updated_at=now() "
                                "WHERE grant_id=:id AND engagement_id=:eng AND action_id=:action "
                                "AND request_id=:request AND revision=:revision AND status='issued' "
                                "RETURNING revision"
                            ),
                            {
                                "id": row["grant_id"],
                                "eng": row["engagement_id"],
                                "action": row["action_id"],
                                "request": row["request_id"],
                                "revision": row["revision"],
                            },
                        )
                    ).scalar_one_or_none()
                    if next_revision != row["revision"] + 1:
                        _deny(409, "Native grant redemption race lost")
                    row.update(status="redeemed", revision=next_revision)
                    await self._event(db, row, "redeemed")
                    return {
                        "grant_id": row["grant_id"],
                        "request_id": row["request_id"],
                        "claim_sha256": claims_hash,
                        "durably_redeemed": True,
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(503, "Durable native grant redeem unavailable") from exc

    async def mark_unknown(
        self, binding: dict[str, Any], actor_id: str, grant_id: str
    ) -> dict[str, Any]:
        return await self._close(binding, actor_id, grant_id, "unknown")

    async def revoke(self, binding: dict[str, Any], actor_id: str, grant_id: str) -> dict[str, Any]:
        return await self._close(binding, actor_id, grant_id, "revoked")

    async def _close(
        self, binding: dict[str, Any], actor_id: str, grant_id: str, status: str
    ) -> dict[str, Any]:
        b = _binding(binding)
        _id(actor_id, _SUBJECT)
        _id(grant_id, _GRANT)
        try:
            async with self.actions._sessions()() as db:
                async with db.begin():
                    await self.actions._authority(db, b, actor_id, dispatch=True)
                    observed = await self._grant(db, grant_id, lock=False)
                    if observed is None or observed["owner_id"] != actor_id:
                        _deny(404, "Native grant is unavailable to signed owner")
                    original = await self._original(db, observed["action_id"])
                    self.actions._same(original, b, actor_id)
                    locked = await self._grant(db, grant_id, lock=True)
                    if locked is None:
                        _deny(409, "Native grant state unavailable")
                    self._same(locked, original)
                    if locked["status"] != "issued":
                        return {
                            "grant_id": grant_id,
                            "status": locked["status"],
                            "revision": locked["revision"],
                            "changed": False,
                        }
                    version = (
                        await db.execute(
                            text(
                                "UPDATE native_mcp_execution_grants SET status=:status,"
                                "revision=revision+1,updated_at=now() "
                                "WHERE grant_id=:id AND engagement_id=:eng "
                                "AND revision=:prior AND status='issued' RETURNING revision"
                            ),
                            {
                                "status": status,
                                "id": grant_id,
                                "eng": b["engagement_id"],
                                "prior": locked["revision"],
                            },
                        )
                    ).scalar_one_or_none()
                    if version != locked["revision"] + 1:
                        _deny(409, "Native grant closure race lost")
                    locked.update(status=status, revision=version)
                    await self._event(db, locked, status)
                    return {
                        "grant_id": grant_id,
                        "status": status,
                        "revision": version,
                        "changed": True,
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(503, "Durable native grant closure unavailable") from exc
