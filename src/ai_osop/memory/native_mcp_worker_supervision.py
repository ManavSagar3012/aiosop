"""PostgreSQL fenced, independently signed observations of native worker lives.

Only the dedicated container supervisor may attest a worker lifecycle. A native
worker's 0032 self-attestation is separate evidence. No method dispatches a
tool, retries an UNKNOWN Action, or proves an external target effect.

Lock order: original Action -> 0029 grant -> 0030 offer -> 0032 receipt ->
0033 supervisor row. Epochs come from one PostgreSQL non-cycling sequence.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, MCPActionDenied
from ai_osop.memory.flow_resource_exports import MAX_EXPORT_FILES, make_manifest
from ai_osop.memory.native_mcp_folder_stage import approved_folder_stage_plan
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPExecutionGrantStore,
    NativeMCPGrantDenied,
    _binding,
    _deny,
    _verify,
)

DOMAIN = b"ai-osop/native-worker-supervisor/v1\x00"
TRUST_ENV = "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,95}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_CONTAINER = re.compile(r"[a-f0-9]{64}\Z")
_STATES = frozenset({"provisioned", "running", "terminating", "terminated", "unknown", "reaped"})
_NEXT = {
    "provisioned": frozenset({"running", "terminating", "unknown"}),
    "running": frozenset({"terminating", "terminated", "unknown"}),
    "terminating": frozenset({"terminated", "unknown"}),
    "unknown": frozenset({"terminating", "terminated", "reaped"}),
    "terminated": frozenset({"reaped"}),
    "reaped": frozenset(),
}
_FIELDS = frozenset(
    {
        "version",
        "grant_id",
        "request_id",
        "server_id",
        "worker_id",
        "container_id",
        "epoch",
        "expected_revision",
        "state",
        "observed_at",
        "evidence_sha256",
        "resource_sha256",
        "folder_staging_sha256",
        "readback_sha256",
    }
)
_SOURCE = (
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
    "resource_sha256",
)


def _canonical(obj: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise NativeMCPGrantDenied(403, "Malformed supervisor observation") from exc
    if len(raw) > 3072:
        _deny(403, "Supervisor observation exceeds bounds")
    return raw


def _decode(value: Any, size: int) -> bytes:
    if type(value) is not str or len(value) != (43 if size == 32 else 86):
        _deny(403, "Noncanonical supervisor credential")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NativeMCPGrantDenied(403, "Malformed supervisor credential") from exc
    if len(raw) != size or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        _deny(403, "Noncanonical supervisor credential")
    return raw


def _supervisor_key(supervisor_id: str, secret: str, kid: str) -> Ed25519PublicKey:
    if (
        type(supervisor_id) is not str
        or _ID.fullmatch(supervisor_id) is None
        or type(secret) is not str
        or not 20 <= len(secret) <= 512
        or type(kid) is not str
        or _KID.fullmatch(kid) is None
    ):
        _deny(403, "Dedicated supervisor identity is required")
    raw_config = os.getenv(TRUST_ENV, "")
    if not 1 <= len(raw_config) <= 8192:
        _deny(503, "Dedicated native worker supervisor trust unavailable")
    try:
        config = json.loads(raw_config)
        if type(config) is not dict or not 1 <= len(config) <= 8:
            raise ValueError("Supervisor trust map invalid")
        trusted = config.get(supervisor_id)
        if type(trusted) is not dict or set(trusted) != {"kid", "public_key", "secret_sha256"}:
            raise ValueError("Supervisor not registered")
        if (
            trusted["kid"] != kid
            or type(trusted["secret_sha256"]) is not str
            or _SHA.fullmatch(trusted["secret_sha256"]) is None
        ):
            raise ValueError("Supervisor signer rotated")
        actual_secret = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual_secret, trusted["secret_sha256"]):
            _deny(403, "Supervisor authentication rejected")
        public = _decode(trusted["public_key"], 32)
        # A worker's own stage attestation key must never become its external
        # supervisor. This is a *separate* observation trust boundary.
        worker_trust = os.getenv("OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON", "")
        if worker_trust:
            workers = json.loads(worker_trust)
            if type(workers) is not dict:
                raise ValueError("Worker trust invalid")
            for worker in workers.values():
                if type(worker) is dict and worker.get("public_key") == trusted["public_key"]:
                    raise ValueError("Worker cannot sign supervisor observations")
        grant_signing = os.getenv("OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON", "")
        if grant_signing:
            signers = json.loads(grant_signing)
            if type(signers) is not dict or len(signers) > 8:
                raise ValueError("Grant trust invalid")
            for seed in signers.values():
                if type(seed) is not str:
                    raise ValueError("Grant signer key malformed")
                key_bytes = base64.b64decode(seed, validate=True)
                if len(key_bytes) != 32:
                    raise ValueError("Grant signer key malformed")
                issuer_public = (
                    Ed25519PrivateKey.from_private_bytes(key_bytes).public_key().public_bytes_raw()
                )
                if hmac.compare_digest(public, issuer_public):
                    raise ValueError("Issuer key cannot sign supervisor observations")
        return Ed25519PublicKey.from_public_bytes(public)
    except NativeMCPGrantDenied:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, base64.binascii.Error) as exc:
        raise NativeMCPGrantDenied(
            503, "Dedicated native worker supervisor trust unavailable"
        ) from exc


def _verify_observation(
    observation: dict[str, Any], supervisor_id: str, secret: str
) -> tuple[dict[str, Any], str, str, str]:
    if (
        type(observation) is not dict
        or set(observation) != {"claims", "kid", "signature"}
        or type(observation["claims"]) is not dict
        or set(observation["claims"]) != _FIELDS
    ):
        _deny(403, "Complete signed supervisor observation required")
    claims = observation["claims"]
    if (
        type(claims["version"]) is not int
        or claims["version"] != 1
        or type(claims["grant_id"]) is not str
        or re.fullmatch(r"ngr-[a-f0-9]{32}", claims["grant_id"]) is None
        or type(claims["request_id"]) is not str
        or re.fullmatch(r"req-[a-f0-9]{48}", claims["request_id"]) is None
        or type(claims["server_id"]) is not str
        or _ID.fullmatch(claims["server_id"]) is None
        or type(claims["worker_id"]) is not str
        or _ID.fullmatch(claims["worker_id"]) is None
        or type(claims["state"]) is not str
        or claims["state"] not in _STATES
        or type(claims["epoch"]) is not int
        or not 0 <= claims["epoch"] < 2**63
        or type(claims["expected_revision"]) is not int
        or not 0 <= claims["expected_revision"] < 2**31 - 1
        or type(claims["observed_at"]) is not int
        or claims["observed_at"] <= 0
        or type(claims["evidence_sha256"]) is not str
        or _SHA.fullmatch(claims["evidence_sha256"]) is None
        or (
            claims["container_id"] is not None
            and (
                type(claims["container_id"]) is not str
                or _CONTAINER.fullmatch(claims["container_id"]) is None
            )
        )
        or any(
            value is not None and (type(value) is not str or _SHA.fullmatch(value) is None)
            for value in (
                claims["resource_sha256"],
                claims["folder_staging_sha256"],
                claims["readback_sha256"],
            )
        )
    ):
        _deny(403, "Invalid supervisor observation identity or state")
    if claims["state"] == "provisioned" and (
        claims["epoch"] != 0 or claims["expected_revision"] != 0
    ):
        _deny(403, "Initial supervisor epoch and revision must be unallocated")
    if claims["state"] != "provisioned" and (
        claims["epoch"] == 0 or claims["expected_revision"] == 0
    ):
        _deny(403, "Worker epoch and revision must be current")
    if claims["state"] in {"running", "terminated"} and claims["container_id"] is None:
        _deny(403, "Container identity was not observed")
    raw = _canonical(claims)
    signature = _decode(observation["signature"], 64)
    public = _supervisor_key(supervisor_id, secret, observation["kid"])
    try:
        public.verify(signature, DOMAIN + raw)
    except InvalidSignature as exc:
        raise NativeMCPGrantDenied(403, "Independent supervisor signature rejected") from exc
    return (
        claims,
        observation["kid"],
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(signature).hexdigest(),
    )


class NativeMCPWorkerSupervisionStore:
    """Only durable signed observations from a dedicated external supervisor."""

    def __init__(self, action_store: FlowMCPActionStore) -> None:
        if not isinstance(action_store, FlowMCPActionStore):
            _deny(503, "Original PostgreSQL MCP Action source required")
        self.grants = NativeMCPExecutionGrantStore(action_store)

    @staticmethod
    async def _current_folder(db: Any, grant: Mapping[str, Any]) -> Optional[str]:
        """Reread live 0026 approved Task catalog and SHA-verified 0013 bytes."""
        if grant["resource_sha256"] is None:
            return None
        snapshot = (
            (
                await db.execute(
                    text(
                        "SELECT id,flow_id,name,size_bytes,sha256,flow_revision,"
                        "authorization_version,authorization_sha256,content FROM flow_artifacts "
                        "WHERE engagement_id=:eng AND flow_id=:flow AND owner_id=:owner "
                        "ORDER BY created_at,id LIMIT :limit FOR SHARE"
                    ),
                    {
                        "eng": grant["engagement_id"],
                        "flow": grant["flow_id"],
                        "owner": grant["owner_id"],
                        "limit": MAX_EXPORT_FILES + 1,
                    },
                )
            )
            .mappings()
            .all()
        )
        if not 1 <= len(snapshot) <= MAX_EXPORT_FILES:
            _deny(409, "Current original worker resources unavailable")
        manifest = make_manifest(
            grant["flow_id"],
            grant["flow_revision"],
            grant["authorization_version"],
            [(dict(item), item["content"]) for item in snapshot],
        )
        if not hmac.compare_digest(manifest["manifest_sha256"], grant["resource_sha256"]):
            _deny(409, "Current original worker resource manifest changed")
        stage = await approved_folder_stage_plan(db, grant, manifest)
        return stage["staging_sha256"] if stage is not None else None

    @staticmethod
    async def _auxiliary(
        db: Any, grant: Mapping[str, Any]
    ) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
        offer = (
            (
                await db.execute(
                    text("SELECT * FROM native_mcp_resource_offers WHERE grant_id=:id FOR SHARE"),
                    {"id": grant["grant_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        receipt = (
            (
                await db.execute(
                    text("SELECT * FROM native_mcp_stage_receipts WHERE grant_id=:id FOR SHARE"),
                    {"id": grant["grant_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if offer is not None and (
            offer["status"] != "offered"
            or any(
                offer[key] != grant[key]
                for key in ("engagement_id", "flow_id", "action_id", "request_id", "server_id")
            )
            or offer["manifest_sha256"] != grant["resource_sha256"]
        ):
            _deny(409, "Stale original source resource offer")
        if receipt is not None and (
            offer is None
            or receipt["status"] != "worker_reported"
            or any(
                receipt[key] != grant[key]
                for key in ("engagement_id", "flow_id", "action_id", "request_id", "server_id")
            )
            or receipt["resource_sha256"] != grant["resource_sha256"]
            or receipt["folder_staging_sha256"] != offer["folder_staging_sha256"]
        ):
            _deny(409, "Inconsistent independent worker receipt history")
        return (dict(offer) if offer else None, dict(receipt) if receipt else None)

    @staticmethod
    async def _event(
        db: Any,
        row: Mapping[str, Any],
        claims: dict[str, Any],
        kid: str,
        digest: str,
        signature: str,
    ) -> None:
        await db.execute(
            text(
                "INSERT INTO native_mcp_worker_supervision_events "
                "(id,grant_id,engagement_id,flow_id,action_id,epoch,revision,state,supervisor_id,kid,observed_at,evidence_sha256,claims_sha256,signature_sha256) "
                "VALUES (:id,:grant_id,:engagement_id,:flow_id,:action_id,:epoch,:revision,:state,:supervisor_id,:kid,:observed_at,:evidence_sha256,:claims_sha256,:signature_sha256)"
            ),
            {
                "id": "evt-" + uuid.uuid4().hex,
                **{
                    key: row[key]
                    for key in (
                        "grant_id",
                        "engagement_id",
                        "flow_id",
                        "action_id",
                        "epoch",
                        "revision",
                        "state",
                        "supervisor_id",
                    )
                },
                "kid": kid,
                "observed_at": claims["observed_at"],
                "evidence_sha256": claims["evidence_sha256"],
                "claims_sha256": digest,
                "signature_sha256": signature,
            },
        )

    async def record(
        self,
        token: dict[str, Any],
        observation: dict[str, Any],
        *,
        supervisor_id: str,
        supervisor_secret: str,
    ) -> dict[str, Any]:
        claims, kid, digest, signature = _verify_observation(
            observation, supervisor_id, supervisor_secret
        )
        token_claims, grant_kid, grant_digest, grant_signature = _verify(token)
        if any(
            claims[key] != token_claims[key]
            for key in ("grant_id", "request_id", "server_id", "resource_sha256")
        ):
            _deny(403, "Supervisor observation differs from independent signed grant")
        active = claims["state"] in {"provisioned", "running"}
        try:
            async with self.grants.actions._sessions()() as db:
                async with db.begin():
                    # Lockless identity discovery avoids grant -> Action inversion.
                    observed = await self.grants._grant(db, claims["grant_id"], lock=False)
                    if observed is None:
                        _deny(409, "Original native worker grant missing")
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
                    if active:
                        original = await self.grants._source(
                            db, b, observed["owner_id"], observed["action_id"]
                        )
                    else:
                        # Cleanup must remain possible after ROE, reviewer or
                        # operator revocation. No active work can use this path.
                        original = await self.grants.actions._row(
                            db, observed["action_id"], lock=True
                        )
                        if original is None:
                            _deny(409, "Original worker Action absent")
                    if original.get("status") != "unknown":
                        _deny(409, "Original committed Action no longer UNKNOWN")
                    locked = await self.grants._grant(db, claims["grant_id"], lock=True)
                    if locked is None or any(locked[key] != observed[key] for key in _SOURCE):
                        _deny(409, "Worker grant source changed")
                    self.grants._same(locked, original)
                    self.grants._signed(token_claims, locked)
                    if (
                        locked["kid"] != grant_kid
                        or locked["claims_sha256"] != grant_digest
                        or locked["signature_sha256"] != grant_signature
                    ):
                        _deny(403, "Native signing identity rotated")
                    if active and locked["status"] not in {"issued", "redeemed"}:
                        _deny(409, "Native grant revoked or unknown")
                    if claims["state"] == "running" and locked["status"] != "redeemed":
                        _deny(409, "Supervisor cannot declare unredeemed worker running")
                    now = await self.grants._now(db)
                    if not now - 20 <= claims["observed_at"] <= now + 2:
                        _deny(409, "Supervisor observation timestamp stale")
                    if active:
                        if not locked["issued_at"] <= now < locked["expires_at"]:
                            _deny(409, "Active supervisor grant expired")
                        await self.grants._resources(db, original, locked["resource_sha256"])
                    offer, receipt = await self._auxiliary(db, locked)
                    if active and locked["resource_sha256"] is not None:
                        approved_folder = await self._current_folder(db, locked)
                        if offer is not None and offer["folder_staging_sha256"] != approved_folder:
                            _deny(409, "Current 0026 approved folder stage changed")
                    if (
                        active
                        and locked["resource_sha256"] is not None
                        and claims["state"] == "running"
                        and offer is None
                    ):
                        _deny(409, "Original approved resource offer not recorded")
                    folder = offer["folder_staging_sha256"] if offer else None
                    if claims["state"] == "provisioned" and (
                        claims["folder_staging_sha256"] is not None
                        or claims["readback_sha256"] is not None
                    ):
                        _deny(403, "Provision request cannot assert worker stage")
                    # The independently authenticated supervisor must name the
                    # daemon-observed container BEFORE a resource-bearing 0029
                    # grant can be redeemed. Persist the immutable identity in
                    # the existing 0033 provision row. Legacy no-resource
                    # inert grants may retain the earlier NULL provision form.
                    if (
                        claims["state"] == "provisioned"
                        and locked["resource_sha256"] is not None
                        and claims["container_id"] is None
                    ):
                        _deny(403, "Original resource worker container was not observed")
                    if claims["state"] != "provisioned":
                        if claims["folder_staging_sha256"] != folder:
                            _deny(409, "Supervisor event stale against approved folder offer")
                        if claims["readback_sha256"] is not None and (
                            receipt is None
                            or claims["readback_sha256"] != receipt["readback_sha256"]
                        ):
                            _deny(409, "Worker self-report does not match immutable receipt")
                    if claims["state"] == "provisioned":
                        if claims["epoch"] or claims["expected_revision"]:
                            _deny(409, "Worker provision already fenced")
                        epoch = (
                            await db.execute(text("SELECT nextval('native_mcp_worker_epoch_seq')"))
                        ).scalar_one()
                        if type(epoch) is not int or epoch <= 0:
                            _deny(503, "Global PostgreSQL supervisor epoch unavailable")
                        row = {key: locked[key] for key in _SOURCE if key != "resource_sha256"}
                        row.update(
                            grant_claims_sha256=grant_digest,
                            resource_sha256=locked["resource_sha256"],
                            folder_staging_sha256=None,
                            epoch=epoch,
                            revision=1,
                            state="provisioned",
                            worker_id=claims["worker_id"],
                            container_id=claims["container_id"],
                            supervisor_id=supervisor_id,
                            supervisor_kid=kid,
                        )
                        inserted = (
                            await db.execute(
                                text(
                                    "INSERT INTO native_mcp_worker_supervisions "
                                    "(grant_id,request_id,engagement_id,flow_id,task_id,subtask_id,action_id,owner_id,server_id,worker_id,container_id,supervisor_id,supervisor_kid,approval_id,lease_id,lease_owner_id,flow_revision,authorization_id,authorization_version,authorization_sha256,grant_claims_sha256,resource_sha256,folder_staging_sha256,epoch,revision,state) "
                                    "VALUES (:grant_id,:request_id,:engagement_id,:flow_id,:task_id,:subtask_id,:action_id,:owner_id,:server_id,:worker_id,:container_id,:supervisor_id,:supervisor_kid,:approval_id,:lease_id,:lease_owner_id,:flow_revision,:authorization_id,:authorization_version,:authorization_sha256,:grant_claims_sha256,:resource_sha256,:folder_staging_sha256,:epoch,:revision,:state) "
                                    "ON CONFLICT DO NOTHING RETURNING grant_id"
                                ),
                                row,
                            )
                        ).scalar_one_or_none()
                        if inserted != locked["grant_id"]:
                            _deny(409, "Worker already provisioned; outcome UNKNOWN")
                    else:
                        existing = (
                            (
                                await db.execute(
                                    text(
                                        "SELECT * FROM native_mcp_worker_supervisions WHERE grant_id=:id FOR UPDATE"
                                    ),
                                    {"id": locked["grant_id"]},
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if existing is None:
                            _deny(409, "Supervisor worker lease was not provisioned")
                        row = dict(existing)
                        if (
                            any(row[key] != locked[key] for key in _SOURCE)
                            or row["grant_claims_sha256"] != grant_digest
                            or row["supervisor_id"] != supervisor_id
                            or row["supervisor_kid"] != kid
                            or row["worker_id"] != claims["worker_id"]
                            or row["epoch"] != claims["epoch"]
                            or row["revision"] != claims["expected_revision"]
                            or claims["state"] not in _NEXT.get(row["state"], ())
                        ):
                            _deny(409, "Stale, rotated or invalid global supervisor lease")
                        if (
                            row["container_id"] is not None
                            and claims["container_id"] != row["container_id"]
                        ):
                            _deny(403, "Observed container identity changed")
                        if (
                            row["container_id"] is None
                            and row["state"] != "provisioned"
                            and claims["container_id"] is not None
                        ):
                            _deny(403, "Container cannot appear after initial lifecycle")
                        if claims["state"] == "running" and claims["container_id"] is None:
                            _deny(403, "Running worker lacks independently observed container")
                        if (
                            row["folder_staging_sha256"] is not None
                            and row["folder_staging_sha256"] != folder
                        ):
                            _deny(409, "Approved folder stage changed during worker lifetime")
                        updated = (
                            await db.execute(
                                text(
                                    "UPDATE native_mcp_worker_supervisions SET revision=revision+1,state=:state,container_id=:container,folder_staging_sha256=:folder,updated_at=now() "
                                    "WHERE grant_id=:grant AND epoch=:epoch AND revision=:prior AND state=:old AND supervisor_id=:supervisor AND supervisor_kid=:kid RETURNING revision"
                                ),
                                {
                                    "grant": locked["grant_id"],
                                    "epoch": row["epoch"],
                                    "prior": row["revision"],
                                    "old": row["state"],
                                    "state": claims["state"],
                                    "container": claims["container_id"],
                                    "folder": folder,
                                    "supervisor": supervisor_id,
                                    "kid": kid,
                                },
                            )
                        ).scalar_one_or_none()
                        if updated != row["revision"] + 1:
                            _deny(409, "Concurrent supervisor CAS lost; outcome UNKNOWN")
                        row.update(
                            revision=updated,
                            state=claims["state"],
                            container_id=claims["container_id"],
                            folder_staging_sha256=folder,
                        )
                    await self._event(db, row, claims, kid, digest, signature)
                    # A separately signed 0033 observation that this worker
                    # is terminating, missing or gone must DURABLY invalidate
                    # an as-yet-unredeemed 0029 grant. The ordinary owner
                    # revocation path requires current dispatch authority and
                    # cannot close grants after a reviewer/lease is revoked.
                    # This terminal supervisor branch is intentionally
                    # independent of the revoked original source and runs
                    # under the same Action -> grant -> supervisor locks.
                    # It never settles/replays the original 0027 UNKNOWN.
                    if (
                        claims["state"] in {"terminating", "unknown", "terminated", "reaped"}
                        and locked["status"] == "issued"
                    ):
                        version = (
                            await db.execute(
                                text(
                                    "UPDATE native_mcp_execution_grants "
                                    "SET status='unknown',revision=revision+1,updated_at=now() "
                                    "WHERE grant_id=:grant AND engagement_id=:eng "
                                    "AND request_id=:request AND action_id=:action "
                                    "AND revision=:prior AND status='issued' RETURNING revision"
                                ),
                                {
                                    "grant": locked["grant_id"],
                                    "eng": locked["engagement_id"],
                                    "request": locked["request_id"],
                                    "action": locked["action_id"],
                                    "prior": locked["revision"],
                                },
                            )
                        ).scalar_one_or_none()
                        if version != locked["revision"] + 1:
                            _deny(409, "Terminal supervisor grant closure race UNKNOWN")
                        await self.grants._event(
                            db,
                            {**locked, "status": "unknown", "revision": version},
                            "unknown",
                        )
                    return {
                        "grant_id": locked["grant_id"],
                        "worker_id": row["worker_id"],
                        "epoch": row["epoch"],
                        "revision": row["revision"],
                        "state": row["state"],
                        "supervisor_observed": True,
                        "independent_target_effect_verified": False,
                        "original_action_status": "unknown",
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(
                503, "Durable independent supervisor outcome UNKNOWN"
            ) from exc

    async def request_recovery(
        self,
        binding: dict[str, Any],
        actor_id: str,
        grant_id: str,
        expected_revision: int,
        *,
        explicit_human_confirmation: bool,
    ) -> dict[str, Any]:
        """Append operator intent only; preserve independently observed state.

        An operator cannot mint a supervisor observation, alter an epoch,
        restart a native worker, or replay the original UNKNOWN Action here.
        """
        b = _binding(binding)
        if explicit_human_confirmation is not True:
            _deny(403, "Explicit human recovery intent required")
        if (
            type(grant_id) is not str
            or re.fullmatch(r"ngr-[a-f0-9]{32}", grant_id) is None
            or type(expected_revision) is not int
            or not 1 <= expected_revision < 2**31
        ):
            _deny(403, "Malformed original worker recovery request")
        try:
            async with self.grants.actions._sessions()() as db:
                async with db.begin():
                    await self.grants.actions._authority(db, b, actor_id, dispatch=True)
                    observed = await self.grants._grant(db, grant_id, lock=False)
                    if observed is None:
                        _deny(404, "Original native worker grant unavailable")
                    original = await self.grants.actions._row(db, observed["action_id"], lock=True)
                    if original is None or original.get("status") != "unknown":
                        _deny(409, "Original Action not pending independent recovery")
                    self.grants.actions._same(original, b, actor_id)
                    locked = await self.grants._grant(db, grant_id, lock=True)
                    if locked is None:
                        _deny(409, "Source worker grant changed")
                    self.grants._same(locked, original)
                    worker = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_worker_supervisions "
                                    "WHERE grant_id=:grant FOR UPDATE"
                                ),
                                {"grant": grant_id},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        worker is None
                        or any(worker[key] != locked[key] for key in _SOURCE)
                        or worker["owner_id"] != actor_id
                        or worker["engagement_id"] != b["engagement_id"]
                        or worker["flow_id"] != b["flow_id"]
                        or worker["revision"] != expected_revision
                        or worker["epoch"] <= 0
                        or worker["state"] not in {"unknown", "terminating"}
                    ):
                        _deny(409, "Stale, foreign or active worker recovery denied")
                    request_id = "evt-" + uuid.uuid4().hex
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_mcp_worker_recovery_intents "
                                "(id,grant_id,engagement_id,flow_id,action_id,actor_id,epoch,expected_revision,observed_state,authorization_id,authorization_sha256,kind) "
                                "VALUES (:id,:grant,:eng,:flow,:action,:actor,:epoch,:revision,:state,:auth,:sha,'operator_recovery_requested') "
                                "ON CONFLICT DO NOTHING RETURNING id"
                            ),
                            {
                                "id": request_id,
                                "grant": grant_id,
                                "eng": b["engagement_id"],
                                "flow": b["flow_id"],
                                "action": worker["action_id"],
                                "actor": actor_id,
                                "epoch": worker["epoch"],
                                "revision": expected_revision,
                                "state": worker["state"],
                                "auth": b["authorization_id"],
                                "sha": b["authorization_sha256"],
                            },
                        )
                    ).scalar_one_or_none()
                    if inserted != request_id:
                        _deny(409, "Recovery already requested for observed revision")
                    return {
                        "grant_id": grant_id,
                        "supervisor_revision": expected_revision,
                        "recovery_intent_recorded": True,
                        "worker_execution_replayed": False,
                        "independent_target_effect_verified": False,
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(
                503, "Original worker recovery intent outcome UNKNOWN"
            ) from exc

    async def list_flow(self, binding: dict[str, Any], owner_id: str) -> dict[str, Any]:
        b = _binding(binding)
        try:
            async with self.grants.actions._sessions()() as db:
                async with db.begin():
                    await self.grants.actions._authority(db, b, owner_id, dispatch=True)
                    items = (
                        (
                            await db.execute(
                                text(
                                    "SELECT w.state,w.revision,EXISTS(SELECT 1 FROM native_mcp_worker_recovery_intents r "
                                    "WHERE r.grant_id=w.grant_id AND r.expected_revision=w.revision) AS recovery_intent_pending "
                                    "FROM native_mcp_worker_supervisions w "
                                    "WHERE w.engagement_id=:eng AND w.flow_id=:flow AND w.owner_id=:owner "
                                    "AND w.flow_revision=:revision AND w.authorization_id=:auth "
                                    "AND w.authorization_version=:version AND w.authorization_sha256=:sha "
                                    "ORDER BY w.created_at,w.grant_id LIMIT 101"
                                ),
                                {
                                    "eng": b["engagement_id"],
                                    "flow": b["flow_id"],
                                    "owner": owner_id,
                                    "revision": b["revision"],
                                    "auth": b["authorization_id"],
                                    "version": b["version"],
                                    "sha": b["authorization_sha256"],
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(items) > 100 or any(
                        item["state"] not in _STATES
                        or type(item["revision"]) is not int
                        or item["revision"] < 1
                        for item in items
                    ):
                        _deny(409, "Native worker lifecycle readback inconsistent")
                    return {
                        "source": "durable_independent_supervisor",
                        "workers": [
                            {
                                "state": item["state"],
                                "revision": item["revision"],
                                "supervisor_observed": True,
                                "cleanup_attested": item["state"] == "reaped",
                                "pending_recovery": item["state"] == "unknown",
                                "recovery_intent_pending": item["recovery_intent_pending"] is True,
                            }
                            for item in items
                        ],
                        "independent_target_effect_verified": False,
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(503, "Native worker lifecycle readback unavailable") from exc
