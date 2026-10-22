"""Production PostgreSQL source-authority callback for inert native supervision.

This is an *injected preflight*, NOT a permission issuer, worker runner or a
replacement for 0029 redemption. A separately protected signed original grant,
its owner and the expected local binary SHA must be pinned by the embedding
orchestrator, never supplied by a native worker or HTTP request. Every callback
re-reads the current PostgreSQL signed ROE, 0027 UNKNOWN Action, 0029 issued
grant, signed approval/lease/budget/scope, and reviewed original resource.

Call only through NativeMCPWorkerSupervisor(source_authority=adapter, ...).
There is no import-time DB access, background processing, or container action.
"""

from __future__ import annotations

import hmac
from typing import Any, Optional

from sqlalchemy import text

from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    _SHA,
    _SUBJECT,
    _binding,
    _id,
)
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPExecutionGrantStore,
    _REQUEST,
    _verify,
)
from ai_osop.safety.native_mcp_worker_supervisor import (
    NativeSupervisorDenied,
    SourceAuthorityDecision,
    SupervisorBinding,
)


def _deny() -> None:
    raise NativeSupervisorDenied("Current protected native supervisor authority unavailable")


class NativeMCPSupervisorSourceAdapter:
    """Read-only repeated preflight using EXISTING native store lock order.

    Inputs must come from a protected orchestrator channel, not Go. In
    particular signed_roe_sha256 is not independently credible until the
    PostgreSQL guard_sql check in this callback succeeds.
    """

    def __init__(
        self,
        action_store: FlowMCPActionStore,
        *,
        protected_grant: dict[str, Any],
        protected_owner_id: str,
        trusted_binary_sha256: str,
    ) -> None:
        if not isinstance(action_store, FlowMCPActionStore):
            _deny()
        try:
            _id(protected_owner_id, _SUBJECT)
            _id(trusted_binary_sha256, _SHA)
            if type(protected_grant) is not dict or set(protected_grant) != {
                "claims",
                "kid",
                "signature",
            }:
                _deny()
            _id(protected_grant["claims"].get("request_id"), _REQUEST)
        except Exception:
            _deny()
        # Own an immutable COPY; an external actor mutating a dict after
        # construction cannot swap the protected original grant/owner.
        import copy

        self._protected_grant = copy.deepcopy(protected_grant)
        self._owner = protected_owner_id
        self._binary_sha256 = trusted_binary_sha256
        self._grants = NativeMCPExecutionGrantStore(action_store)

    async def __call__(self, binding: SupervisorBinding) -> SourceAuthorityDecision:
        try:
            if type(binding) is not SupervisorBinding:
                _deny()
            binding.validate()
            if not hmac.compare_digest(binding.binary_sha256, self._binary_sha256):
                _deny()
            claims, kid, claims_hash, signature_hash = _verify(self._protected_grant)
            if (
                claims["resource_sha256"] is None
                or binding.issuer_kid != kid
                or binding.request_id != claims["request_id"]
                or binding.engagement_id != claims["engagement_id"]
                or binding.flow_id != claims["flow_id"]
                or binding.task_id != claims["task_id"]
                or binding.subtask_id != claims["subtask_id"]
                or binding.action_id != claims["action_id"]
                or binding.lease_id != claims["lease_id"]
                or binding.server_id != claims["server_id"]
                or binding.tool_name != claims["tool_name"]
                or not hmac.compare_digest(
                    binding.authorization_sha256, claims["authorization_sha256"]
                )
                or not hmac.compare_digest(
                    binding.signed_roe_sha256, claims["authorization_sha256"]
                )
                or not hmac.compare_digest(binding.manifest_sha256, claims["manifest_sha256"])
            ):
                _deny()
            async with self._grants.actions._sessions()() as db:
                async with db.begin():
                    # Discovery MUST NOT lock grant before original Action.
                    # Lock order: original Flow/Action/Task/lease, then grant.
                    observed = await self._grants._grant(db, claims["grant_id"], lock=False)
                    if (
                        observed is None
                        or observed.get("status") != "issued"
                        or observed.get("revision") != 1
                        or observed.get("kid") != kid
                        or observed.get("owner_id") != self._owner
                        or observed.get("claims_sha256") != claims_hash
                        or observed.get("signature_sha256") != signature_hash
                        or observed.get("resource_sha256") != claims["resource_sha256"]
                    ):
                        _deny()
                    self._grants._signed(claims, observed)
                    current_binding = _binding(
                        {
                            "engagement_id": observed["engagement_id"],
                            "flow_id": observed["flow_id"],
                            "revision": observed["flow_revision"],
                            "version": observed["authorization_version"],
                            "authorization_id": observed["authorization_id"],
                            "authorization_sha256": observed["authorization_sha256"],
                        }
                    )
                    # _source invokes the real current signed authorization
                    # Flow fence (guard_sql), original UNKNOWN 0027 immutable
                    # event, Task/subtask, human reviewer, lease, scope/budget
                    # and inert declaration. Any missing dependency denies.
                    original = await self._grants._source(
                        db, current_binding, self._owner, claims["action_id"]
                    )
                    # Re-read the 0029 row AFTER acquiring original Action
                    # locks, just like redeem. This cannot mint permission.
                    current = await self._grants._grant(db, claims["grant_id"], lock=True)
                    if (
                        current is None
                        or current.get("status") != "issued"
                        or current.get("revision") != 1
                        or current.get("owner_id") != self._owner
                        or current.get("kid") != kid
                        or current.get("claims_sha256") != claims_hash
                        or current.get("signature_sha256") != signature_hash
                        or current.get("resource_sha256") != claims["resource_sha256"]
                    ):
                        _deny()
                    self._grants._same(current, original)
                    self._grants._signed(claims, current)
                    if (
                        current["approval_id"] != binding.approval_id
                        or current["lease_id"] != binding.lease_id
                        or original["approval_id"] != binding.approval_id
                        or original["lease_id"] != binding.lease_id
                        or original["request_id"] != binding.request_id
                        or original["task_id"] != binding.task_id
                        or original["subtask_id"] != binding.subtask_id
                        or original["server_id"] != "recon-mcp"
                        or original["tool_name"] != "authority_status"
                    ):
                        _deny()
                    now = await self._grants._now(db)
                    if not current["issued_at"] <= now < current["expires_at"]:
                        _deny()
                    # Verify a COMMITTED signed issuance, independently of
                    # the valid cryptographic token alone.
                    issued_event = (
                        await db.execute(
                            text(
                                "SELECT 1 FROM native_mcp_execution_grant_events "
                                "WHERE grant_id=:grant AND engagement_id=:eng "
                                "AND flow_id=:flow AND action_id=:action "
                                "AND request_id=:request AND revision=1 "
                                "AND kind='issued' AND status='issued' "
                                "AND claims_sha256=:sha LIMIT 1 FOR SHARE"
                            ),
                            {
                                "grant": claims["grant_id"],
                                "eng": claims["engagement_id"],
                                "flow": claims["flow_id"],
                                "action": claims["action_id"],
                                "request": claims["request_id"],
                                "sha": claims_hash,
                            },
                        )
                    ).scalar_one_or_none()
                    if issued_event != 1:
                        _deny()
                    # Original reviewed Task-pinned digest, artifact bytes,
                    # independent reviewer and current Flow resource lineage.
                    await self._grants._resources(db, original, current["resource_sha256"])
                    # Fresh signed ROE SHA must come from PostgreSQL's
                    # independently verified policy, NOT a caller assertion.
                    signed = await guard_sql(
                        db,
                        original["engagement_id"],
                        expected_version=current["authorization_version"],
                    )
                    if (
                        signed.authorization_id != original["authorization_id"]
                        or not hmac.compare_digest(
                            signed.policy_sha256, current["authorization_sha256"]
                        )
                        or not hmac.compare_digest(signed.policy_sha256, binding.signed_roe_sha256)
                        or signed.policy.get("created_by") != self._owner
                    ):
                        _deny()
                    expires_at = min(current["expires_at"], now + 10)
                    if expires_at <= now:
                        _deny()
                    return SourceAuthorityDecision(
                        binding=binding,
                        authority_version=current["authorization_version"],
                        checked_at=now,
                        expires_at=expires_at,
                        issuer_trusted=True,
                        signed_roe_valid=True,
                        task_active=True,
                        approval_current=True,
                        lease_active=True,
                    )
        except NativeSupervisorDenied:
            raise
        except Exception:
            # No raw PG errors, Task content, reviewer PII, signing keys or
            # partial permission facts escape this production preflight.
            _deny()
