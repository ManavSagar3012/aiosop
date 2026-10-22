"""Conservative native MCP supervisor reconciliation over existing 0029/0033.

0033.updated_at is the last *durable signed transition*, NOT a heartbeat or
evidence that a process exited. Candidate listing is read-only and returns
SUSPECT/UNKNOWN labels, never a terminal assertion. The only write path calls
the original authenticated 0033 Store.record with a caller-supplied Ed25519
observation; its PostgreSQL Action->grant->worker CAS and immutable event are
the final authority. No watchdog, container reaper, or background job is
started by importing or constructing this helper.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Mapping, Optional

from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import (
    MCPActionDenied,
    _SUBJECT,
    _binding,
    _id,
)
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    _GRANT,
    _supervisor_public_key,
    _verify,
)
from ai_osop.memory.native_mcp_worker_supervision import (
    NativeMCPWorkerSupervisionStore,
    _SOURCE,
    _verify_observation,
)
from ai_osop.safety.native_mcp_worker_supervisor import verify_supervisor_statement

_CANDIDATE_STATES = frozenset({"provisioned", "running", "terminating", "terminated", "unknown"})
_RECONCILE_STATES = frozenset({"unknown", "reaped"})
_CONTAINER = re.compile(r"[a-f0-9]{64}\Z")
_NETWORK = re.compile(r"[a-f0-9]{64}\Z")
_OWNER = re.compile(r"osop-native-sup-[a-f0-9]{32}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _deny(message: str = "Native supervisor reconciliation unavailable") -> None:
    raise NativeMCPGrantDenied(409, message)


def _match_worker(worker: Mapping[str, Any], grant: Mapping[str, Any]) -> None:
    if any(
        type(worker.get(key)) is not type(grant.get(key)) or worker.get(key) != grant.get(key)
        for key in _SOURCE
    ) or worker.get("grant_claims_sha256") != grant.get("claims_sha256"):
        _deny("Native supervisor original grant identity changed")
    if (
        type(worker.get("epoch")) is not int
        or worker["epoch"] <= 0
        or type(worker.get("revision")) is not int
        or worker["revision"] < 1
        or worker.get("state") not in _CANDIDATE_STATES | {"reaped"}
        or type(worker.get("supervisor_id")) is not str
        or type(worker.get("supervisor_kid")) is not str
        or type(worker.get("worker_id")) is not str
    ):
        _deny("Native supervisor lineage or epoch invalid")


def _check_latest_event(event: Optional[Mapping[str, Any]], worker: Mapping[str, Any]) -> None:
    if (
        event is None
        or any(
            type(event.get(field)) is not type(worker.get(field))
            or event.get(field) != worker.get(field)
            for field in (
                "grant_id",
                "engagement_id",
                "flow_id",
                "action_id",
                "epoch",
                "revision",
                "state",
                "supervisor_id",
            )
        )
        or event.get("kid") != worker.get("supervisor_kid")
    ):
        _deny("Latest immutable supervisor event is absent or inconsistent")
    if any(
        type(event.get(key)) is not str or _SHA.fullmatch(event[key]) is None
        for key in ("evidence_sha256", "claims_sha256", "signature_sha256")
    ):
        _deny("Supervisor event digests are unavailable")


def _check_owned_cleanup(
    *,
    worker: Mapping[str, Any],
    grant: Mapping[str, Any],
    observation: Mapping[str, Any],
    ownership_statement: Any,
    cleanup_statement: Any,
    now: int,
) -> None:
    """Require actual separate supervisor-signed owned-container teardown.

    An opaque 0033 evidence_sha256, a stale timestamp, a container-not-found
    message, or an operator recovery intent is insufficient to assert REAPED.
    Existing dedicated independent supervisor signs the two exact statements
    after its owned container and network have been removed and rechecked.
    """
    public = _supervisor_public_key(worker["supervisor_id"], worker["supervisor_kid"])
    key = public.public_bytes_raw()
    if (
        type(ownership_statement) is not dict
        or type(cleanup_statement) is not dict
        or ownership_statement.get("kid") != worker["supervisor_kid"]
        or cleanup_statement.get("kid") != worker["supervisor_kid"]
        or not verify_supervisor_statement(ownership_statement, public_key=key, ownership=True)
        or not verify_supervisor_statement(cleanup_statement, public_key=key)
    ):
        _deny("Independent owned resource cleanup proof is not trusted")
    owned = ownership_statement["claims"]
    cleanup = cleanup_statement["claims"]
    attested_binding = cleanup.get("binding")
    observed = cleanup.get("observations")
    container = worker.get("container_id")
    if (
        type(container) is not str
        or _CONTAINER.fullmatch(container) is None
        or type(owned.get("owner")) is not str
        or _OWNER.fullmatch(owned["owner"]) is None
        or owned.get("version") != 1
        or owned.get("container_id") != container
        or type(owned.get("network_id")) is not str
        or _NETWORK.fullmatch(owned["network_id"]) is None
        or type(owned.get("created_at")) is not int
        or cleanup.get("version") != 1
        or cleanup.get("cleanup_verified") is not True
        or cleanup.get("container_id") != container
        or cleanup.get("network_id") != owned["network_id"]
        or cleanup.get("server_id") != "recon-mcp"
        or cleanup.get("tool_name") != "authority_status"
        or cleanup.get("target_contacted") is not False
        or cleanup.get("provider_contacted") is not False
        or cleanup.get("scanner_invoked") is not False
        or type(cleanup.get("observed_at")) is not int
        or not now - 20 <= cleanup["observed_at"] <= now
        or not 0 < owned["created_at"] <= cleanup["observed_at"]
        or type(attested_binding) is not dict
        or type(observed) is not dict
        or observed.get("container_id") != container
        or observed.get("network_id") != owned["network_id"]
        or observed.get("private_stage_mount_verified") is not True
        or observed.get("stage_empty") is not True
        or observed.get("no_host_mounts") is not True
        or observed.get("no_external_network") is not True
        or observation["claims"]["observed_at"] < cleanup["observed_at"]
    ):
        _deny("Independent owned container destruction not demonstrated")
    for source_key in (
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "lease_id",
        "authorization_sha256",
    ):
        if attested_binding.get(source_key) != grant.get(source_key):
            _deny("Independent cleanup refers to different original Task")
    if (
        attested_binding.get("server_id") != grant.get("server_id")
        or attested_binding.get("tool_name") != "authority_status"
    ):
        _deny("Independent cleanup refers to different native MCP")


class NativeMCPSupervisorReconciler:
    """Explicit adapter, never scheduled automatically.

    Instantiation needs a production NativeMCPWorkerSupervisionStore. The
    listing uses current signed owner authority; the terminal path can work
    after revocation by delegating only separately signed observations to the
    existing 0033 store. Neither API accepts a worker's self-report.
    """

    def __init__(self, store: NativeMCPWorkerSupervisionStore) -> None:
        if not isinstance(store, NativeMCPWorkerSupervisionStore):
            _deny("Production 0033 worker supervision store required")
        self.store = store

    @staticmethod
    async def _event(db: Any, grant_id: str) -> Optional[dict[str, Any]]:
        found = (
            (
                await db.execute(
                    text(
                        "SELECT * FROM native_mcp_worker_supervision_events "
                        "WHERE grant_id=:grant ORDER BY revision DESC LIMIT 1"
                    ),
                    {"grant": grant_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        return dict(found) if found is not None else None

    async def suspects(
        self,
        binding: dict[str, Any],
        owner_id: str,
        *,
        minimum_age_seconds: int = 60,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Bounded PG list of SUSPECTS, not live processes or proven orphans.

        updated_at is NOT a heartbeat. Candidates here may be healthy, paused
        or already cleaned up; this method performs NO native/Go/Docker action
        and never changes either 0029 or 0033 state.
        """
        scope = _binding(binding)
        _id(owner_id, _SUBJECT)
        if (
            type(minimum_age_seconds) is not int
            or not 60 <= minimum_age_seconds <= 86400
            or type(limit) is not int
            or not 1 <= limit <= 32
        ):
            _deny("Unbounded supervisor reconciliation request")
        try:
            async with self.store.grants.actions._sessions()() as db:
                async with db.begin():
                    await self.store.grants.actions._authority(db, scope, owner_id, dispatch=True)
                    now = await self.store.grants._now(db)
                    rows = (
                        (
                            await db.execute(
                                text(
                                    "SELECT w.*, FLOOR(EXTRACT(EPOCH FROM w.updated_at))::bigint "
                                    "AS transition_at FROM native_mcp_worker_supervisions w "
                                    "WHERE w.engagement_id=:eng AND w.flow_id=:flow "
                                    "AND w.owner_id=:owner AND w.flow_revision=:revision "
                                    "AND w.authorization_id=:authorization "
                                    "AND w.authorization_version=:version "
                                    "AND w.authorization_sha256=:sha "
                                    "AND w.state IN ('provisioned','running','terminating',"
                                    "'terminated','unknown') "
                                    "AND w.updated_at <= to_timestamp(:before) "
                                    "ORDER BY w.updated_at,w.grant_id LIMIT :limit"
                                ),
                                {
                                    "eng": scope["engagement_id"],
                                    "flow": scope["flow_id"],
                                    "owner": owner_id,
                                    "revision": scope["revision"],
                                    "authorization": scope["authorization_id"],
                                    "version": scope["version"],
                                    "sha": scope["authorization_sha256"],
                                    "before": now - minimum_age_seconds,
                                    "limit": limit + 1,
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(rows) > limit:
                        _deny("Suspect worker list exceeded bounded snapshot")
                    result: list[dict[str, Any]] = []
                    for worker_row in rows:
                        worker = dict(worker_row)
                        if worker.get("state") not in _CANDIDATE_STATES or any(
                            worker.get(field) != expected
                            for field, expected in (
                                ("engagement_id", scope["engagement_id"]),
                                ("flow_id", scope["flow_id"]),
                                ("owner_id", owner_id),
                                ("flow_revision", scope["revision"]),
                                ("authorization_id", scope["authorization_id"]),
                                ("authorization_version", scope["version"]),
                                ("authorization_sha256", scope["authorization_sha256"]),
                            )
                        ):
                            _deny("Unknown supervisor candidate state")
                        transition_at = worker.get("transition_at")
                        if (
                            type(transition_at) is not int
                            or transition_at <= 0
                            or transition_at > now - minimum_age_seconds
                            or transition_at > now
                        ):
                            _deny("Invalid durable last-transition timestamp")
                        grant = await self.store.grants._grant(db, worker["grant_id"], lock=False)
                        if grant is None:
                            _deny("Original 0029 grant not found")
                        _match_worker(worker, grant)
                        _check_latest_event(await self._event(db, worker["grant_id"]), worker)
                        result.append(
                            {
                                "grant_id": worker["grant_id"],
                                "request_id": worker["request_id"],
                                "worker_id": worker["worker_id"],
                                "epoch": worker["epoch"],
                                "revision": worker["revision"],
                                "state": worker["state"],
                                "grant_status": grant["status"],
                                "age_since_last_signed_transition_seconds": now - transition_at,
                                "classification": (
                                    "pending_independent_recovery"
                                    if worker["state"] in {"unknown", "terminating"}
                                    else "suspected_orphan_unverified"
                                ),
                                "container_destroyed_verified": False,
                                "execution_replay_authorized": False,
                            }
                        )
                    return {
                        "source": "durable_0033_last_transition_not_heartbeat",
                        "candidates": result,
                        "independent_process_liveness_verified": False,
                        "automatic_reaping_enabled": False,
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(
                503, "Durable native worker suspect read unavailable"
            ) from exc

    async def reconcile_signed(
        self,
        token: dict[str, Any],
        observation: dict[str, Any],
        *,
        supervisor_id: str,
        supervisor_secret: str,
        ownership_statement: Optional[dict[str, Any]] = None,
        cleanup_statement: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Forward ONLY independently authenticated UNKNOWN/REAPED testimony.

        0033.record is the *sole* durable writer, and atomically marks a still
        issued 0029 grant UNKNOWN on terminal observation. A timeout or stale
        updated_at NEVER creates an observation. For REAPED the caller must
        supply two separately signed exact owned-container removal facts.
        """
        claims, kid, _, _ = _verify_observation(observation, supervisor_id, supervisor_secret)
        grant_claims, _, grant_digest, _ = _verify(token)
        state = claims["state"]
        if state not in _RECONCILE_STATES or any(
            claims[key] != grant_claims[key]
            for key in ("grant_id", "request_id", "server_id", "resource_sha256")
        ):
            _deny("Only exact independently signed UNKNOWN or REAPED is accepted")
        try:
            async with self.store.grants.actions._sessions()() as db:
                async with db.begin():
                    grant = await self.store.grants._grant(db, claims["grant_id"], lock=False)
                    if grant is None or grant.get("claims_sha256") != grant_digest:
                        _deny("Reconciliation original grant no longer current")
                    worker_row = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_worker_supervisions "
                                    "WHERE grant_id=:grant"
                                ),
                                {"grant": claims["grant_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if worker_row is None:
                        _deny("Current durable supervisor state absent")
                    worker = dict(worker_row)
                    _match_worker(worker, grant)
                    _check_latest_event(await self._event(db, claims["grant_id"]), worker)
                    if (
                        claims["epoch"] != worker["epoch"]
                        or claims["expected_revision"] != worker["revision"]
                        or claims["worker_id"] != worker["worker_id"]
                        or supervisor_id != worker["supervisor_id"]
                        or kid != worker["supervisor_kid"]
                        or (
                            worker["container_id"] is not None
                            and claims["container_id"] != worker["container_id"]
                        )
                        or (
                            worker["container_id"] is None
                            and worker["state"] != "provisioned"
                            and claims["container_id"] is not None
                        )
                    ):
                        _deny("Stale supervisor epoch, worker or container")
                    if state == "unknown" and worker["state"] not in {
                        "provisioned",
                        "running",
                        "terminating",
                    }:
                        _deny("Stale or repeated UNKNOWN supervisor observation")
                    if state == "reaped":
                        if worker["state"] not in {"unknown", "terminated"}:
                            _deny("Premature or repeated REAPED supervisor observation")
                        now = await self.store.grants._now(db)
                        _check_owned_cleanup(
                            worker=worker,
                            grant=grant,
                            observation=observation,
                            ownership_statement=ownership_statement,
                            cleanup_statement=cleanup_statement,
                            now=now,
                        )
            # Separate transaction deliberately; original 0033.record repeats
            # original-source authentication, locks, CAS and immutable audit.
            # A revision change after the read is denied by 0033, never retried.
            readback = await asyncio.wait_for(
                self.store.record(
                    token,
                    observation,
                    supervisor_id=supervisor_id,
                    supervisor_secret=supervisor_secret,
                ),
                timeout=15,
            )
            if (
                type(readback) is not dict
                or readback.get("grant_id") != claims["grant_id"]
                or readback.get("worker_id") != claims["worker_id"]
                or readback.get("epoch") != claims["epoch"]
                or readback.get("revision") != claims["expected_revision"] + 1
                or readback.get("state") != state
                or readback.get("supervisor_observed") is not True
                or readback.get("independent_target_effect_verified") is not False
            ):
                _deny("Durable 0033 reconciliation readback unconfirmed")
            return {
                "grant_id": readback["grant_id"],
                "epoch": readback["epoch"],
                "revision": readback["revision"],
                "state": state,
                "durable_supervisor_observation_recorded": True,
                "container_destroyed_verified": state == "reaped",
                "original_action_settled": False,
                "replay_authorized": False,
            }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(
                503, "Native supervisor reconciliation outcome UNKNOWN"
            ) from exc
