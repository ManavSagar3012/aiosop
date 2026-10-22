"""Independent, non-consuming current 0033/0035/0037 SourceMap corroboration.

This is NOT an issuer, a Process/PID observer, a filesystem mount observer, a
grant redeemer, or a replacement for the original 0027 UNKNOWN Action. A
valid response requires separately enrolled signed 0033 ledger, signed current
0035 STATUS + original 0035 preflight, live process/PID and mount observations,
and a separate signed supervisor-source binding. Every fact is rejoined to
live PostgreSQL Action/Task/0013 BYTEA/0015 reviewer, immutable 0037 bound-only
provenance, 0029 grant, 0030/0031 offered resource, and latest 0033 event.

Real external process/mount producers and an independently signed SourceMap
native grant do not presently exist in the mounted original runtime; missing
sources DENY. Test signatures are not production process/mount measurements.
No network, Docker, provider, mounts, source reissue, target or SQL writes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_execution_grants import _verify as _verify_native
from ai_osop.memory.native_mcp_worker_supervision import NativeMCPWorkerSupervisionStore
from ai_osop.memory.sourcemap_source_authority import (
    CLAIM_FIELDS,
    DOMAIN as PREFLIGHT_DOMAIN,
    SourceMapSourceAuthorityStore,
    canonical as source_canonical,
    validate_request,
)
from ai_osop.memory.sourcemap_status_authority import SourceMapStatusAuthorityStore
from ai_osop.orchestrator.sourcemap_native_mount_observer import (
    MOUNT_DOMAIN,
    MOUNT_FIELDS,
    verify_supervisor_source,
)
from ai_osop.orchestrator.sourcemap_original_stage import _canonical, _roots, _signed_claims
from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
    LEDGER_DOMAIN,
    PROCESS_DOMAIN,
    SOURCE_STATUS_DOMAIN,
    _LEDGER_FIELDS,
    _PROCESS_FIELDS,
    _STATUS_FIELDS,
    _verified,
)

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_GRANT = re.compile(r"ngr-[a-f0-9]{32}\Z")
_SOURCE = "source-map-mcp"
_TOOL = "inspect_local_original_sourcemap"
_ROOT = "/run/osop-sourcemap/sourcemap-originals"
_SAME_SOURCE = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "authorization_sha256",
    "artifact_sha256",
    "manifest_sha256",
)
_PROC = (
    "pid",
    "pid_start_ticks",
    "mount_namespace_inode",
    "native_fsuid",
    "container_id",
    "epoch",
)
_SUPERVISOR = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "lease_owner_id",
    "server_id",
    "authorization_version",
    "authorization_sha256",
)
_BIND_SOURCE = (
    "action_id",
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "lease_owner_id",
    "flow_revision",
    "authorization_id",
    "authorization_version",
    "authorization_sha256",
)


class SourceMap0033CurrentWitnessDenied(ValueError):
    """No independent current process, grant, mount or resource corroboration."""


def _deny() -> None:
    raise SourceMap0033CurrentWitnessDenied(
        "Independent current SourceMap 0033 witness unavailable"
    )


def _equal(left: Mapping[str, Any], right: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(
        field in left
        and field in right
        and type(left[field]) is type(right[field])
        and left[field] == right[field]
        for field in fields
    )


def _sha(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _fresh(item: Mapping[str, Any], now: int, *, timestamp: str, age: int, ttl: int) -> bool:
    issued = item.get(timestamp)
    end = item.get("expires_at")
    return (
        type(now) is int
        and type(issued) is int
        and type(end) is int
        and now - age <= issued <= now + 1
        and now < end <= issued + ttl
    )


def _verify_external_proofs(
    *,
    supervisor_observation: Any,
    source_status: Any,
    source_preflight_proof: Any,
    live_process_witness: Any,
    signed_supervisor_source: Any,
    native_mount_witness: Any,
    roots: Mapping[str, Mapping[str, bytes]],
    now: int,
) -> dict[str, Any]:
    """Verify authentic independent signatures; never create evidence here.

    Caller-provided PID/path/boolean is NOT an input. Only signed claim sets
    from the separately enrolled kernel process and mount observers can join.
    """
    try:
        if type(now) is not int or now <= 0:
            _deny()
        ledger, ledger_sha = _verified(
            supervisor_observation, roots["ledger"], LEDGER_DOMAIN, _LEDGER_FIELDS
        )
        status, status_sha = _verified(
            source_status, roots["status"], SOURCE_STATUS_DOMAIN, _STATUS_FIELDS
        )
        process, _ = _verified(
            live_process_witness, roots["process"], PROCESS_DOMAIN, _PROCESS_FIELDS
        )
        original_proof, _ = _signed_claims(
            source_preflight_proof, roots["status"], PREFLIGHT_DOMAIN, CLAIM_FIELDS, now
        )
        supervisor, supervisor_sha = verify_supervisor_source(
            signed_supervisor_source, roots["supervisor"], _ROOT, now=now
        )
        mount, _ = _verified(native_mount_witness, roots["mount"], MOUNT_DOMAIN, MOUNT_FIELDS)
        if (
            any(
                type(claims.get("version")) is not int or claims["version"] != 1
                for claims in (ledger, status, process, original_proof, supervisor, mount)
            )
            or ledger.get("state") != "running"
            or ledger.get("server_id") != _SOURCE
            or status.get("server_id") != _SOURCE
            or status.get("tool_name") != _TOOL
            or supervisor.get("server_id") != _SOURCE
            or supervisor.get("tool_name") != _TOOL
            or supervisor.get("status") != "running"
            or mount.get("server_id") != _SOURCE
            or mount.get("mode") != "host-stage-v1"
            or mount.get("native_stage_root") != _ROOT
            or supervisor.get("native_stage_root") != _ROOT
            or process.get("native_stage_root") != _ROOT
            or mount.get("read_only") is not True
            or type(mount.get("observer_id")) is not str
            or not mount["observer_id"]
            or not _fresh(status, now, timestamp="issued_at", age=2, ttl=5)
            or not _fresh(original_proof, now, timestamp="issued_at", age=5, ttl=10)
            or type(ledger.get("observed_at")) is not int
            or not now - 3 <= ledger["observed_at"] <= now + 1
            or not _fresh(process, now, timestamp="observed_at", age=2, ttl=5)
            or not _fresh(supervisor, now, timestamp="issued_at", age=2, ttl=5)
            or not _fresh(mount, now, timestamp="issued_at", age=2, ttl=5)
            or status.get("preflight_id") != original_proof.get("preflight_id")
            or not _equal(
                status,
                original_proof,
                (
                    "request_id",
                    "engagement_id",
                    "flow_id",
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "server_id",
                    "tool_name",
                    "approval_id",
                    "lease_id",
                    "artifact_sha256",
                    "manifest_sha256",
                    "authorization_version",
                    "authorization_sha256",
                ),
            )
            or not _equal(status, supervisor, _SAME_SOURCE)
            or not _equal(status, mount, _SAME_SOURCE)
            or not _equal(
                ledger,
                process,
                (
                    "grant_id",
                    "request_id",
                    "worker_id",
                    "container_id",
                    "epoch",
                ),
            )
            or not _equal(
                ledger,
                supervisor,
                (
                    "request_id",
                    "container_id",
                    "epoch",
                ),
            )
            or not _equal(process, supervisor, _PROC)
            or not _equal(supervisor, mount, _PROC)
            or process.get("cgroup_sha256") != supervisor.get("cgroup_sha256")
            or process.get("supervisor_observation_sha256") != ledger_sha
            or mount.get("supervisor_source_sha256") != supervisor_sha
            or ledger.get("request_id") != status.get("request_id")
            or ledger.get("resource_sha256") != status.get("manifest_sha256")
            or type(ledger.get("epoch")) is not int
            or ledger["epoch"] <= 0
            or type(ledger.get("expected_revision")) is not int
            or ledger["expected_revision"] < 1
            or not _sha(ledger.get("container_id"))
            or type(process.get("pid")) is not int
            or not 0 < process["pid"] <= 4194304
            or any(
                type(process.get(k)) is not int or process[k] <= 0
                for k in ("pid_start_ticks", "mount_namespace_inode", "native_fsuid")
            )
            or not _sha(process.get("cgroup_sha256"))
            or not _sha(supervisor.get("signed_roe_sha256"))
            or supervisor.get("signed_roe_sha256") != status.get("authorization_sha256")
            or not _sha(mount.get("authorization_sha256"))
            or any(type(mount.get(k)) is not int or mount[k] <= 0 for k in ("root_dev", "root_ino"))
            or mount.get("expires_at") > supervisor.get("expires_at")
            or supervisor.get("expires_at") > status.get("expires_at")
            or any(
                supervisor.get(k) is not True
                for k in (
                    "source_current",
                    "lease_active",
                    "approval_current",
                )
            )
        ):
            _deny()
        return {
            "ledger": ledger,
            "status": status,
            "source": original_proof,
            "process": process,
            "supervisor": supervisor,
            "mount": mount,
            "ledger_sha": ledger_sha,
            "status_sha": status_sha,
            "supervisor_sha": supervisor_sha,
            "source_kid": source_preflight_proof["kid"],
            "source_signature_sha256": hashlib.sha256(
                base64.urlsafe_b64decode(source_preflight_proof["signature"] + "==")
            ).hexdigest(),
            "ledger_kid": supervisor_observation["kid"],
        }
    except SourceMap0033CurrentWitnessDenied:
        raise
    except Exception as exc:
        raise SourceMap0033CurrentWitnessDenied(
            "Missing or invalid independently signed current SourceMap evidence"
        ) from exc


def _verify_current_rows(
    *,
    original: Mapping[str, Any],
    manifest: str,
    preflight: Mapping[str, Any],
    binding: Mapping[str, Any],
    grant: Mapping[str, Any],
    offer: Mapping[str, Any],
    worker: Mapping[str, Any],
    events: list[Mapping[str, Any]],
    signed: Mapping[str, Any],
    folder_sha: str,
    now: int,
    current_task: Mapping[str, Any],
    review: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare already DB-verified original with immutable 0037/0033 sources.

    No caller can directly turn a mapping into authority: only corroborate()
    calls this after Ed25519 signature validation and a single live DB read.
    """
    if (
        any(
            not isinstance(item, Mapping)
            for item in (
                original,
                preflight,
                binding,
                grant,
                offer,
                worker,
                signed,
                current_task,
                review,
            )
        )
        or type(events) is not list
    ):
        _deny()
    ledger = signed["ledger"]
    status = signed["status"]
    source = signed["source"]
    mount = signed["mount"]
    process = signed["process"]
    supervisor = signed["supervisor"]
    if (
        original.get("status") != "unknown"
        or original.get("cancel_requested") is not False
        or original.get("receipt_sha256") is not None
        or original.get("server_id") != _SOURCE
        or original.get("tool_name") != _TOOL
        or original.get("side_effect_class") != "READ_ONLY"
        or not _equal(
            original,
            status,
            (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "authorization_sha256",
                "authorization_version",
            ),
        )
        or status.get("manifest_sha256") != manifest
        or source.get("manifest_sha256") != manifest
        or preflight.get("preflight_id") != status.get("preflight_id")
        or preflight.get("kid") != signed.get("source_kid")
        or preflight.get("artifact_sha256") != status.get("artifact_sha256")
        or preflight.get("manifest_sha256") != manifest
        or preflight.get("claims_sha256") != hashlib.sha256(source_canonical(source)).hexdigest()
        or preflight.get("signature_sha256") != signed.get("source_signature_sha256")
        or not _equal(
            preflight,
            source,
            (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "authorization_sha256",
                "authorization_version",
                "issued_at",
                "expires_at",
            ),
        )
        or type(now) is not int
        or now < preflight.get("issued_at", 0)
        or now >= preflight.get("expires_at", 0)
        or binding.get("status") != "bound_only"
        or not _equal(original, binding, _BIND_SOURCE)
        or binding.get("preflight_id") != preflight.get("preflight_id")
        or binding.get("grant_id") != ledger.get("grant_id")
        or binding.get("artifact_sha256") != status.get("artifact_sha256")
        or binding.get("resource_manifest_sha256") != manifest
        or binding.get("declaration_sha256") != original.get("declaration_sha256")
        or binding.get("parameters_sha256") != original.get("parameters_sha256")
        or binding.get("preflight_claims_sha256") != preflight.get("claims_sha256")
        or binding.get("preflight_signature_sha256") != preflight.get("signature_sha256")
        or not _sha(binding.get("join_sha256"))
        or binding.get("reviewer_id") != review.get("reviewer_sub")
        or review.get("reviewer_sub") in (None, "", original.get("owner_id"))
        or review.get("reviewer_role") != "senior_operator"
        or review.get("decision") != "approve"
        or review.get("artifact_id") != binding.get("artifact_id")
        or review.get("artifact_sha256") != status.get("artifact_sha256")
        or not _equal(
            review,
            original,
            (
                "engagement_id",
                "flow_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            ),
        )
        or current_task.get("resource_artifact_id") != binding.get("artifact_id")
        or current_task.get("resource_artifact_sha256") != status.get("artifact_sha256")
        or current_task.get("resource_manifest_sha256") != manifest
        or current_task.get("resource_command_sha256") != original.get("parameters_sha256")
        or current_task.get("resource_authorization_sha256") != original.get("authorization_sha256")
        or not _equal(
            original,
            grant,
            (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
                "server_id",
                "tool_name",
                "parameters_sha256",
                "side_effect_class",
                "intent_sha256",
            ),
        )
        or grant.get("grant_id") != binding.get("grant_id")
        or grant.get("status") != "redeemed"
        or type(grant.get("issued_at")) is not int
        or type(grant.get("expires_at")) is not int
        or not grant["issued_at"] <= now < grant["expires_at"]
        or grant.get("resource_sha256") != manifest
        or grant.get("manifest_sha256") != original.get("declaration_sha256")
        or binding.get("grant_claims_sha256") != grant.get("claims_sha256")
        or binding.get("grant_signature_sha256") != grant.get("signature_sha256")
        or not _equal(
            grant,
            offer,
            (
                "grant_id",
                "request_id",
                "engagement_id",
                "flow_id",
                "action_id",
                "server_id",
            ),
        )
        or offer.get("status") != "offered"
        or offer.get("manifest_sha256") != manifest
        or offer.get("claims_sha256") != grant.get("claims_sha256")
        or not _sha(folder_sha)
        or offer.get("folder_staging_sha256") != folder_sha
        or not _equal(original, worker, _SUPERVISOR)
        or worker.get("grant_id") != grant.get("grant_id")
        or worker.get("state") != "running"
        or worker.get("resource_sha256") != manifest
        or worker.get("folder_staging_sha256") != folder_sha
        or worker.get("grant_claims_sha256") != grant.get("claims_sha256")
        or worker.get("worker_id") != ledger.get("worker_id")
        or worker.get("container_id") != ledger.get("container_id")
        or worker.get("epoch") != ledger.get("epoch")
        or worker.get("supervisor_kid") != signed.get("ledger_kid")
        or type(worker.get("revision")) is not int
        or worker["revision"] != ledger.get("expected_revision", -10) + 1
        or not _equal(worker, ledger, ("grant_id", "request_id"))
        or ledger.get("folder_staging_sha256") != folder_sha
        or ledger.get("resource_sha256") != manifest
        or len(events) != 1
    ):
        _deny()
    # Use exactly the original 0033 canonical event hash convention. A signed
    # ledger observation is committed at revision expected_revision+1.
    event = events[0]
    if not isinstance(event, Mapping):
        _deny()
    try:
        sig = base64.urlsafe_b64decode(signed["ledger_signature"] + "==")
        expected = {
            "grant_id": ledger["grant_id"],
            "epoch": ledger["epoch"],
            "revision": worker["revision"],
            "state": "running",
            "kid": worker["supervisor_kid"],
            "supervisor_id": worker["supervisor_id"],
            "observed_at": ledger["observed_at"],
            "evidence_sha256": ledger["evidence_sha256"],
            "claims_sha256": hashlib.sha256(_canonical(ledger)).hexdigest(),
            "signature_sha256": hashlib.sha256(sig).hexdigest(),
        }
        if any(event.get(key) != val for key, val in expected.items()):
            _deny()
        immutable = {
            name: binding[name]
            for name in binding
            if name not in {"binding_id", "join_sha256", "committed_at"}
        }
        if not hmac.compare_digest(
            hashlib.sha256(source_canonical(immutable)).hexdigest(), binding["join_sha256"]
        ):
            _deny()
    except SourceMap0033CurrentWitnessDenied:
        raise
    except Exception as exc:
        raise SourceMap0033CurrentWitnessDenied(
            "Invalid current SourceMap immutable ledger"
        ) from exc
    return {
        "status": "corroborated_read_only",
        "binding_id": binding["binding_id"],
        "grant_id": grant["grant_id"],
        "preflight_id": preflight["preflight_id"],
        "0033_epoch": worker["epoch"],
        "0033_revision": worker["revision"],
        "observed_mount_read_only": True,
        "authorizes_execution": False,
        "authorizes_mount_or_replay": False,
    }


class SourceMap0033CurrentWitness:
    """Read original, signed and current sources; never materialize authority."""

    _folder_plan = staticmethod(NativeMCPWorkerSupervisionStore._current_folder)

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny()
        self._actions = actions
        self._sources = SourceMapSourceAuthorityStore(actions)
        self._status = SourceMapStatusAuthorityStore(actions)
        try:
            self._roots = {
                name: _roots(env)
                for name, env in (
                    ("ledger", "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON"),
                    ("status", "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"),
                    ("process", "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON"),
                    (
                        "supervisor",
                        "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
                    ),
                    ("mount", "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON"),
                )
            }
            groups = tuple(self._roots.values())
            if any(
                set(groups[i].values()) & set(groups[j].values())
                for i in range(len(groups))
                for j in range(i + 1, len(groups))
            ):
                _deny()
        except Exception as exc:
            raise SourceMap0033CurrentWitnessDenied(
                "Independently enrolled SourceMap process and mount producers unavailable"
            ) from exc

    async def corroborate(
        self,
        *,
        supervisor_observation: dict[str, Any],
        source_status: dict[str, Any],
        source_preflight_proof: dict[str, Any],
        native_grant_token: dict[str, Any],
        live_process_witness: dict[str, Any],
        signed_supervisor_source: dict[str, Any],
        native_mount_witness: dict[str, Any],
    ) -> dict[str, Any]:
        """Read-only, non-consuming check; NEVER issue/reissue after lost ACK."""
        try:
            signed = _verify_external_proofs(
                supervisor_observation=supervisor_observation,
                source_status=source_status,
                source_preflight_proof=source_preflight_proof,
                live_process_witness=live_process_witness,
                signed_supervisor_source=signed_supervisor_source,
                native_mount_witness=native_mount_witness,
                roots=self._roots,
                now=int(time.time()),
            )
            # No valid SourceMap native grant token exists in the unchanged
            # 0029 operational verifier; this denies BEFORE any DB access.
            token_claims, _, token_sha, token_signature_sha = _verify_native(native_grant_token)
            ledger = signed["ledger"]
            status = signed["status"]
            if (
                token_claims.get("server_id") != _SOURCE
                or token_claims.get("tool_name") != _TOOL
                or token_claims.get("grant_id") != ledger["grant_id"]
                or token_claims.get("resource_sha256") != status["manifest_sha256"]
            ):
                _deny()
            request = validate_request(
                {
                    key: status[key]
                    for key in (
                        "request_id",
                        "engagement_id",
                        "task_id",
                        "server_id",
                        "tool_name",
                        "artifact_sha256",
                    )
                }
            )
            signed["ledger_signature"] = supervisor_observation["signature"]
            async with self._actions._sessions()() as db:
                async with db.begin():
                    original, manifest = await self._sources._source(db, request)
                    now = await self._sources._now(db)
                    if (
                        now >= signed["mount"]["expires_at"]
                        or now >= signed["status"]["expires_at"]
                    ):
                        _deny()

                    async def one(sql: str, bindings: Mapping[str, Any]) -> Mapping[str, Any]:
                        result = (await db.execute(text(sql), bindings)).mappings().one_or_none()
                        if not isinstance(result, Mapping):
                            _deny()
                        return dict(result)

                    base = {"action": original["action_id"], "request": original["request_id"]}
                    preflight = await one(
                        "SELECT * FROM native_sourcemap_source_preflights "
                        "WHERE action_id=:action AND request_id=:request FOR SHARE",
                        base,
                    )
                    self._status._verify_issued(
                        preflight,
                        original,
                        manifest,
                        request["artifact_sha256"],
                        current_kid=source_preflight_proof["kid"],
                        now=now,
                    )
                    binding = await one(
                        "SELECT * FROM native_sourcemap_grant_bindings "
                        "WHERE action_id=:action AND request_id=:request FOR SHARE",
                        base,
                    )
                    grant = await one(
                        "SELECT * FROM native_mcp_execution_grants WHERE grant_id=:grant FOR SHARE",
                        {"grant": ledger["grant_id"]},
                    )
                    if (
                        grant.get("claims_sha256") != token_sha
                        or grant.get("signature_sha256") != token_signature_sha
                    ):
                        _deny()
                    offer = await one(
                        "SELECT * FROM native_mcp_resource_offers WHERE grant_id=:grant FOR SHARE",
                        {"grant": ledger["grant_id"]},
                    )
                    worker = await one(
                        "SELECT * FROM native_mcp_worker_supervisions WHERE grant_id=:grant FOR SHARE",
                        {"grant": ledger["grant_id"]},
                    )
                    events = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_worker_supervision_events "
                                    "WHERE grant_id=:grant AND epoch=:epoch AND revision=:revision "
                                    "ORDER BY recorded_at DESC LIMIT 2 FOR SHARE"
                                ),
                                {
                                    "grant": ledger["grant_id"],
                                    "epoch": ledger["epoch"],
                                    "revision": worker["revision"],
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    task = await one(
                        "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:eng "
                        "AND flow_id=:flow FOR SHARE",
                        {
                            "task": original["task_id"],
                            "eng": original["engagement_id"],
                            "flow": original["flow_id"],
                        },
                    )
                    if type(task.get("payload")) is not dict:
                        _deny()
                    review = await one(
                        "SELECT * FROM flow_artifact_reviews WHERE artifact_id=:artifact "
                        "AND engagement_id=:eng AND flow_id=:flow FOR SHARE",
                        {
                            "artifact": binding["artifact_id"],
                            "eng": original["engagement_id"],
                            "flow": original["flow_id"],
                        },
                    )
                    folder_sha = await self._folder_plan(db, grant)
                    # An actual same-transaction PostgreSQL clock check AFTER
                    # all joins prevents a slow DB read from laundering an
                    # already-expired externally signed PID/mount observation.
                    final_now = await self._sources._now(db)
                    if (
                        final_now < now
                        or any(
                            final_now >= signed[name]["expires_at"]
                            for name in ("status", "source", "process", "supervisor", "mount")
                        )
                        or final_now > ledger["observed_at"] + 3
                    ):
                        _deny()
                    return _verify_current_rows(
                        original=original,
                        manifest=manifest,
                        preflight=preflight,
                        binding=binding,
                        grant=grant,
                        offer=offer,
                        worker=worker,
                        events=list(events),
                        signed=signed,
                        folder_sha=folder_sha,
                        now=final_now,
                        current_task=task["payload"],
                        review=review,
                    )
        except SourceMap0033CurrentWitnessDenied:
            raise
        except Exception as exc:
            raise SourceMap0033CurrentWitnessDenied(
                "Independent 0033/0035/0037 SourceMap witness missing or UNKNOWN"
            ) from exc
