"""Host-only binding of original SourceMap Task authority to observed PID/mount.

Only existing, independently signed proofs are verified here. The central
CURRENT_DB issuer separately rereads the original 0013/0015/0026/0027/0029/
0030/0031/0033/0035 records, Task, Flow, reviewer, ROE and lease in PostgreSQL.
This verifier binds that fresh original to an independently observed host PID,
nonroot filesystem identity and read-only mount. It cannot issue an observation,
redeem a grant, admit an Action, authorize execution or settle 0027 UNKNOWN.
The separate 0037 durable join still requires its existing central verifier.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from ai_osop.orchestrator.sourcemap_0033_current_witness import (
    _verify_external_proofs,
)
from ai_osop.orchestrator.sourcemap_original_stage import _roots
from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
    CURRENT_DB_DOMAIN,
    _DB_FIELDS,
    _verified,
)

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_ACTION = re.compile(r"action-[a-f0-9]{32}\Z")
_GRANT = re.compile(r"ngr-[a-f0-9]{32}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_SOURCE = "source-map-mcp"
_TOOL = "inspect_local_original_sourcemap"
_NATIVE_ROOT = "/run/osop-sourcemap/sourcemap-originals"
_ROOT_ENVS = {
    "ledger": "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON",
    "status": "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "process": "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
    "supervisor": "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "mount": "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
    "current_db": "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON",
}
_ORIGINAL_FIELDS = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "artifact_sha256",
    "manifest_sha256",
    "authorization_sha256",
)
_POSITIVE = (
    "source_current",
    "lease_active",
    "approval_current",
    "reviewer_current",
    "roe_current",
)


class SourceMapHostProcessJoinDenied(ValueError):
    """Original, independently verified current PID/mount authority unavailable."""


def _deny() -> None:
    raise SourceMapHostProcessJoinDenied(
        "Independent SourceMap original host process join unavailable"
    )


@dataclass(frozen=True)
class HostPinnedOriginalSourceMapTask:
    """Expected original scope, obtained from an independently trusted host.

    The consumer must supply the existing immutable original intent from its
    host-only journal; constructing this value from an HTTP request is not an
    authorization step. An unsigned value alone never yields an admission.
    """

    request_id: str
    engagement_id: str
    flow_id: str
    task_id: str
    subtask_id: str
    action_id: str
    owner_id: str
    approval_id: str
    lease_id: str
    artifact_sha256: str
    manifest_sha256: str
    authorization_sha256: str
    authorization_version: int


@dataclass(frozen=True)
class HostPinnedSourceMapMountRoot:
    """Already verified host-owned source directory inode, never from HTTP."""

    root_dev: int
    root_ino: int
    native_stage_root: str = _NATIVE_ROOT


@dataclass(frozen=True)
class VerifiedSourceMapHostProcessMount:
    """Short-lived, nontransferable *prerequisite* for the central 0037 join."""

    request_id: str
    engagement_id: str
    flow_id: str
    task_id: str
    action_id: str
    lease_id: str
    grant_id: str
    worker_id: str
    container_id: str
    epoch: int
    revision: int
    pid: int
    pid_start_ticks: int
    mount_namespace_inode: int
    native_fsuid: int
    root_dev: int
    root_ino: int
    observed_at: int
    expires_at: int

    @property
    def status(self) -> str:
        return "host_process_readonly_mount_correlated_only"

    @property
    def authorizes_execution(self) -> bool:
        return False

    @property
    def authorizes_mount_or_replay(self) -> bool:
        return False

    @property
    def native_grant_redemption_verified_here(self) -> bool:
        return False

    @property
    def durable_0037_binding_verified_here(self) -> bool:
        return False

    @property
    def target_effect_verified(self) -> bool:
        return False


def _original_intent(intent: HostPinnedOriginalSourceMapTask) -> None:
    if type(intent) is not HostPinnedOriginalSourceMapTask:
        _deny()
    if (
        type(intent.request_id) is not str
        or _REQUEST.fullmatch(intent.request_id) is None
        or type(intent.action_id) is not str
        or _ACTION.fullmatch(intent.action_id) is None
        or any(
            type(getattr(intent, field)) is not str
            or _IDENTITY.fullmatch(getattr(intent, field)) is None
            for field in (
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "owner_id",
                "approval_id",
                "lease_id",
            )
        )
        or not intent.engagement_id.startswith("eng-")
        or not intent.task_id.startswith("task-")
        or any(
            type(getattr(intent, field)) is not str
            or _SHA.fullmatch(getattr(intent, field)) is None
            for field in ("artifact_sha256", "manifest_sha256", "authorization_sha256")
        )
        or type(intent.authorization_version) is not int
        or intent.authorization_version <= 0
    ):
        _deny()


def _trusted_roots() -> dict[str, Mapping[str, bytes]]:
    """Load only host-enrolled public keys using the source's existing parser."""
    try:
        roots = {name: _roots(env) for name, env in _ROOT_ENVS.items()}
        if any(not keys for keys in roots.values()):
            _deny()
        all_keys: set[bytes] = set()
        for keys in roots.values():
            if len(set(keys.values())) != len(keys) or all_keys.intersection(keys.values()):
                _deny()
            all_keys.update(keys.values())
        return {name: MappingProxyType(dict(keys)) for name, keys in roots.items()}
    except SourceMapHostProcessJoinDenied:
        raise
    except Exception as exc:
        raise SourceMapHostProcessJoinDenied(
            "Independent host signer enrollment unavailable"
        ) from exc


def _same(first: Mapping[str, Any], second: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(
        name in first
        and name in second
        and type(first[name]) is type(second[name])
        and first[name] == second[name]
        for name in fields
    )


class SourceMapHostProcessJoin:
    """Read-only original/current process-to-mount cryptographic corroborator.

    Callers must obtain all proofs from separately enrolled trusted producers.
    This class has no DB, filesystem, process, HTTP, stage or issuer interface.
    It checks pinned host trust again before/after verification to avoid silently
    accepting a rotated enrollment or credentials from an unrelated producer.
    """

    def __init__(self, *, pinned_mount_root: HostPinnedSourceMapMountRoot) -> None:
        if (
            type(pinned_mount_root) is not HostPinnedSourceMapMountRoot
            or type(pinned_mount_root.root_dev) is not int
            or pinned_mount_root.root_dev <= 0
            or type(pinned_mount_root.root_ino) is not int
            or pinned_mount_root.root_ino <= 0
            or pinned_mount_root.native_stage_root != _NATIVE_ROOT
        ):
            _deny()
        self._host_root = pinned_mount_root
        self._roots = _trusted_roots()
        self._pins = self._fingerprints(self._roots)

    @staticmethod
    def _fingerprints(roots: Mapping[str, Mapping[str, bytes]]) -> tuple[Any, ...]:
        return tuple(
            (
                domain,
                tuple(
                    sorted(
                        (kid, hashlib.sha256(key).hexdigest()) for kid, key in roots[domain].items()
                    )
                ),
            )
            for domain in _ROOT_ENVS
        )

    def _assert_enrollment(self) -> None:
        if self._fingerprints(_trusted_roots()) != self._pins:
            _deny()

    def verify(
        self,
        *,
        original: HostPinnedOriginalSourceMapTask,
        supervisor_observation: dict[str, Any],
        source_status: dict[str, Any],
        source_preflight_proof: dict[str, Any],
        current_db_witness: dict[str, Any],
        live_process_witness: dict[str, Any],
        signed_supervisor_source: dict[str, Any],
        native_mount_witness: dict[str, Any],
    ) -> VerifiedSourceMapHostProcessMount:
        """Corroborate signed host PID/read-only mount against original Task.

        This is a host prerequisite check; 0029 redemption and 0037 bound-only
        provenance still require their own existing current database verifier.
        Failure does not allow an UNKNOWN Action or signer call to be repeated.
        """
        try:
            _original_intent(original)
            self._assert_enrollment()
            now = int(time.time())
            signed = _verify_external_proofs(
                supervisor_observation=supervisor_observation,
                source_status=source_status,
                source_preflight_proof=source_preflight_proof,
                live_process_witness=live_process_witness,
                signed_supervisor_source=signed_supervisor_source,
                native_mount_witness=native_mount_witness,
                roots=self._roots,
                now=now,
            )
            current, current_sha = _verified(
                current_db_witness,
                self._roots["current_db"],
                CURRENT_DB_DOMAIN,
                _DB_FIELDS,
            )
            ledger = signed["ledger"]
            status = signed["status"]
            process = signed["process"]
            supervisor = signed["supervisor"]
            mount = signed["mount"]
            preflight = signed["source"]
            original_claims = vars(original)
            if (
                type(current.get("version")) is not int
                or current["version"] != 1
                or current.get("status") != "running"
                or any(
                    type(current.get(flag)) is not bool or current[flag] is not True
                    for flag in _POSITIVE
                )
                or not _same(original_claims, status, _ORIGINAL_FIELDS)
                or not _same(original_claims, current, _ORIGINAL_FIELDS)
                or not _same(original_claims, preflight, _ORIGINAL_FIELDS)
                or not _same(original_claims, supervisor, _ORIGINAL_FIELDS)
                or not _same(original_claims, mount, _ORIGINAL_FIELDS)
                or status.get("authorization_version") != original.authorization_version
                or preflight.get("authorization_version") != original.authorization_version
                or status.get("server_id") != _SOURCE
                or status.get("tool_name") != _TOOL
                or current.get("signed_roe_sha256") != original.authorization_sha256
                or supervisor.get("signed_roe_sha256") != original.authorization_sha256
                or current.get("status_proof_sha256") != signed["status_sha"]
                or current.get("supervisor_observation_sha256") != signed["ledger_sha"]
                or process.get("supervisor_observation_sha256") != signed["ledger_sha"]
                or not _same(
                    current,
                    ledger,
                    ("request_id", "grant_id", "worker_id", "container_id", "epoch"),
                )
                or not _same(
                    current,
                    process,
                    ("request_id", "grant_id", "worker_id", "container_id", "epoch"),
                )
                or not _same(
                    process,
                    mount,
                    (
                        "pid",
                        "pid_start_ticks",
                        "mount_namespace_inode",
                        "native_fsuid",
                        "container_id",
                        "epoch",
                    ),
                )
                or not _same(process, supervisor, ("cgroup_sha256",))
                or type(current.get("revision")) is not int
                or current["revision"] != ledger.get("expected_revision", -2) + 1
                or current["revision"] < 2
                or type(current.get("observed_at")) is not int
                or not now - 2 <= current["observed_at"] <= now + 1
                or current["observed_at"] < ledger["observed_at"]
                or type(current.get("expires_at")) is not int
                or not now < current["expires_at"] <= current["observed_at"] + 5
                or current["expires_at"] > status["expires_at"]
                or type(process.get("native_fsuid")) is not int
                or process["native_fsuid"] <= 0
                or type(mount.get("root_dev")) is not int
                or type(mount.get("root_ino")) is not int
                or mount["root_dev"] <= 0
                or mount["root_ino"] <= 0
                or mount["root_dev"] != self._host_root.root_dev
                or mount["root_ino"] != self._host_root.root_ino
                or mount.get("read_only") is not True
                or process.get("native_stage_root") != _NATIVE_ROOT
                or supervisor.get("native_stage_root") != _NATIVE_ROOT
                or mount.get("native_stage_root") != _NATIVE_ROOT
                or type(ledger.get("grant_id")) is not str
                or _GRANT.fullmatch(ledger["grant_id"]) is None
                or type(ledger.get("worker_id")) is not str
                or _IDENTITY.fullmatch(ledger["worker_id"]) is None
            ):
                _deny()

            # A final bound after verification must still be within ALL signed
            # short-lived testimonies. This is not a durable authorization.
            final_now = int(time.time())
            expires = min(
                current["expires_at"],
                status["expires_at"],
                preflight["expires_at"],
                process["expires_at"],
                supervisor["expires_at"],
                mount["expires_at"],
                final_now + 2,
            )
            self._assert_enrollment()
            if final_now < now or final_now > current["observed_at"] + 2 or expires <= final_now:
                _deny()
            if type(current_sha) is not str or _SHA.fullmatch(current_sha) is None:
                _deny()
            return VerifiedSourceMapHostProcessMount(
                request_id=original.request_id,
                engagement_id=original.engagement_id,
                flow_id=original.flow_id,
                task_id=original.task_id,
                action_id=original.action_id,
                lease_id=original.lease_id,
                grant_id=ledger["grant_id"],
                worker_id=ledger["worker_id"],
                container_id=ledger["container_id"],
                epoch=ledger["epoch"],
                revision=current["revision"],
                pid=process["pid"],
                pid_start_ticks=process["pid_start_ticks"],
                mount_namespace_inode=process["mount_namespace_inode"],
                native_fsuid=process["native_fsuid"],
                root_dev=mount["root_dev"],
                root_ino=mount["root_ino"],
                observed_at=final_now,
                expires_at=expires,
            )
        except SourceMapHostProcessJoinDenied:
            raise
        except Exception as exc:
            raise SourceMapHostProcessJoinDenied(
                "Independent SourceMap signed process and mount corroboration unavailable"
            ) from exc


__all__ = [
    "HostPinnedOriginalSourceMapTask",
    "HostPinnedSourceMapMountRoot",
    "SourceMapHostProcessJoin",
    "SourceMapHostProcessJoinDenied",
    "VerifiedSourceMapHostProcessMount",
]
