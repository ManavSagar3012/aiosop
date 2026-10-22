"""Non-executing, PostgreSQL-backed operator preflight for a *prepared* MCP Action.

This is not an approval, capability token, budget reservation or assurance that a
later network call will succeed.  The actual executor/store must repeat every
authority check at reservation/dispatch.  Never return stored tool parameters.
"""

from __future__ import annotations

import hmac
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.core.config import settings
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.mcp.tool_budget import _declared_targets
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    _ACTION,
    _SHA,
    _binding,
    _id,
    _safe_parameters,
)
from ai_osop.memory.flow_resource_folders import FlowResourceFolders
from ai_osop.orchestrator.flow_mcp_action_executor import (
    FlowMCPActionExecutor,
    _bounded_params,
    _tool_definition,
)
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets


class _Reject(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


_REASONS = {
    "invalid_request": "Complete bounded signed Action identity is required",
    "signed_flow_denied": "Current signed owner, Flow or rules of engagement unavailable",
    "action_unavailable": "Exact prepared Action is unavailable or no longer eligible",
    "approval_denied": "Current independently approved Task, Subtask or lease unavailable",
    "declaration_denied": "Initialized scope-checked READ_ONLY tool declaration unavailable",
    "parameters_denied": "Prepared immutable tool parameters or approved digest differ",
    "scope_denied": "Prepared target differs from approved in-scope Task target",
    "resource_denied": "Current immutable resource assignment or senior review unavailable",
    "source_unavailable": "Authoritative preflight data unavailable",
}


def _deny(code: str) -> _Reject:
    return _Reject(code, _REASONS[code])


def _sha(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _resource_pointer(payload: Mapping[str, Any], expected_manifest: str | None) -> dict | None:
    """Only a human-approved Task payload may name a resource; never caller JSON.

    Established signed Task resource keys are used for the immutable artifact.
    A virtual-folder assignment requires the additional mcp_resource_binding
    (folder_id, manifest_sha256, catalog_revision), rather than a guessed path.
    """
    keys = (
        "resource_artifact_id",
        "resource_artifact_sha256",
        "resource_authorization_sha256",
        "resource_command_sha256",
    )
    has_resource = any(k in payload for k in keys) or "mcp_resource_binding" in payload
    if not has_resource:
        # The caller's manifest hint must never conjure a resource binding.
        return None
    artifact_id = payload.get("resource_artifact_id")
    digest = payload.get("resource_artifact_sha256")
    if (
        type(artifact_id) is not str
        or len(artifact_id) != 41
        or not artifact_id.startswith("artifact-")
        or not all(c in "0123456789abcdef" for c in artifact_id[9:])
        or not _sha(digest)
        or not _sha(payload.get("resource_authorization_sha256"))
        or not _sha(payload.get("resource_command_sha256"))
    ):
        raise _deny("resource_denied")
    folder = payload.get("mcp_resource_binding")
    if folder is not None and (
        type(folder) is not dict
        or set(folder) != {"folder_id", "manifest_sha256", "catalog_revision"}
        or type(folder.get("folder_id")) is not str
        or not folder["folder_id"].startswith("folder-")
        or len(folder["folder_id"]) != 39
        or not all(c in "0123456789abcdef" for c in folder["folder_id"][7:])
        or not _sha(folder.get("manifest_sha256"))
        or type(folder.get("catalog_revision")) is not int
        or folder["catalog_revision"] < 0
    ):
        raise _deny("resource_denied")
    manifest = folder.get("manifest_sha256") if folder else expected_manifest
    if (
        not _sha(manifest)
        or not _sha(expected_manifest)
        or not hmac.compare_digest(manifest, expected_manifest)
    ):
        raise _deny("resource_denied")
    return {
        "artifact_id": artifact_id,
        "artifact_sha256": digest,
        "folder": folder,
        "manifest_sha256": manifest,
    }


class FlowMCPActionApprovalPreflight:
    """Never invoke provider, reserve a lease, issue approval, or expose bytes."""

    def __init__(self, executor: FlowMCPActionExecutor, store: FlowMCPActionStore) -> None:
        if (
            not isinstance(executor, FlowMCPActionExecutor)
            or not isinstance(store, FlowMCPActionStore)
            or executor.store is not store
            or executor.memory is not store.memory
            or executor.registry is not store.registry
        ):
            raise ValueError("Production Flow MCP executor and durable store required")
        self.executor = executor
        self.store = store

    async def _resource(self, db: Any, b: dict, owner: str, pointer: dict) -> None:
        resource_binding = {**b, "manifest_sha256": pointer["manifest_sha256"]}
        # The catalog is reconstructed from original immutable PostgreSQL bytes,
        # and validated against the exact signed source manifest, not from a
        # caller-supplied folder listing or a provider's claimed file path.
        source = await FlowResourceFolders._snapshot(db, resource_binding, owner)
        resources = [i for i in source["items"] if i["artifact_id"] == pointer["artifact_id"]]
        if len(resources) != 1 or not hmac.compare_digest(
            resources[0]["sha256"], pointer["artifact_sha256"]
        ):
            raise _deny("resource_denied")
        await FlowResourceFolders._approved_review(
            db, resource_binding, owner, pointer["artifact_id"], pointer["artifact_sha256"]
        )
        # The folder service checks explicit senior decisions, but its historic
        # reviewer-control lookup treats missing rows as unknown. A *current*
        # admission cannot use a missing/disabled senior in deployments with
        # durable subject revocation: require an enabled row in this snapshot.
        if settings.operator_revocation_required:
            signed_reviewer = (
                (
                    await db.execute(
                        text(
                            "SELECT reviewer_sub FROM flow_artifact_reviews WHERE "
                            "artifact_id=:artifact AND engagement_id=:eng AND flow_id=:flow FOR SHARE"
                        ),
                        {
                            "artifact": pointer["artifact_id"],
                            "eng": b["engagement_id"],
                            "flow": b["flow_id"],
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                signed_reviewer is None
                or type(signed_reviewer.get("reviewer_sub")) is not str
                or signed_reviewer["reviewer_sub"] == owner
            ):
                raise _deny("resource_denied")
            reviewer_active = (
                await db.execute(
                    text(
                        "SELECT disabled FROM operator_subject_controls "
                        "WHERE actor_id=:actor FOR SHARE"
                    ),
                    {"actor": signed_reviewer["reviewer_sub"]},
                )
            ).scalar_one_or_none()
            if reviewer_active is not False:
                raise _deny("resource_denied")
        if pointer["folder"] is not None:
            catalog = await FlowResourceFolders._catalog_row(
                db, resource_binding, owner, create=False
            )
            if catalog is None or catalog["revision"] != pointer["folder"]["catalog_revision"]:
                raise _deny("resource_denied")
            folders, assignments = await FlowResourceFolders._rows(db, resource_binding)
            view = FlowResourceFolders._representation(
                resource_binding, catalog["revision"], source, folders, assignments
            )
            matches = [
                item
                for folder in view["folders"]
                if folder["folder_id"] == pointer["folder"]["folder_id"]
                for item in folder["items"]
                if item["artifact_id"] == pointer["artifact_id"]
                and item["artifact_sha256"] == pointer["artifact_sha256"]
            ]
            if len(matches) != 1:
                raise _deny("resource_denied")

    async def check(
        self,
        binding: dict[str, Any],
        operator: dict[str, Any],
        *,
        action_id: str,
        task_id: str,
        subtask_id: str,
        server_id: str,
        tool_name: str,
        expected_parameters_sha256: str | None = None,
        expected_manifest_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Read-only verification of an *existing* prepared Action, not execution.

        Safe for GET routing: accepts IDs and SHA only, never raw arguments.
        The actual arguments are read inside the source PostgreSQL transaction.
        """
        result: dict[str, Any] = {
            "allowed": False,
            "code": "source_unavailable",
            "reason": _REASONS["source_unavailable"],
            "read_only": True,
            "provider_contacted": False,
            "approval_issued": False,
            "dispatch_performed": False,
            "reservation_performed": False,
            "guarantees_future_dispatch": False,
        }
        stage = "invalid_request"
        try:
            b = _binding(binding)
            _id(action_id, _ACTION)
            for value in (task_id, subtask_id, server_id, tool_name):
                _id(value)
            if expected_parameters_sha256 is not None and not _sha(expected_parameters_sha256):
                raise _deny("invalid_request")
            if expected_manifest_sha256 is not None and not _sha(expected_manifest_sha256):
                raise _deny("invalid_request")
            if type(operator) is not dict or type(operator.get("sub")) is not str:
                raise _deny("invalid_request")

            # Request-local copy: the executor normalizes missing signed fields.
            stage = "signed_flow_denied"
            await self.executor._authority(b, operator)
            owner = operator["sub"]

            stage = "declaration_denied"
            declaration = _tool_definition(self.store.registry, server_id, tool_name)
            if declaration.side_effect_class is not SideEffectClass.READ_ONLY:
                raise _deny("declaration_denied")
            digest = self.store.declaration_sha256(declaration, server_id)

            stage = "action_unavailable"
            async with self.store._sessions()() as db:
                async with db.begin():
                    stage = "signed_flow_denied"
                    session = await self.store._authority(db, b, owner, dispatch=True)
                    await FlowArtifactReviewStore._reviewer_fence(
                        db,
                        reviewer_sub=owner,
                        reviewer_token_sha256=operator.get("token_sha256"),
                        reviewer_expires_at=operator["claims"]["exp"],
                    )
                    if settings.operator_revocation_required:
                        current_owner = (
                            await db.execute(
                                text(
                                    "SELECT disabled FROM operator_subject_controls "
                                    "WHERE actor_id=:actor FOR SHARE"
                                ),
                                {"actor": owner},
                            )
                        ).scalar_one_or_none()
                        if current_owner is not False:
                            raise _deny("signed_flow_denied")
                    stage = "action_unavailable"
                    row = await self.store._row(db, action_id, lock=True)
                    if row is None:
                        raise _deny("action_unavailable")
                    self.store._same(row, b, owner)
                    if (
                        row["status"] != "prepared"
                        or row["cancel_requested"] is not False
                        or row["task_id"] != task_id
                        or row["subtask_id"] != subtask_id
                        or row["server_id"] != server_id
                        or row["tool_name"] != tool_name
                        or row["side_effect_class"] != SideEffectClass.READ_ONLY.value
                        or not hmac.compare_digest(row["declaration_sha256"], digest)
                        or (
                            expected_parameters_sha256 is not None
                            and not hmac.compare_digest(
                                row["parameters_sha256"], expected_parameters_sha256
                            )
                        )
                    ):
                        raise _deny("action_unavailable")

                    stage = "parameters_denied"
                    safe = _safe_parameters(row["safe_parameters"], declaration)
                    strict = _bounded_params(safe, declaration)
                    if strict != safe or not hmac.compare_digest(
                        self.store.parameters_sha256(safe), row["parameters_sha256"]
                    ):
                        raise _deny("parameters_denied")
                    scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
                    scope.validate_time_window()

                    stage = "approval_denied"
                    approval = await self.store._approved_task(
                        db,
                        b,
                        owner,
                        task_id,
                        subtask_id,
                        server_id,
                        tool_name,
                        digest,
                        row["parameters_sha256"],
                        SideEffectClass.READ_ONLY.value,
                        scope,
                    )
                    if any(
                        row[field] != approval[field]
                        for field in ("action_id", "approval_id", "lease_id", "lease_owner_id")
                    ):
                        raise _deny("approval_denied")
                    task = (
                        (
                            await db.execute(
                                text(
                                    "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:eng "
                                    "AND flow_id=:flow FOR SHARE"
                                ),
                                {"task": task_id, "eng": b["engagement_id"], "flow": b["flow_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if task is None or type(task.get("payload")) is not dict:
                        raise _deny("approval_denied")
                    payload = task["payload"]
                    stage = "scope_denied"
                    targets = _declared_targets(safe)
                    approved_targets = _declared_targets(payload)
                    if (
                        not targets
                        or not approved_targets
                        or not all(
                            type(t) is str and t in approved_targets.values()
                            for t in targets.values()
                        )
                    ):
                        raise _deny("scope_denied")
                    validate_payload_targets(scope, targets, require_target=True)

                    stage = "resource_denied"
                    pointer = _resource_pointer(payload, expected_manifest_sha256)
                    if pointer is not None:
                        if not hmac.compare_digest(
                            payload["resource_authorization_sha256"], b["authorization_sha256"]
                        ):
                            raise _deny("resource_denied")
                        await self._resource(db, b, owner, pointer)

                    return {
                        **result,
                        "allowed": True,
                        "code": "preflight_eligible",
                        "reason": "Existing prepared Action passes current read-only authority checks",
                        "flow_id": b["flow_id"],
                        "action_id": action_id,
                        "task_id": task_id,
                        "subtask_id": subtask_id,
                        "action_status": "prepared",
                        "declaration_sha256": digest,
                        "parameters_sha256": row["parameters_sha256"],
                        "resource_bound": pointer is not None,
                        "resource_artifact_sha256": (
                            pointer["artifact_sha256"] if pointer else None
                        ),
                    }
        except _Reject as error:
            code = error.code
        except Exception:
            # Absolutely no exception text, SQL statement, Task payload, tool
            # parameter, credential or target URL escapes this boundary.
            code = stage
        return {**result, "code": code, "reason": _REASONS[code]}
