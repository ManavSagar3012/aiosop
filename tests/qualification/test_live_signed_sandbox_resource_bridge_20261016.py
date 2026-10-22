"""Opt-in REAL Docker rootfs read-only resource handoff (NO application DB).

Runs only against an already-local python:3.11-slim image on an isolated
Docker daemon. No network, ports, mounts, files, live targets or providers.
Current Task/ROE approval is simulated by an adversarial deterministic PG
fixture; this proves sandbox bytes and Docker permissions, NOT live app PG.
"""

from __future__ import annotations

import os

import docker
import pytest

from ai_osop.core.exceptions import SandboxException
from ai_osop.memory.flow_resource_materialization import (
    SignedFlowTaskResources,
    TaskResourceBinding,
)
from ai_osop.safety.approval_binding import pinned_evidence
from ai_osop.safety.scope import SandboxManager
from tests.test_signed_sandbox_resource_delivery_20261016 import _Artifacts, source


@pytest.mark.asyncio
async def test_live_disposable_readonly_signed_resource_delivery(monkeypatch):
    if os.environ.get("OSOP_DISPOSABLE_RESOURCE_BRIDGE_DOCKER") != "1":
        pytest.skip("Explicit disposable Docker resource qualification opt-in required")

    # An entirely disposable *standalone* lab worker. Never use an existing
    # sandbox/app container, user database, Docker volume, network or mount.
    name = "osop-live-resource-bridge-20261016"
    cli = docker.from_env()
    if cli.containers.list(all=True, filters={"name": name}):
        pytest.skip("Reserved disposable resource container name already in use")
    cli.images.get("python:3.11-slim")  # Never silently pull external images.

    binding, verifier, rows, _db = source.__wrapped__(monkeypatch)
    artifact = _Artifacts(binding)
    binding = TaskResourceBinding(**{**binding.__dict__, "artifact_sha256": artifact.digest})
    rows["tasks"]["payload"]["resource_artifact_sha256"] = artifact.digest
    rows["approval_requests"]["evidence"] = pinned_evidence([], rows["tasks"]["payload"])
    reader = SignedFlowTaskResources(artifact, verifier)

    container = None
    manager = SandboxManager()
    try:
        container = cli.containers.run(
            "python:3.11-slim",
            command=["sleep", "75"],
            detach=True,
            remove=False,
            name=name,
            network_mode="none",
            read_only=True,
            user="65534:65534",
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=32,
            mem_limit="128m",
            tmpfs={"/run/ai-osop/resources": "rw,noexec,nosuid,nodev,size=8m,mode=0700"},
            volumes={},
            ports={},
        )
        manager._active_sandboxes["resource-qualification"] = {
            "id": "resource-qualification",
            "status": "ready",
            "container_id": container.id,
            "network": None,
        }
        receipt = await manager.provision_approved_flow_resource(
            "resource-qualification", binding, reader
        )
        assert receipt["status"] == "materialized_untrusted_read_only"
        assert receipt["sha256"] == artifact.digest
        assert receipt["approved_for_agent_instructions"] is False

        # The actual unprivileged sandbox command is independently approved
        # in the pinned human Task payload, not an LLM-written invocation.
        observed = await manager.execute_in_sandbox(
            "resource-qualification", ["cat", "/run/ai-osop/resources/notes.txt"]
        )
        assert observed["status"] == "success"
        assert observed["stdout"].encode() == artifact.original

        # The worker (uid 65534) cannot undo root-only chmod/read-only file.
        tamper = container.exec_run(["sh", "-c", "echo changed > /run/ai-osop/resources/notes.txt"])
        assert tamper.exit_code != 0

        # An approval revoked after provisioning closes future execution.
        rows["approval_requests"]["status"] = "rejected"
        with pytest.raises(SandboxException):
            await manager.execute_in_sandbox(
                "resource-qualification", ["cat", "/run/ai-osop/resources/notes.txt"]
            )
        assert "resource-qualification" not in manager._active_sandboxes
    finally:
        if container is not None:
            try:
                container.reload()
                if container.status == "running":
                    container.stop(timeout=3)
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
