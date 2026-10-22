"""Executable authorization and resource-to-sandbox tests; no real DB/Docker."""

from __future__ import annotations

import io
import tarfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import docker
import pytest

from ai_osop.core.exceptions import SandboxException
from ai_osop.memory.authoritative_task_resources import (
    PostgresApprovedTaskResourceVerifier,
)
from ai_osop.memory.flow_resource_materialization import (
    ResourceAdmissionDenied,
    SignedFlowTaskResources,
    TaskResourceBinding,
)
from ai_osop.safety.approval_binding import pinned_evidence
from ai_osop.safety.scope import SandboxManager


class _Rows:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class _Tx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class _DB:
    def __init__(self, rows):
        self.rows = rows
        self.names = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def begin(self):
        return _Tx()

    async def execute(self, statement, parameters):
        sql = str(statement)
        for name in (
            "session_states",
            "execution_flows",
            "tasks",
            "approval_requests",
            "execution_subtasks",
            "supervision_execution_leases",
        ):
            if f"FROM {name} " in sql:
                self.names.append(name)
                return _Rows(self.rows.get(name))
        raise AssertionError("Unexpected SQL query")


@pytest.fixture
def source(monkeypatch):
    digest = "a" * 64
    file_digest = "c" * 64
    binding = TaskResourceBinding(
        engagement_id="eng-owned",
        flow_id="flow-owned",
        owner_id="owner-1",
        task_id="task-approved",
        flow_revision=3,
        authorization_version=2,
        authorization_sha256=digest,
        artifact_id="artifact-" + "b" * 32,
        artifact_sha256=file_digest,
    )
    payload = {
        "_authorization_version": 2,
        "_flow_revision": 3,
        "target": "https://example.com/",
        "resource_artifact_id": binding.artifact_id,
        "resource_artifact_sha256": binding.artifact_sha256,
        "resource_authorization_sha256": digest,
        "resource_command_sha256": SandboxManager._command_sha256(
            ["cat", "/run/ai-osop/resources/notes.txt"]
        ),
        "operator_approved": True,
        "approval_id": "approval-1",
    }
    rows = {
        "session_states": {
            "created_by": binding.owner_id,
            "phase": "reconnaissance",
            "scope": {"engagement_id": binding.engagement_id, "domains": ["example.com"]},
        },
        "execution_flows": {
            "id": binding.flow_id,
            "engagement_id": binding.engagement_id,
            "status": "running",
            "revision": 3,
        },
        "tasks": {
            "id": binding.task_id,
            "engagement_id": binding.engagement_id,
            "flow_id": binding.flow_id,
            "type": "read_flow_resource",
            "status": "running",
            "assigned_agent_id": "agent-resource-claim",
            "started_at": datetime.utcnow() - timedelta(seconds=10),
            "completed_at": None,
            "scope_check": True,
            "approval_required": True,
            "subtask_id": "subtask-1",
            "payload": payload,
        },
        "approval_requests": {
            "id": "approval-1",
            "task_id": binding.task_id,
            "engagement_id": binding.engagement_id,
            "action_type": "read_flow_resource",
            "target": payload["target"],
            "status": "approved",
            "operator_id": "senior-2",
            "responded_at": datetime.now(timezone.utc),
            "evidence": pinned_evidence([], payload),
        },
        "execution_subtasks": {
            "id": "subtask-1",
            "engagement_id": binding.engagement_id,
            "flow_id": binding.flow_id,
            "execution_task_id": binding.task_id,
            "status": "running",
        },
        "supervision_execution_leases": {
            "engagement_id": binding.engagement_id,
            "task_id": binding.task_id,
            "lease_id": "lease-resource-claim",
            "owner_id": "worker-resource-owner",
            "state": "dispatched",
            "expires_at": datetime.utcnow() + timedelta(minutes=5),
        },
    }
    db = _DB(rows)

    async def guard(_db, eng, expected_version=None, expected_digest=None):
        if expected_version != binding.authorization_version or expected_digest != digest:
            raise ValueError("Stale signed ROE")
        return SimpleNamespace(
            session_id=eng,
            version=2,
            policy_sha256=digest,
            policy={"created_by": binding.owner_id},
        )

    import ai_osop.memory.authoritative_task_resources as target

    monkeypatch.setattr(target, "guard_sql", guard)
    verifier = PostgresApprovedTaskResourceVerifier(SimpleNamespace(_async_session=lambda: db))
    return binding, verifier, rows, db


@pytest.mark.asyncio
async def test_real_callback_rechecks_postgres_approval_and_original_flow(source):
    binding, verifier, _, db = source
    result = await verifier(binding)
    assert result["approved"] and result["active"]
    assert result["task_id"] == binding.task_id
    assert db.names == [
        "session_states",
        "execution_flows",
        "tasks",
        "approval_requests",
        "execution_subtasks",
        "supervision_execution_leases",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table,key,value",
    [
        ("session_states", "created_by", "other-owner"),
        ("session_states", "phase", "halted"),
        ("execution_flows", "revision", 4),
        ("execution_flows", "status", "completed"),
        ("execution_flows", "status", "pending"),
        ("tasks", "status", "awaiting_approval"),
        ("tasks", "assigned_agent_id", None),
        ("tasks", "started_at", None),
        ("tasks", "completed_at", datetime.utcnow()),
        ("tasks", "approval_required", False),
        ("approval_requests", "status", "revoked"),
        ("approval_requests", "operator_id", None),
        ("execution_subtasks", "execution_task_id", "task-other"),
        ("supervision_execution_leases", "state", "reserved"),
        ("supervision_execution_leases", "state", "released"),
        ("supervision_execution_leases", "lease_id", "forged"),
        ("supervision_execution_leases", "owner_id", ""),
        ("supervision_execution_leases", "expires_at", datetime.utcnow() - timedelta(seconds=1)),
    ],
)
async def test_durable_signed_scope_and_approval_fail_closed(source, table, key, value):
    binding, verifier, rows, _ = source
    rows[table][key] = value
    with pytest.raises(ResourceAdmissionDenied):
        await verifier(binding)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key",
    [
        "resource_artifact_id",
        "resource_artifact_sha256",
        "resource_authorization_sha256",
        "resource_command_sha256",
    ],
)
async def test_unsigned_or_unapproved_artifact_not_granted(source, key):
    binding, verifier, rows, _ = source
    rows["tasks"]["payload"][key] = "replaced"
    with pytest.raises(ResourceAdmissionDenied):
        await verifier(binding)


@pytest.mark.asyncio
async def test_unclaimed_or_missing_lease_blocks_resource_bytes(source):
    binding, verifier, rows, db = source
    rows.pop("supervision_execution_leases")
    with pytest.raises(ResourceAdmissionDenied, match="lease"):
        await verifier(binding)
    assert db.names[-1] == "supervision_execution_leases"


@pytest.mark.asyncio
@pytest.mark.parametrize("revision", [None, 4, True])
async def test_unpinned_or_changed_flow_revision_denied(source, revision):
    binding, verifier, rows, _ = source
    rows["tasks"]["payload"]["_flow_revision"] = revision
    with pytest.raises(ResourceAdmissionDenied):
        await verifier(binding)


@pytest.mark.asyncio
async def test_post_approval_payload_mutation_cannot_use_old_evidence(source):
    binding, verifier, rows, _ = source
    rows["tasks"]["payload"]["extra_tool_argument"] = "changed"
    with pytest.raises(ResourceAdmissionDenied):
        await verifier(binding)


class _Artifacts:
    def __init__(self, binding):
        self.binding = binding
        self.original = b"safe reference notes\n"
        import hashlib

        self.digest = hashlib.sha256(self.original).hexdigest()

    async def read(self, flow_id, artifact_id, owner_id, revision, version):
        return {
            "id": artifact_id,
            "flow_id": flow_id,
            "sha256": self.digest,
            "name": "notes.txt",
            "authorization_version": version,
            "flow_revision": revision,
        }, self.original


class _Container:
    def __init__(self):
        self.archive = b""
        self.tamper = False
        self.transfer_failed = False

    def exec_run(self, command, **kwargs):
        if command[:2] == ["python3", "-c"]:
            import hashlib

            assert command[3] == "notes.txt"
            assert kwargs["user"] == "65534:65534"
            assert kwargs["privileged"] is False and kwargs["demux"] is True
            content = b"tampered" if self.tamper else self.archive
            receipt = (hashlib.sha256(content).hexdigest() + ":" + str(len(content)) + "\n").encode(
                "ascii"
            )
            return SimpleNamespace(exit_code=0, output=(receipt, None))
        return SimpleNamespace(exit_code=0, output=(b"safe reference notes\n", b""))

    def put_archive(self, destination, archive):
        raise AssertionError("Docker archive upload must never run on read-only rootfs")

    def get_archive(self, path):
        raise AssertionError("Docker read-only rootfs cannot use GET /archive on tmpfs")


class _Socket:
    def __init__(self, container):
        self.container = container
        self.closed = False

    def sendall(self, content):
        assert isinstance(content, bytes)
        self.container.archive = content

    def close(self):
        self.closed = True


class _Api:
    def __init__(self, container):
        self.container = container

    def exec_create(self, container_id, command, **options):
        assert container_id == "container-1"
        assert command[0:2] == ["python3", "-c"]
        assert options["stdin"] is True and options["user"] == "0:0"
        assert options["privileged"] is False
        assert options["stdout"] is False and options["stderr"] is False
        assert command[3] == "notes.txt"
        assert len(command) == 6
        assert command[4].isdecimal()
        assert len(command[5]) == 64
        assert "safe reference notes" not in str(command)
        return {"Id": "only-signed-transfer"}

    def exec_start(self, exec_id, **options):
        assert exec_id == "only-signed-transfer"
        assert options == {"socket": True, "tty": False}
        return _Socket(self.container)

    def exec_inspect(self, exec_id):
        assert exec_id == "only-signed-transfer"
        return {
            "Running": False,
            "Pid": 12345,
            "ExitCode": 1 if self.container.transfer_failed else 0,
        }


@pytest.fixture
def sandbox(source, monkeypatch):
    binding, verifier, rows, _ = source
    art = _Artifacts(binding)
    import hashlib

    binding = TaskResourceBinding(**{**binding.__dict__, "artifact_sha256": art.digest})
    rows["tasks"]["payload"]["resource_artifact_sha256"] = binding.artifact_sha256
    rows["approval_requests"]["evidence"] = pinned_evidence([], rows["tasks"]["payload"])
    reader = SignedFlowTaskResources(art, verifier)
    container = _Container()
    client = SimpleNamespace(
        containers=SimpleNamespace(get=lambda _id: container), api=_Api(container)
    )
    monkeypatch.setattr(docker, "from_env", lambda: client)
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {
        "container_id": "container-1",
        "status": "ready",
        "network": None,
    }
    removed = []

    async def destroy(identifier):
        removed.append(identifier)
        manager._active_sandboxes.pop(identifier, None)

    manager.destroy_sandbox = destroy
    return manager, container, reader, binding, rows, removed


@pytest.mark.asyncio
async def test_approved_original_flow_resource_is_materialized_and_readback(sandbox):
    manager, _, reader, binding, _, removed = sandbox
    response = await manager.provision_approved_flow_resource("sb-1", binding, reader)
    assert response["status"] == "materialized_untrusted_read_only"
    assert response["approved_for_agent_instructions"] is False
    assert not removed


@pytest.mark.asyncio
async def test_tampered_container_readback_stops_sandbox_before_command(sandbox):
    manager, container, reader, binding, _, removed = sandbox
    container.tamper = True
    with pytest.raises(SandboxException):
        await manager.provision_approved_flow_resource("sb-1", binding, reader)
    assert removed == ["sb-1"]


@pytest.mark.asyncio
async def test_daemon_side_writer_failure_denied_and_container_stopped(sandbox):
    manager, container, reader, binding, _, removed = sandbox
    container.transfer_failed = True
    with pytest.raises(SandboxException):
        await manager.provision_approved_flow_resource("sb-1", binding, reader)
    assert removed == ["sb-1"]


@pytest.mark.asyncio
async def test_revoked_approval_after_mount_stops_sandbox_before_execution(sandbox):
    manager, _, reader, binding, rows, removed = sandbox
    await manager.provision_approved_flow_resource("sb-1", binding, reader)
    rows["approval_requests"]["status"] = "rejected"
    with pytest.raises(SandboxException):
        await manager.execute_in_sandbox("sb-1", ["cat", "/run/ai-osop/resources/notes.txt"])
    assert removed == ["sb-1"]


@pytest.mark.asyncio
async def test_exact_human_approved_argv_required_before_sandbox_execution(sandbox):
    manager, _, reader, binding, _, removed = sandbox
    await manager.provision_approved_flow_resource("sb-1", binding, reader)
    approved_argv = ["cat", "/run/ai-osop/resources/notes.txt"]
    result = await manager.execute_in_sandbox("sb-1", approved_argv)
    assert result["status"] == "success"
    assert not removed
    with pytest.raises(SandboxException):
        await manager.execute_in_sandbox(
            "sb-1", ["sh", "-c", "cat /run/ai-osop/resources/notes.txt"]
        )
    assert removed == ["sb-1"]


@pytest.mark.asyncio
async def test_approval_revoked_during_remote_exec_returns_unknown_without_stdout(sandbox):
    manager, container, reader, binding, rows, removed = sandbox
    await manager.provision_approved_flow_resource("sb-1", binding, reader)
    run = container.exec_run

    def revoke_on_exec(command, **kwargs):
        result = run(command, **kwargs)
        if command == ["cat", "/run/ai-osop/resources/notes.txt"]:
            rows["approval_requests"]["status"] = "rejected"
        return result

    container.exec_run = revoke_on_exec
    result = await manager.execute_in_sandbox("sb-1", ["cat", "/run/ai-osop/resources/notes.txt"])
    assert result == {
        "status": "UNKNOWN",
        "error": "sandbox_authority_changed_during_remote_execution",
        "execution_time": result["execution_time"],
    }
    assert "stdout" not in result and "stderr" not in result
    assert removed == ["sb-1"]
