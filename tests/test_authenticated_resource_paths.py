"""Real PlaywrightAgent HAR extraction path, without browser/network/app DB.

The browser provider's remote path is never assumed to exist locally.
Signed capture -> terminal PostgreSQL parent -> extract requires a configured
operator-owned shared mount and same-tenant, same-path authorization.
"""

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.authenticated_resource_paths import (
    MAX_HAR_BYTES,
    ResourcePathDenied,
    snapshot_local_har,
)

SID = "eng-har-a"
OTHER = "eng-har-b"
CAPTURE = "task-har-capture"
EXTRACT = "task-har-extract"
PATH = "captures/user-a.har"
VERSION = 3


def _har(url="https://example.test/api/profile"):
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": url,
                        "method": "GET",
                        "headers": [],
                        "queryString": [],
                    },
                    "response": {"status": 200, "headers": [], "content": {"size": 0}},
                }
            ],
        },
    }


@pytest.fixture
def resources(tmp_path, monkeypatch):
    root = tmp_path / "trusted-mount"
    manual = tmp_path / "manual-imports"
    for parent in (root, manual):
        for sid in (SID, OTHER):
            (parent / sid / "captures").mkdir(parents=True)
            (parent / sid / PATH).write_text(json.dumps(_har()), encoding="utf-8")
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_ROOT", str(root))
    monkeypatch.setenv("OSOP_MANUAL_HAR_ROOT", str(manual))
    return SimpleNamespace(root=root, manual=manual)


@pytest.fixture
def workflow(resources):
    capture = Task(
        id=CAPTURE,
        engagement_id=SID,
        agent_type=AgentType.WORKFLOW,
        type="capture_authenticated_surface",
        status="completed",
        payload={
            "_authorization_version": VERSION,
            "workflow_id": "wf-1",
            "user_label": "user-a",
            "url": "https://example.test/",
        },
        result={
            "status": "success",
            "har_path": PATH,
            "resource_sha256": hashlib.sha256(
                (resources.root / SID / PATH).read_bytes()
            ).hexdigest(),
        },
    )
    child = Task(
        id=EXTRACT,
        engagement_id=SID,
        agent_type=AgentType.WORKFLOW,
        type="extract_har_api_inventory",
        status="running",
        parent_task_id=CAPTURE,
        dependencies=[CAPTURE],
        payload={
            "_authorization_version": VERSION,
            "workflow_id": "wf-1",
            "user_label": "user-a",
            "har_path": PATH,
        },
    )
    tasks = {capture.id: capture, child.id: child}
    memory = SimpleNamespace(
        load_task_authoritative=AsyncMock(side_effect=lambda task_id: tasks.get(task_id)),
        assert_signed_authorization=AsyncMock(
            return_value=SimpleNamespace(version=VERSION),
        ),
        load_session_state=AsyncMock(
            return_value=SimpleNamespace(
                session_id=SID,
                phase="reconnaissance",
                scope=SimpleNamespace(
                    authorization_ref="signed-policy",
                    domains=["example.test"],
                    ips=[],
                ),
            )
        ),
    )
    graph = SimpleNamespace(add_endpoint=AsyncMock())
    ctx = AgentContext(
        agent_id="har-test-agent",
        agent_type=AgentType.WORKFLOW,
        session_id=SID,
        session_memory=memory,
        graph_memory=graph,
        vector_memory=AsyncMock(),
        llm_client=AsyncMock(),
        mcp_registry=AsyncMock(),
        rate_limiter=AsyncMock(),
        threat_intel_adapter=AsyncMock(),
        audit_callback=AsyncMock(),
        coordination_bus=AsyncMock(),
    )
    ctx.current_task = child
    return SimpleNamespace(
        agent=PlaywrightAgent(ctx),
        capture=capture,
        child=child,
        tasks=tasks,
        memory=memory,
        graph=graph,
        resources=resources,
    )


def _pin_signed_happy_path_mount(fx, monkeypatch):
    """An independent operator-pinned descriptor, not provider path trust."""
    image_sha256 = "4" * 64
    descriptor = {
        "engagement_id": SID,
        "mount_id": "har-test-shared-volume",
        "container_image_sha256": image_sha256,
    }
    attestation = fx.resources.root / SID / ".osop-har-mount.json"
    blob = json.dumps(descriptor, separators=(",", ":")).encode("utf-8")
    attestation.write_bytes(blob)
    mount_sha256 = hashlib.sha256(blob).hexdigest()
    monkeypatch.setenv(
        "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
        json.dumps({SID: mount_sha256}),
    )
    fx.capture.result["mount_sha256"] = mount_sha256
    fx.capture.result["container_image_sha256"] = image_sha256
    return mount_sha256, image_sha256


@pytest.mark.asyncio
async def test_real_signed_extract_uses_shared_tenant_snapshot_and_scope(workflow, monkeypatch):
    fx = workflow
    _pin_signed_happy_path_mount(fx, monkeypatch)
    # Calling _execute dispatches to the real PlaywrightAgent branch.
    result = await fx.agent._execute(fx.child)
    assert result["status"] == "success"
    assert result["endpoints_extracted"] == 1
    assert result["endpoints_persisted"] == 1
    assert result["resource_origin"] == "operator_shared_tenant_mount"
    assert len(result["resource_sha256"]) == 64
    endpoint = fx.graph.add_endpoint.await_args.args[0]
    assert endpoint.engagement_id == SID
    assert endpoint.host == "example.test"
    assert fx.memory.assert_signed_authorization.await_count == 2


@pytest.mark.asyncio
async def test_signed_extractor_never_widens_durable_scope(workflow, monkeypatch):
    fx = workflow
    _pin_signed_happy_path_mount(fx, monkeypatch)
    (fx.resources.root / SID / PATH).write_text(
        json.dumps(_har("https://forbidden.test/private")),
        encoding="utf-8",
    )
    fx.capture.result["resource_sha256"] = hashlib.sha256(
        (fx.resources.root / SID / PATH).read_bytes()
    ).hexdigest()
    fx.child.payload["scope_hosts"] = ["forbidden.test"]
    result = await fx.agent._execute(fx.child)
    assert result["endpoints_extracted"] == 0
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "wrong_parent",
        "other_tenant",
        "unfinished",
        "unknown",
        "parent_wrong_path",
        "parent_wrong_tenant",
        "wrong_label",
        "wrong_workflow",
        "missing_signed_version",
        "revoked",
        "unclaimed_child",
    ],
)
async def test_signed_recovered_child_refuses_untrusted_parent_or_policy(workflow, tamper):
    fx = workflow
    if tamper == "wrong_parent":
        fx.child.parent_task_id = "task-not-authenticated"
    elif tamper == "other_tenant":
        fx.child.engagement_id = OTHER
    elif tamper in ("unfinished", "unknown"):
        fx.capture.status = "running" if tamper == "unfinished" else "dispatch_unknown"
    elif tamper == "parent_wrong_path":
        fx.capture.result["har_path"] = "captures/other.har"
    elif tamper == "parent_wrong_tenant":
        fx.capture.engagement_id = OTHER
    elif tamper == "wrong_label":
        fx.capture.payload["user_label"] = "user-b"
    elif tamper == "wrong_workflow":
        fx.capture.payload["workflow_id"] = "wf-other"
    elif tamper == "missing_signed_version":
        fx.child.payload.pop("_authorization_version")
    elif tamper == "revoked":
        fx.memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    elif tamper == "unclaimed_child":
        fx.child.status = "pending"
    result = await fx.agent._execute(fx.child)
    assert result["status"] == "failed"
    assert "unavailable" in result["error"]
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_signed_root_never_falls_back_to_cwd_or_manual(workflow, monkeypatch):
    monkeypatch.delenv("OSOP_AUTHENTICATED_HAR_ROOT")
    assert (workflow.resources.manual / SID / PATH).is_file()
    result = await workflow.agent._execute(workflow.child)
    assert result["status"] == "failed"
    workflow.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_source_har_replaced_after_capture_refuses_persistence(workflow):
    fx = workflow
    path = fx.resources.root / SID / PATH
    path.write_text(json.dumps(_har("https://example.test/api/replaced")), encoding="utf-8")
    result = await fx.agent._execute(fx.child)
    assert result["status"] == "failed"
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_parent_requires_original_capture_digest(workflow):
    fx = workflow
    fx.capture.result.pop("resource_sha256")
    result = await fx.agent._execute(fx.child)
    assert result["status"] == "failed"
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_manual_import_is_tenant_scoped_and_cannot_use_signed_root(workflow):
    fx = workflow
    fx.agent.ctx.current_task = Task(
        engagement_id=SID,
        type="extract_har_api_inventory",
        agent_type=AgentType.WORKFLOW,
        payload={"har_path": PATH, "workflow_id": "wf-1", "user_label": "user-a"},
    )
    result = await fx.agent._execute_extract_har_api_inventory(
        fx.agent.ctx.current_task.payload,
    )
    assert result["status"] == "success"
    assert result["resource_origin"] == "manual_tenant_import"
    fx.graph.add_endpoint.assert_awaited_once()


@pytest.mark.parametrize(
    "malicious",
    [
        "/etc/hosts",
        "C:/Windows/private.har",
        "\\\\server\\share\\file.har",
        "../../other.har",
        "captures/../user-a.har",
        "captures//user-a.har",
        "./captures/user-a.har",
        "captures/./user-a.har",
        "~/user-a.har",
        "captures\\user-a.har",
        "http://server/a.har",
        "captures/file.txt",
        "captures/a.har?token=private",
        "captures/\x00.har",
    ],
)
def test_path_attack_never_reads_host_root_or_other_resource(resources, malicious):
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, malicious, signed=True)


def test_tenant_file_cannot_be_loaded_with_foreign_engagement(resources):
    # No browser/provider path is allowed to name an engagement directory.
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, f"../{OTHER}/{PATH}", signed=True)
    assert snapshot_local_har(OTHER, PATH, signed=True)[0]["log"]["entries"]


@pytest.mark.parametrize(
    "content",
    [
        b"not-json",
        b"{}",
        b'{"log":{"entries":null}}',
        b'{"log":{"entries":[{}]}}',
        b'{"log":{"entries":[{"request":{"method": "GET"}}]}}',
        b'{"log":{"entries":[],"entries":[]}}',
        b'{"log":{"entries":[],"extra":NaN}}',
    ],
)
def test_malformed_har_does_not_reach_extractor(resources, content):
    (resources.root / SID / PATH).write_bytes(content)
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, PATH, signed=True)


def test_oversized_har_and_excessive_entries_denied(resources):
    path = resources.root / SID / PATH
    path.write_bytes(b" " * (MAX_HAR_BYTES + 1))
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, PATH, signed=True)
    path.write_text(
        json.dumps({"log": {"entries": [_har()["log"]["entries"][0]] * 2001}}),
        encoding="utf-8",
    )
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, PATH, signed=True)


def test_symlinks_in_file_and_parent_refused(resources):
    target = resources.root / OTHER / PATH
    own = resources.root / SID / PATH
    own.unlink()
    try:
        own.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Host disallows symlink creation")
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, PATH, signed=True)
    own.unlink()
    capture = resources.root / SID / "captures"
    capture.rmdir()
    capture.symlink_to(resources.root / OTHER / "captures", target_is_directory=True)
    with pytest.raises(ResourcePathDenied):
        snapshot_local_har(SID, PATH, signed=True)


@pytest.mark.asyncio
async def test_remote_browser_mcp_exists_is_not_a_local_file_receipt(workflow):
    fx = workflow
    fx.agent.ctx.current_task = fx.capture.model_copy(deep=True)
    fx.agent.ctx.current_task.status = "running"
    fx.tasks[CAPTURE] = fx.agent.ctx.current_task.model_copy(deep=True)
    fx.agent._execute_navigation = AsyncMock(return_value={"status": "success"})
    fx.agent.browser_adapter = SimpleNamespace(
        flush_har=AsyncMock(
            return_value={
                "path": "/remote/browser/provider/root/record.har",
                "exists": True,
            }
        ),
    )
    result = await fx.agent._execute_capture_authenticated_surface(
        {
            "url": "https://example.test/",
            "user_label": "user-a",
            "workflow_id": "wf-1",
        }
    )
    assert result["status"] == "partial"
    assert "har_path" not in result
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_local_capture_only_succeeds_when_shared_mount_has_tenant_file(workflow, monkeypatch):
    fx = workflow
    mount_sha256, image_sha256 = _pin_signed_happy_path_mount(fx, monkeypatch)
    fx.agent.ctx.current_task = fx.capture.model_copy(deep=True)
    fx.agent.ctx.current_task.status = "running"
    fx.tasks[CAPTURE] = fx.agent.ctx.current_task.model_copy(deep=True)
    fx.agent._execute_navigation = AsyncMock(return_value={"status": "success"})
    fx.agent.browser_adapter = SimpleNamespace(
        flush_har=AsyncMock(return_value={
            "path": PATH,
            "exists": True,
            "engagement_id": SID,
            "user_label": "user-a",
            "workflow_id": "wf-1",
            "resource_sha256": fx.capture.result["resource_sha256"],
            "mount_sha256": mount_sha256,
            "container_image_sha256": image_sha256,
            "capture_task_id": CAPTURE,
        }),
    )
    result = await fx.agent._execute_capture_authenticated_surface(
        {
            "url": "https://example.test/",
            "user_label": "user-a",
            "workflow_id": "wf-1",
        }
    )
    assert result["status"] == "success"
    assert result["har_path"] == PATH
    assert result["endpoints_persisted"] == 1
    assert "resource_sha256" in result
