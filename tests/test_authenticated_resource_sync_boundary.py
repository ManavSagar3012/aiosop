"""Signed browser HAR handoff needs an independent tenant mount + producer receipt.

No browser, database, network or external target is used. Legacy/manual imports
remain separate; all signed requests here use the existing production helpers.
"""

import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.memory.authenticated_resource_paths import (
    ResourcePathDenied,
    signed_har_mount_attestation,
)
from tests.test_authenticated_resource_paths import (
    CAPTURE,
    OTHER,
    PATH,
    SID,
    _har,
    resources,
    workflow,
)

CONTAINER_IMAGE_SHA256 = "4" * 64


@pytest.fixture
def trusted_sync(workflow, monkeypatch):
    fx = workflow
    descriptor = {
        "engagement_id": SID,
        "mount_id": "browser-shared-volume-v1",
        "container_image_sha256": CONTAINER_IMAGE_SHA256,
    }
    mounted = fx.resources.root / SID / ".osop-har-mount.json"
    blob = json.dumps(descriptor, separators=(",", ":")).encode()
    mounted.write_bytes(blob)
    mount_sha256 = hashlib.sha256(blob).hexdigest()
    monkeypatch.setenv(
        "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
        json.dumps({SID: mount_sha256}),
    )
    fx.capture.result["mount_sha256"] = mount_sha256
    fx.capture.result["container_image_sha256"] = CONTAINER_IMAGE_SHA256
    receipt = {
        "path": PATH,
        "exists": True,
        "engagement_id": SID,
        "user_label": "user-a",
        "workflow_id": "wf-1",
        "resource_sha256": fx.capture.result["resource_sha256"],
        "mount_sha256": mount_sha256,
        "container_image_sha256": CONTAINER_IMAGE_SHA256,
        "capture_task_id": CAPTURE,
    }
    return SimpleNamespace(
        **vars(fx),
        mounted=mounted,
        mount_sha256=mount_sha256,
        receipt=receipt,
    )


def _capture(trusted, *, receipt=None):
    fx = trusted
    task = fx.capture.model_copy(deep=True)
    task.status = "running"
    fx.agent.ctx.current_task = task
    fx.tasks[CAPTURE] = task
    fx.agent._execute_navigation = AsyncMock(return_value={"status": "success"})
    fx.agent.browser_adapter = SimpleNamespace(
        flush_har=AsyncMock(return_value=fx.receipt if receipt is None else receipt),
    )
    return task


@pytest.mark.asyncio
async def test_eligible_signed_capture_requires_matching_producer_and_tenant_mount(trusted_sync):
    fx = trusted_sync
    _capture(fx)
    result = await fx.agent._execute_capture_authenticated_surface(
        {"url": "https://example.test/", "workflow_id": "wf-1", "user_label": "user-a"},
    )
    assert result["status"] == "success"
    assert result["resource_sha256"] == fx.receipt["resource_sha256"]
    assert result["mount_sha256"] == fx.mount_sha256
    assert result["container_image_sha256"] == CONTAINER_IMAGE_SHA256
    assert result["resource_origin"] == "operator_shared_tenant_mount"
    fx.agent._execute_navigation.assert_awaited_once()
    fx.graph.add_endpoint.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["pins", "descriptor", "wrong_pin"])
async def test_untrusted_or_absent_mount_refused_before_target_navigation(
    trusted_sync,
    monkeypatch,
    missing,
):
    fx = trusted_sync
    if missing == "pins":
        monkeypatch.delenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS")
    elif missing == "descriptor":
        fx.mounted.unlink()
    elif missing == "wrong_pin":
        monkeypatch.setenv(
            "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
            json.dumps({SID: "0" * 64}),
        )
    _capture(fx)
    result = await fx.agent._execute_capture_authenticated_surface(
        {"url": "https://example.test/", "workflow_id": "wf-1", "user_label": "user-a"},
    )
    assert result["status"] == "partial"
    assert "har_path" not in result
    fx.agent._execute_navigation.assert_not_awaited()
    fx.agent.browser_adapter.flush_har.assert_not_awaited()
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,altered",
    [
        ("engagement_id", OTHER),
        ("user_label", "user-b"),
        ("workflow_id", "wf-foreign"),
        ("mount_sha256", "a" * 64),
        ("container_image_sha256", "c" * 64),
        ("resource_sha256", "e" * 64),
        ("path", "captures/different.har"),
        ("capture_task_id", "task-forged"),
    ],
)
async def test_signed_capture_refuses_stale_or_foreign_producer_receipts(
    trusted_sync,
    field,
    altered,
):
    fx = trusted_sync
    receipt = {**fx.receipt, field: altered}
    _capture(fx, receipt=receipt)
    result = await fx.agent._execute_capture_authenticated_surface(
        {"url": "https://example.test/", "workflow_id": "wf-1", "user_label": "user-a"},
    )
    assert result["status"] == "partial"
    assert "har_path" not in result
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing",
    [
        "engagement_id",
        "user_label",
        "workflow_id",
        "mount_sha256",
        "container_image_sha256",
        "resource_sha256",
    ],
)
async def test_signed_capture_rejects_missing_producer_provenance_fields(
    trusted_sync,
    missing,
):
    fx = trusted_sync
    receipt = dict(fx.receipt)
    receipt.pop(missing)
    _capture(fx, receipt=receipt)
    result = await fx.agent._execute_capture_authenticated_surface(
        {"url": "https://example.test/", "workflow_id": "wf-1", "user_label": "user-a"},
    )
    assert result["status"] == "partial"
    assert "har_path" not in result
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_capture_rejects_reused_stale_har_bytes_even_with_valid_mount(trusted_sync):
    fx = trusted_sync
    _capture(fx)
    (fx.resources.root / SID / PATH).write_text(
        json.dumps(_har("https://example.test/api/changed")),
        encoding="utf-8",
    )
    result = await fx.agent._execute_capture_authenticated_surface(
        {"url": "https://example.test/", "workflow_id": "wf-1", "user_label": "user-a"},
    )
    assert result["status"] == "partial"
    assert "har_path" not in result
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["mount_sha256", "container_image_sha256", "resource_sha256"])
async def test_restarted_child_refuses_old_parent_without_full_sync_receipt(
    trusted_sync,
    missing,
):
    fx = trusted_sync
    fx.capture.result.pop(missing)
    recovered = await fx.agent._execute_extract_har_api_inventory(fx.child.payload)
    assert recovered["status"] == "failed"
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_restarted_child_reads_bound_snapshot_only_from_original_engagement(trusted_sync):
    fx = trusted_sync
    recovered = await fx.agent._execute_extract_har_api_inventory(fx.child.payload)
    assert recovered["status"] == "success"
    assert recovered["mount_sha256"] == fx.mount_sha256
    fx.graph.add_endpoint.assert_awaited_once()
    fx.graph.add_endpoint.reset_mock()
    fx.child.engagement_id = OTHER
    refused = await fx.agent._execute_extract_har_api_inventory(fx.child.payload)
    assert refused["status"] == "failed"
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_replaced_container_descriptor_blocks_child_even_if_har_bytes_unchanged(trusted_sync):
    fx = trusted_sync
    fx.mounted.write_text(
        json.dumps(
            {"engagement_id": SID, "mount_id": "new-volume", "container_image_sha256": "f" * 64}
        ),
        encoding="utf-8",
    )
    recovered = await fx.agent._execute_extract_har_api_inventory(fx.child.payload)
    assert recovered["status"] == "failed"
    fx.graph.add_endpoint.assert_not_awaited()


def test_operator_pin_requires_exact_tenant_and_inert_attestation_schema(trusted_sync, monkeypatch):
    fx = trusted_sync
    assert signed_har_mount_attestation(SID) == (
        fx.mount_sha256,
        CONTAINER_IMAGE_SHA256,
    )
    with pytest.raises(ResourcePathDenied):
        signed_har_mount_attestation(OTHER)
    with pytest.raises(ResourcePathDenied):
        signed_har_mount_attestation(SID, expected_sha256="d" * 64)
    monkeypatch.setenv(
        "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
        '{"eng-har-a":"' + fx.mount_sha256 + '","eng-har-a":"' + fx.mount_sha256 + '"}',
    )
    with pytest.raises(ResourcePathDenied):
        signed_har_mount_attestation(SID)


@pytest.mark.asyncio
async def test_manual_har_import_stays_separate_and_does_not_need_signed_mount(
    workflow, monkeypatch
):
    fx = workflow
    monkeypatch.delenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", raising=False)
    fx.agent.ctx.current_task = None
    inventory = await fx.agent._execute_extract_har_api_inventory(
        {"har_path": PATH, "workflow_id": "wf-1", "user_label": "user-a"},
    )
    assert inventory["status"] == "success"
    assert inventory["resource_origin"] == "manual_tenant_import"
    assert "mount_sha256" not in inventory
    fx.graph.add_endpoint.assert_awaited_once()
