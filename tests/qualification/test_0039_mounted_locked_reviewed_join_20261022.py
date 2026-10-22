"""Mounted 0039 independently enrolled transaction-locked PENDING join.

All signer/store callbacks are deliberately synthetic and labelled as such.
No real reviewer enrollment, PostgreSQL writer, original import or agent use.
"""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from ai_osop.api import deps
from ai_osop.api.routers import reviewed_library_flow_import as routes
from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
    LockedReviewedCitationPlan,
    OperatorReviewedFlowAtomicWriter,
)
from ai_osop.memory.reviewed_library_flow_import import (
    PendingLibraryFlowCitation,
    ReviewedLibraryFlowImport,
    ReviewedLibraryFlowImportDenied,
)
from tests.qualification.test_0039_mounted_reviewed_library_preflight_20261021 import (
    BODY,
    FLOW,
    isolated,
    token,
)


@pytest.fixture
def joined(isolated, monkeypatch):
    maker = object()
    memory = SimpleNamespace(_async_session=maker)
    monkeypatch.setitem(deps.state, "orchestrator", SimpleNamespace(session_memory=memory))
    reviewer = ReviewedLibraryFlowImport()
    reviewer._enrolled_shape = True
    reviewer._library = SimpleNamespace(_maker=maker)
    pending = PendingLibraryFlowCitation(
        source_id=BODY["global_document_id"],
        original_revision=BODY["global_revision"],
        original_sha256=BODY["global_sha256"],
        source_kind="guide",
        engagement_id=BODY["engagement_id"],
        flow_id=FLOW,
        flow_revision=BODY["expected_flow_revision"],
    )
    reviewer.inspect_pending_citation = AsyncMock(return_value=pending)
    routes.install_host_reviewed_library_preflight(isolated, reviewer)
    writer = OperatorReviewedFlowAtomicWriter(preflight=reviewer)
    writer._artifacts = SimpleNamespace(session_memory=memory)
    # The real worker store requires actual independently signed Flow/ROE/
    # reviewer and PostgreSQL. This synthetic only proves the actual route
    # insists on both observations and compares exact immutable identities.
    writer._trusted_session_maker = lambda: maker
    plan = LockedReviewedCitationPlan(
        source_id=pending.source_id,
        source_revision=pending.original_revision,
        source_sha256=pending.original_sha256,
        source_kind=pending.source_kind,
        engagement_id=pending.engagement_id,
        flow_id=pending.flow_id,
        flow_revision=pending.flow_revision,
        task_id=BODY["task_id"],
        authorization_version=BODY["authorization_version"],
        authorization_sha256=BODY["authorization_sha256"],
        reviewed_identity_sha256="e" * 64,
    )
    writer.inspect_pending = AsyncMock(return_value=plan)
    routes.install_host_locked_reviewed_library_preflight(isolated, writer)
    return isolated, reviewer, writer, plan


@pytest.mark.asyncio
async def test_actual_mounted_preflight_requires_both_original_signed_observations(joined):
    app, reviewer, writer, _ = joined
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as cli:
        result = await cli.post(
            f"/flows/{FLOW}/reviewed-library-import/preflight",
            json=BODY,
            headers={"Authorization": "Bearer " + token()},
        )
    assert result.status_code == 200, result.text
    assert reviewer.inspect_pending_citation.await_count == 1
    assert writer.inspect_pending.await_count == 1
    assert writer.inspect_pending.await_args.args[0] == reviewer.inspect_pending_citation.await_args.args[0]
    body = result.json()
    assert body["status"] == "pending_atomic_reviewed_bind"
    assert body["approved_for_agent_context"] is False
    assert body["verified_target_evidence"] is False
    assert body["safe_for_execution"] is False
    assert "content" not in body and "reviewed_identity_sha256" not in body


@pytest.mark.asyncio
async def test_locked_identity_tamper_denies_mounted_original_readback(joined):
    app, _, writer, plan = joined
    for change in (
        replace(plan, source_revision=plan.source_revision + 1),
        replace(plan, flow_revision=plan.flow_revision + 1),
        replace(plan, source_sha256="f" * 64),
        replace(plan, authorization_sha256="0" * 64),
        replace(plan, transaction_committed_citation=True),
        replace(plan, approved_for_agent_context=True),
        replace(plan, safe_for_execution=True),
    ):
        writer.inspect_pending = AsyncMock(return_value=change)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as cli:
            result = await cli.post(
                f"/flows/{FLOW}/reviewed-library-import/preflight",
                json=BODY,
                headers={"Authorization": "Bearer " + token()},
            )
        assert result.status_code == 409, result.text
        assert "content" not in result.text


def test_host_cannot_install_different_or_unenrolled_locked_writer(joined):
    app, reviewer, writer, _ = joined
    with pytest.raises(ReviewedLibraryFlowImportDenied):
        routes.install_host_locked_reviewed_library_preflight(app, writer)
    with pytest.raises(ReviewedLibraryFlowImportDenied):
        routes.install_host_locked_reviewed_library_preflight(
            type(app)(), OperatorReviewedFlowAtomicWriter(preflight=reviewer)
        )
