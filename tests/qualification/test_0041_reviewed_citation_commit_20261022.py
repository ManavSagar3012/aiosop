"""0041 reviewed citation: signed fixture + fake transaction; not live PG.

Production endpoint stays 503 without external signer enrollment. No source
body reaches Flow notes, model prompts, targets or scanners in these tests.
"""

from __future__ import annotations

import asyncio
import importlib.util
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ai_osop.memory import operator_reviewed_flow_atomic_writer_20261022 as atomic


def _setup(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    source = Path(__file__).with_name("test_0039_reviewed_atomic_writer_20261022.py")
    spec = importlib.util.spec_from_file_location("_citation_base_20261022", source)
    assert spec and spec.loader
    suite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(suite)
    ctx = suite.scope.__wrapped__(monkeypatch)
    originals = suite._DB.execute
    ctx["state"]["written"] = []

    async def execute(db: Any, statement: Any, values: dict[str, Any]) -> Any:
        if "INSERT INTO operator_reviewed_global_flow_citations" in str(statement):
            ctx["state"]["written"].append(dict(values))
            return SimpleNamespace(scalar_one=lambda: values["id"])
        if "SELECT id FROM operator_reviewed_global_flow_citations" in str(statement):
            matching = [
                row["id"] for row in ctx["state"]["written"]
                if all(row[key] == value for key, value in values.items())
            ]
            return SimpleNamespace(
                scalar_one_or_none=lambda: matching[0] if len(matching) == 1 else None
            )
        return await originals(db, statement, values)

    monkeypatch.setattr(suite._DB, "execute", execute)
    return ctx


def test_immutable_scoped_metadata_only_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _setup(monkeypatch)
    result = asyncio.run(ctx["handler"].record_reviewed_metadata_citation(ctx["proposal"]))
    assert isinstance(result, atomic.RecordedReviewedCitation)
    assert result.citation_id.startswith("citation-")
    assert result.source_sha256 == ctx["proposal"].global_sha256
    assert result.transaction_committed_citation is True
    assert result.approved_for_agent_context is False
    assert result.flow_local_document_created is False
    assert result.verified_target_evidence is False
    assert result.safe_for_execution is False
    assert result.source_original_returned is False
    written = ctx["state"]["written"]
    assert len(written) == 1
    row = written[0]
    assert row["source"] == ctx["proposal"].global_document_id
    assert row["task"] == ctx["proposal"].task_id
    assert row["auth_sha"] == ctx["proposal"].authorization_sha256
    assert row["review_sha"] and len(row["review_sha"]) == 64
    assert "content" not in row and "original" not in row
    assert ctx["state"]["row"]["content"] not in repr(result)
    assert len(ctx["signers"]["signed_reads"]) == 8


@pytest.mark.parametrize(
    "attack",
    ["unenrolled", "wrong_flow_owner", "stale_revision", "tombstone", "bad_original", "task_stopped"],
)
def test_denial_before_any_citation_insert(
    monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    ctx = _setup(monkeypatch)
    request = ctx["proposal"]
    if attack == "unenrolled":
        ctx["signed"]._enrolled_shape = False
    elif attack == "wrong_flow_owner":
        request = replace(request, principal_subject="not-the-flow-owner")
    elif attack == "stale_revision":
        ctx["state"]["row"]["current_revision"] += 1
    elif attack == "tombstone":
        ctx["state"]["source_deleted"] = True
    elif attack == "bad_original":
        ctx["state"]["row"]["content"] += " forged"
    elif attack == "task_stopped":
        ctx["state"]["task"]["status"] = "done"
    with pytest.raises(atomic.AtomicReviewedImportDenied):
        asyncio.run(ctx["handler"].record_reviewed_metadata_citation(request))
    assert ctx["state"]["written"] == []


def test_ambiguous_insert_failure_never_claims_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _setup(monkeypatch)
    # A commit/write failure cannot return a proof (including an already-used
    # unique reviewed source identity). Retry requires separate readback.
    from sqlalchemy.exc import IntegrityError

    original = ctx["maker"]

    class FaultyDB:
        def __init__(self, inner: Any):
            self.inner = inner

        async def __aenter__(self) -> "FaultyDB":
            await self.inner.__aenter__()
            return self

        async def __aexit__(self, *args: Any) -> Any:
            return await self.inner.__aexit__(*args)

        def begin(self) -> Any:
            return self.inner.begin()

        async def execute(self, statement: Any, values: dict[str, Any]) -> Any:
            if "INSERT INTO operator_reviewed_global_flow_citations" in str(statement):
                raise IntegrityError("INSERT", values, Exception("collision"))
            return await self.inner.execute(statement, values)

    class FaultyMaker:
        def __call__(self) -> FaultyDB:
            return FaultyDB(original())

    maker = FaultyMaker()
    ctx["signed"]._library._maker = maker
    ctx["handler"]._artifacts.session_memory._async_session = maker
    with pytest.raises(atomic.AtomicReviewedImportDenied, match="UNKNOWN"):
        asyncio.run(ctx["handler"].record_reviewed_metadata_citation(ctx["proposal"]))


def test_actual_app_mount_has_new_endpoint_without_host_enrollment() -> None:
    from ai_osop.api.main import app

    routes = [
        route for route in app.routes
        if getattr(route, "path", "") == "/flows/{flow_id}/reviewed-library-import/record-citation"
    ]
    assert len(routes) == 1
    assert getattr(routes[0], "methods", None) == {"POST"}
    recovered = [
        route for route in app.routes
        if getattr(route, "path", "")
        == "/flows/{flow_id}/reviewed-library-import/record-citation/readback"
    ]
    assert len(recovered) == 1
    assert getattr(recovered[0], "methods", None) == {"POST"}
    assert not hasattr(app.state, "_host_reviewed_global_flow_import_20261021")
    assert not hasattr(app.state, "_host_reviewed_global_flow_locked_20261022")


def test_current_signed_readback_does_not_issue_a_second_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _setup(monkeypatch)
    request = ctx["proposal"]
    committed = asyncio.run(ctx["handler"].record_reviewed_metadata_citation(request))
    verified = asyncio.run(ctx["handler"].readback_reviewed_metadata_citation(request))
    assert verified == committed
    assert len(ctx["state"]["written"]) == 1
    assert len(ctx["signers"]["signed_reads"]) == 16


@pytest.mark.parametrize("changed", ["not_written", "review_revoked", "task_changed"])
def test_readback_absence_or_changed_authority_remains_unknown_not_retry(
    monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    ctx = _setup(monkeypatch)
    if changed != "not_written":
        asyncio.run(ctx["handler"].record_reviewed_metadata_citation(ctx["proposal"]))
    if changed == "review_revoked":
        ctx["signed"]._enrolled_shape = False
    elif changed == "task_changed":
        ctx["state"]["task"]["payload"]["_authorization_sha256"] = "f" * 64
    before = len(ctx["state"]["written"])
    with pytest.raises(atomic.AtomicReviewedImportDenied):
        asyncio.run(ctx["handler"].readback_reviewed_metadata_citation(ctx["proposal"]))
    assert len(ctx["state"]["written"]) == before
