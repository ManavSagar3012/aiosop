"""Signed fixture qualification for 0042 inert reviewed Flow original.

Fake database methods are not a transactional PostgreSQL certification. The
actual private nonroot PostgreSQL16 schema/atomic rollback test is separate.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from ai_osop.memory import operator_reviewed_flow_atomic_writer_20261022 as atomic
from tests.qualification import test_0041_reviewed_citation_commit_20261022 as base


def setup(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    ctx = base._setup(monkeypatch)
    ctx["state"]["originals"] = []
    db_class = type(ctx["maker"]())
    original = db_class.execute

    async def execute(db: Any, statement: Any, values: dict[str, Any]) -> Any:
        statement_text = str(statement)
        if "INSERT INTO operator_reviewed_flow_originals" in statement_text:
            ctx["state"]["originals"].append(dict(values))
            return SimpleNamespace(scalar_one=lambda: values["id"])
        if "SELECT c.id,o.content_bytes FROM operator_reviewed_global_flow_citations" in statement_text:
            matches = [
                row for row in ctx["state"]["originals"]
                if any(
                    citation["id"] == row["id"]
                    and all(citation[key] == value for key, value in values.items() if key != "id")
                    for citation in ctx["state"]["written"]
                )
            ]
            value = (
                {"id": matches[0]["id"], "content_bytes": matches[0]["bytes"]}
                if len(matches) == 1 else None
            )
            return SimpleNamespace(mappings=lambda: SimpleNamespace(one_or_none=lambda: value))
        return await original(db, statement, values)

    monkeypatch.setattr(db_class, "execute", execute)
    return ctx


def test_signed_current_original_source_bytes_and_citation_commit_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = setup(monkeypatch)
    request = ctx["proposal"]
    created = asyncio.run(ctx["handler"].store_reviewed_flow_original(request))
    assert isinstance(created, atomic.StoredReviewedFlowOriginal)
    assert created.status == "reviewed_flow_original_stored_inert"
    assert created.transaction_committed_source_and_citation is True
    assert created.flow_local_original_stored is True
    assert created.approved_for_agent_context is False
    assert created.verified_target_evidence is False
    assert created.safe_for_execution is False
    assert created.source_original_returned is False
    assert created.citation_id.startswith("citation-")
    assert created.source_sha256 == request.global_sha256
    assert len(ctx["state"]["written"]) == len(ctx["state"]["originals"]) == 1
    row = ctx["state"]["originals"][0]
    assert row["id"] == created.citation_id
    assert row["original"] == ctx["state"]["row"]["content"]
    assert row["bytes"] == len(row["original"].encode("utf-8"))
    assert row["sha"] == request.global_sha256
    assert row["flow"] == request.flow_id
    assert row["eng"] == request.engagement_id
    assert "IGNORE ALL PRIOR RULES" not in repr(created)
    assert len(ctx["signers"]["signed_reads"]) == 8


def test_readback_confirms_original_and_citation_without_content_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = setup(monkeypatch)
    request = ctx["proposal"]
    first = asyncio.run(ctx["handler"].store_reviewed_flow_original(request))
    readback = asyncio.run(ctx["handler"].readback_reviewed_flow_original(request))
    assert readback == first
    assert len(ctx["state"]["written"]) == len(ctx["state"]["originals"]) == 1
    assert "IGNORE ALL PRIOR RULES" not in repr(readback)
    assert len(ctx["signers"]["signed_reads"]) == 16


@pytest.mark.parametrize(
    "attack",
    ["unenrolled", "owner_changed", "original_revised", "original_deleted",
     "tampered_content", "wrong_task", "revoked_signed_roe", "forged_reviewer"],
)
def test_absent_or_wrong_original_current_admission_denies_both_inserts(
    monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    ctx = setup(monkeypatch)
    request = ctx["proposal"]
    if attack == "unenrolled":
        ctx["signed"]._enrolled_shape = False
    elif attack == "owner_changed":
        request = replace(request, principal_subject="not-owner")
    elif attack == "original_revised":
        ctx["state"]["row"]["current_revision"] += 1
    elif attack == "original_deleted":
        ctx["state"]["source_deleted"] = True
    elif attack == "tampered_content":
        ctx["state"]["row"]["content"] += " altered"
    elif attack == "wrong_task":
        ctx["state"]["task"]["status"] = "complete"
    elif attack == "revoked_signed_roe":
        ctx["state"]["signed_authorization_id"] = "another-auth"
    else:
        ctx["signers"]["sign_as"]["reviewer"] = "principal"
    with pytest.raises(atomic.AtomicReviewedImportDenied):
        asyncio.run(ctx["handler"].store_reviewed_flow_original(request))
    assert ctx["state"]["written"] == ctx["state"]["originals"] == []


def test_no_auto_retry_or_false_readback_on_original_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = setup(monkeypatch)
    with pytest.raises(atomic.AtomicReviewedImportDenied, match="UNKNOWN"):
        asyncio.run(ctx["handler"].readback_reviewed_flow_original(ctx["proposal"]))
    assert ctx["state"]["written"] == ctx["state"]["originals"] == []


def test_mounted_main_has_separate_original_and_readback_routes() -> None:
    from ai_osop.api.main import app

    for path in (
        "/flows/{flow_id}/reviewed-library-import/store-reviewed-original",
        "/flows/{flow_id}/reviewed-library-import/store-reviewed-original/readback",
    ):
        routes = [route for route in app.routes if getattr(route, "path", "") == path]
        assert len(routes) == 1
        assert getattr(routes[0], "methods", None) == {"POST"}
    assert not hasattr(app.state, "_host_reviewed_global_flow_import_20261021")
    assert not hasattr(app.state, "_host_reviewed_global_flow_locked_20261022")
