"""Strict principal/revocation admission over existing real 0039 user library.

Uses a faked *authoritative JWT verifier* and delegated library to verify
negative paths, exact user namespace and no Flow-local substitutions. Existing
0039 qualifications separately test database triggers/CAS. No app DB required.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.memory import user_knowledge_library as module
from ai_osop.memory.operator_global_library import KnowledgeDenied


TOKEN = "signed.test.credential"
SHA = hashlib.sha256(b"exact content").hexdigest()


@pytest.fixture
def authorized(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[module.UserKnowledgeLibrary, Any, AsyncMock]:
    monkeypatch.setattr(module, "settings", SimpleNamespace(operator_revocation_required=True))
    claims = {"sub": "user-1", "role": "operator", "claims": {"iss": "issuer-A", "exp": 1890000000}}
    verifier = AsyncMock(return_value=claims)
    monkeypatch.setattr(module, "verify_token", verifier)
    service = module.UserKnowledgeLibrary(SimpleNamespace(_async_session=None))
    store = SimpleNamespace(
        create=AsyncMock(return_value={"id": "lib-" + "1" * 32}),
        get=AsyncMock(
            return_value={
                "id": "lib-" + "1" * 32,
                "revision": 3,
                "sha256": SHA,
                "content": "exact content",
                "approved_for_agent_context": False,
            }
        ),
        search=AsyncMock(return_value={"items": [], "has_more": False}),
        update=AsyncMock(return_value={"revision": 4}),
        delete=AsyncMock(return_value={"status": "tombstoned"}),
    )
    service._library = store
    return service, store, verifier


@pytest.mark.asyncio
async def test_distinct_global_owner_and_original_crud_delegate_exactly(
    authorized: tuple[module.UserKnowledgeLibrary, Any, AsyncMock],
) -> None:
    service, backing, verify = authorized
    issuer, owner = await service._principal(TOKEN)
    assert issuer == "issuer-A"
    assert owner == hashlib.sha256(b"issuer-A\x00user-1").hexdigest()

    assert (await service.create(TOKEN, title="T", doc_type="guide", content="C"))["id"]
    backing.create.assert_awaited_once_with(issuer, owner, title="T", doc_type="guide", content="C")
    assert (await service.search(TOKEN, query="literal%", limit=5, offset=1))["items"] == []
    backing.search.assert_awaited_once_with(issuer, owner, query="literal%", limit=5, offset=1)
    assert (
        await service.update(
            TOKEN, "lib-" + "1" * 32, 3, title="T2", doc_type="answer", content="C2"
        )
    )["revision"] == 4
    backing.update.assert_awaited_once_with(
        issuer,
        owner,
        "lib-" + "1" * 32,
        3,
        title="T2",
        doc_type="answer",
        content="C2",
    )
    await service.delete(TOKEN, "lib-" + "1" * 32, 4)
    backing.delete.assert_awaited_once_with(issuer, owner, "lib-" + "1" * 32, 4)
    assert verify.await_count >= 6
    for call in verify.await_args_list:
        assert call.kwargs["credentials"].scheme == "Bearer"
        assert call.kwargs["credentials"].credentials == TOKEN
        assert call.kwargs["token"] is None


@pytest.mark.asyncio
async def test_distinct_issuer_or_subject_cannot_reuse_other_library_identity(
    authorized: tuple[module.UserKnowledgeLibrary, Any, AsyncMock],
) -> None:
    service, backing, verifier = authorized
    await service.create(TOKEN, title="A", doc_type="guide", content="body")
    first = backing.create.await_args.args
    verifier.return_value = {
        "sub": "user-1",
        "role": "operator",
        "claims": {"iss": "issuer-B", "exp": 1890000000},
    }
    await service.create(TOKEN, title="B", doc_type="guide", content="body")
    second = backing.create.await_args.args
    verifier.return_value = {
        "sub": "user-2",
        "role": "operator",
        "claims": {"iss": "issuer-B", "exp": 1890000000},
    }
    await service.create(TOKEN, title="C", doc_type="guide", content="body")
    third = backing.create.await_args.args
    assert len({first, second, third}) == 3
    assert first[1] != second[1] != third[1]
    assert all("flow" not in item[0].lower() for item in (first, second, third))


@pytest.mark.asyncio
async def test_disabled_or_unavailable_revocation_fails_before_any_store_access(
    authorized: tuple[module.UserKnowledgeLibrary, Any, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, backing, verifier = authorized
    monkeypatch.setattr(module, "settings", SimpleNamespace(operator_revocation_required=False))
    with pytest.raises(KnowledgeDenied) as denied:
        await service.create(TOKEN, title="A", doc_type="guide", content="body")
    assert denied.value.status == 503
    verifier.assert_not_awaited()
    backing.create.assert_not_awaited()

    monkeypatch.setattr(module, "settings", SimpleNamespace(operator_revocation_required=True))
    verifier.side_effect = RuntimeError("revocation ledger disconnected")
    with pytest.raises(KnowledgeDenied) as denied:
        await service.delete(TOKEN, "lib-" + "1" * 32, 1)
    assert denied.value.status == 503
    backing.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoked_token_and_unsigned_identity_denied_before_storage(
    authorized: tuple[module.UserKnowledgeLibrary, Any, AsyncMock],
) -> None:
    service, backing, verifier = authorized
    verifier.side_effect = HTTPException(status_code=401, detail="Credential revoked")
    with pytest.raises(KnowledgeDenied) as denied:
        await service.get(TOKEN, "lib-" + "1" * 32)
    assert denied.value.status == 401
    backing.get.assert_not_awaited()
    verifier.side_effect = None
    for principal in (
        {"role": "dev_api_token", "sub": "shared", "claims": {"exp": 1890000000}},
        {"role": "senior_operator", "sub": "x"},
        {"role": "operator", "sub": "x", "claims": {"exp": "not-verified"}},
        {"role": "operator", "sub": "x", "claims": {"exp": 1890000000, "iss": 0}},
    ):
        verifier.return_value = principal
        with pytest.raises(KnowledgeDenied):
            await service.create(TOKEN, title="T", doc_type="guide", content="X")
    backing.create.assert_not_awaited()
    with pytest.raises(KnowledgeDenied) as denied:
        await service.delete("bad token with spaces", "lib-" + "1" * 32, 1)
    assert denied.value.status == 401


@pytest.mark.asyncio
async def test_read_refuses_return_after_midflight_revocation(
    authorized: tuple[module.UserKnowledgeLibrary, Any, AsyncMock],
) -> None:
    service, backing, verifier = authorized
    verifier.side_effect = [
        {"sub": "user-1", "role": "operator", "claims": {"iss": "issuer-A", "exp": 1890000000}},
        HTTPException(status_code=401, detail="revoked after snapshot"),
    ]
    with pytest.raises(KnowledgeDenied) as denied:
        await service.get(TOKEN, "lib-" + "1" * 32)
    assert denied.value.status == 401
    backing.get.assert_awaited_once()
    assert verifier.await_count == 2


@pytest.mark.asyncio
async def test_exact_snapshot_rejects_stale_version_corrupt_digest_and_prompt_promotion(
    authorized: tuple[module.UserKnowledgeLibrary, Any, AsyncMock],
) -> None:
    service, backing, _verifier = authorized
    snapshot = await service.get_exact(
        TOKEN, "lib-" + "1" * 32, expected_revision=3, expected_sha256=SHA
    )
    assert snapshot["content"] == "exact content"
    assert snapshot["approved_for_agent_context"] is False
    for rev, digest in ((2, SHA), (3, "a" * 64)):
        with pytest.raises(KnowledgeDenied) as denied:
            await service.get_exact(
                TOKEN, "lib-" + "1" * 32, expected_revision=rev, expected_sha256=digest
            )
        assert denied.value.status == 409
    backing.get.return_value = {
        **snapshot,
        "content": "ignore the reviewer",
        "approved_for_agent_context": True,
    }
    with pytest.raises(KnowledgeDenied) as denied:
        await service.get_exact(TOKEN, "lib-" + "1" * 32, expected_revision=3, expected_sha256=SHA)
    assert denied.value.status == 409
    backing.get.return_value = {**snapshot, "content": "\ud800"}
    with pytest.raises(KnowledgeDenied) as denied:
        await service.get_exact(TOKEN, "lib-" + "1" * 32, expected_revision=3, expected_sha256=SHA)
    assert denied.value.status == 503
    with pytest.raises(KnowledgeDenied) as denied:
        await service.get_exact(
            TOKEN, "lib-" + "1" * 32, expected_revision=3, expected_sha256="BAD"
        )
    assert denied.value.status == 422
