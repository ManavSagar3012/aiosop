"""Independent target receipts cannot bypass original signed MCP dispatches."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.routers.target_authority import _verify_signed_replay_dispatches
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _signed_provider_events(case):
    case.source.result["provider_evidence"].update(
        {
            "provider_event_id": "evt-source",
            "provider_receipt_sha256": "a" * 64,
        }
    )
    case.target.result["provider_evidence"].update(
        {
            "provider_event_id": "evt-target",
            "provider_receipt_sha256": "b" * 64,
        }
    )


@pytest.mark.asyncio
async def test_both_independent_signed_dispatch_receipts_required(proof_case):
    case = proof_case
    _signed_provider_events(case)
    verify = AsyncMock(return_value=True)
    store = SimpleNamespace(verify_signed_graph_action=verify)
    assert (
        await _verify_signed_replay_dispatches(
            store,
            "eng-tenant",
            5,
            case.source,
            case.target,
        )
        is True
    )
    assert verify.await_count == 2
    assert verify.await_args_list[0].args == (
        "eng-tenant",
        case.source.id,
        "evt-source",
        "a" * 64,
        5,
    )
    assert verify.await_args_list[1].args == (
        "eng-tenant",
        case.target.id,
        "evt-target",
        "b" * 64,
        5,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["missing", "duplicate_event", "duplicate_receipt", "malformed"])
async def test_incomplete_or_reused_provider_receipts_are_denied(proof_case, bad):
    case = proof_case
    _signed_provider_events(case)
    if bad == "missing":
        del case.target.result["provider_evidence"]["provider_event_id"]
    elif bad == "duplicate_event":
        case.target.result["provider_evidence"]["provider_event_id"] = "evt-source"
    elif bad == "duplicate_receipt":
        case.target.result["provider_evidence"]["provider_receipt_sha256"] = "a" * 64
    else:
        case.target.result["provider_evidence"]["provider_receipt_sha256"] = "not-a-digest"
    verifier = AsyncMock(return_value=True)
    assert (
        await _verify_signed_replay_dispatches(
            SimpleNamespace(verify_signed_graph_action=verifier),
            "eng-tenant",
            5,
            case.source,
            case.target,
        )
        is False
    )


@pytest.mark.asyncio
async def test_unavailable_or_denying_signed_dispatch_store_fail_closed(proof_case):
    case = proof_case
    _signed_provider_events(case)
    assert (
        await _verify_signed_replay_dispatches(
            SimpleNamespace(),
            "eng-tenant",
            5,
            case.source,
            case.target,
        )
        is False
    )
    verifier = AsyncMock(side_effect=OSError("private provider failure"))
    assert (
        await _verify_signed_replay_dispatches(
            SimpleNamespace(verify_signed_graph_action=verifier),
            "eng-tenant",
            5,
            case.source,
            case.target,
        )
        is False
    )
    assert verifier.await_count == 1
