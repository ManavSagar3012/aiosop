"""V2 reports bind producer Task + signed ROE; no external providers."""

from types import SimpleNamespace
from datetime import datetime
from unittest.mock import AsyncMock
import json
from pathlib import Path

import pytest

from ai_osop.core.exceptions import AgentException
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.reporting.attestation import verify_report_files
from tests.test_report_attestation import (
    ENGAGEMENT, EVIDENCE, FINDING, reporting_agent, signer, install_signed_report_source,
)


@pytest.mark.asyncio
async def test_real_memory_type_report_producer_signs_durable_task_binding(
    reporting_agent, signer,
):
    agent = reporting_agent
    install_signed_report_source(agent)
    task = agent.ctx.current_task
    task.status = "running"
    task.started_at = datetime.utcnow()
    task.assigned_agent_id = agent.ctx.agent_id
    task.approval_required = True
    task.payload = {
        "version": "v1",
        "require_attestation": True,
        "signer_key_id": "report-prod-kid",
        "_authorization_version": 2,
    }
    previous_session = await agent.ctx.session_memory.load_session_state(ENGAGEMENT)
    durable = SessionMemory.__new__(SessionMemory)
    durable.load_session_state = AsyncMock(return_value=previous_session)
    durable.load_task_authoritative = AsyncMock(return_value=task.model_copy(deep=True))
    durable.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=2, policy_sha256="a" * 64)
    )
    agent.ctx.session_memory = durable

    outcome = await agent._execute(task)
    assert outcome["status"] == "success"
    assert outcome["signature_status"] == "ed25519_signed"
    envelope = json.loads(Path(outcome["report_paths"]["attestation"]).read_text())
    binding = envelope["attestation"]["generation_binding"]
    assert binding["task_id"] == task.id
    assert binding["authorization_version"] == 2
    assert binding["authorization_sha256"] == "a" * 64
    verified = verify_report_files(
        outcome["report_paths"],
        evidence_by_finding={FINDING: EVIDENCE},
        trusted_public_keys={"report-prod-kid": signer},
    )
    assert verified["status"] == "signature_and_snapshot_verified"
    assert envelope["attestation"]["schema"] == "ai-osop-report-attestation-v2"
    durable.assert_signed_authorization.assert_awaited_once_with(
        ENGAGEMENT, expected_version=2,
    )


@pytest.mark.asyncio
async def test_unverified_producer_task_cannot_sign_v2(
    reporting_agent, signer,
):
    agent = reporting_agent
    task = agent.ctx.current_task
    task.payload = {
        "version": "v1", "require_attestation": True,
        "signer_key_id": "report-prod-kid", "_authorization_version": 1,
    }
    previous_session = await agent.ctx.session_memory.load_session_state(ENGAGEMENT)
    durable = SessionMemory.__new__(SessionMemory)
    durable.load_session_state = AsyncMock(return_value=previous_session)
    durable.load_task_authoritative = AsyncMock(return_value=None)
    durable.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=1, policy_sha256="b" * 64)
    )
    agent.ctx.session_memory = durable
    with pytest.raises(AgentException, match="generating Task authorization unavailable"):
        await agent._execute(task)
