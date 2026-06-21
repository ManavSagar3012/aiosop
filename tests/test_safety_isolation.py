import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.models import AuditEvent
from ai_osop.safety.scope import AuditIntegrity, SandboxManager


@pytest.fixture
def mock_docker():
    with patch("docker.from_env") as mock:
        client = MagicMock()
        mock.return_value = client
        yield client


@pytest.mark.asyncio
@patch("subprocess.run")
async def test_create_sandbox(mock_subproc, mock_docker) -> None:
    # Setup
    manager = SandboxManager()
    sandbox_id = "sb-123"
    policy = {"egress": {"allowed_cidrs": ["10.0.0.0/8"]}}

    mock_container = MagicMock()
    mock_container.id = "cont-123"
    mock_container.short_id = "cont-123"
    mock_container.labels = {"ai-osop.sandbox.id": sandbox_id}
    mock_container.reload = MagicMock()
    mock_container.attrs = {
        "NetworkSettings": {
            "Networks": {
                f"ai-osop-sandbox-{sandbox_id}": {
                    "NetworkID": "net-123",
                    "Gateway": "172.30.1.1",
                    "IPAddress": "172.30.1.2",
                }
            }
        }
    }
    mock_docker.containers.run.return_value = mock_container

    # Act
    sandbox = await manager.create_sandbox(sandbox_id, policy)

    # Assert
    assert sandbox["id"] == sandbox_id
    assert sandbox["container_id"] == "cont-123"
    mock_docker.containers.run.assert_called_once()
    # Check that seccomp was passed if restricted.json exists
    args, kwargs = mock_docker.containers.run.call_args
    assert "security_opt" in kwargs


@pytest.mark.asyncio
async def test_execute_in_sandbox(mock_docker) -> None:
    # Setup
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {"container_id": "cont-1"}

    mock_container = MagicMock()
    mock_docker.containers.get.return_value = mock_container
    mock_container.exec_run.return_value = MagicMock(exit_code=0, output=[b"hello", b""])

    # Act
    result = await manager.execute_in_sandbox("sb-1", ["echo", "hello"])

    # Assert
    assert result["status"] == "success"
    assert "hello" in result["stdout"]


def test_audit_integrity_chain() -> None:
    # Setup
    key = b"secret-key"
    integrity = AuditIntegrity(key)

    events = [
        AuditEvent(
            event_id="e1",
            actor_id="a1",
            actor_type="agent",
            event_type="t1",
            engagement_id="eng1",
            severity="info",
            action={"msg": "test action"},
            result={"msg": "test result"},
            context={},
        ),
        AuditEvent(
            event_id="e2",
            actor_id="a2",
            actor_type="agent",
            event_type="t2",
            engagement_id="eng1",
            severity="info",
            action={"msg": "test action 2"},
            result={"msg": "test result 2"},
            context={},
        ),
    ]

    # Act: Sign
    events[0].integrity_hash = integrity.sign_event(events[0])
    events[1].integrity_hash = integrity.sign_event(events[1])

    # Assert: Verify
    assert integrity.verify_chain(events) == True

    # Tamper
    events[0].event_type = "TAMPERED"
    assert integrity.verify_chain(events) == False


def test_audit_integrity_key_rotation() -> None:
    old_key = b"old-key"
    new_key = b"new-key"

    integrity_old = AuditIntegrity(old_key)
    integrity_new = AuditIntegrity(new_key, old_keys=[old_key])

    event1 = AuditEvent(
        event_id="e1",
        actor_id="a1",
        actor_type="agent",
        event_type="t1",
        engagement_id="eng1",
        severity="info",
        action={},
        result={},
        context={},
    )
    event2 = AuditEvent(
        event_id="e2",
        actor_id="a2",
        actor_type="agent",
        event_type="t2",
        engagement_id="eng1",
        severity="info",
        action={},
        result={},
        context={},
    )

    # Sign event 1 with old key
    event1.integrity_hash = integrity_old.sign_event(event1)

    # Initialize the new instance to have the same last_hash to continue the chain
    integrity_new._last_hash = event1.integrity_hash

    # Sign event 2 with new key
    event2.integrity_hash = integrity_new.sign_event(event2)

    # Verify chain with new integrity object that knows the old key
    assert integrity_new.verify_chain([event1, event2]) == True
