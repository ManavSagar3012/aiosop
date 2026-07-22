import base64
import json
import os
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.visual_agent import VisualContextAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "visual-1"
    ctx.agent_type = AgentType.VISUAL_CONTEXT
    ctx.session_id = "test-session"
    ctx.llm_client = AsyncMock()
    ctx.session_memory = AsyncMock()
    ctx.graph_memory = AsyncMock()
    ctx.persona = "test_persona"
    ctx.current_task = None
    ctx.cost_incurred = 0.0
    ctx.audit_callback = AsyncMock()
    ctx.coordination_bus = AsyncMock()
    return ctx


@pytest.fixture
def agent(mock_context):
    a = VisualContextAgent(mock_context)
    return a


@pytest.mark.asyncio
async def test_execute_visual_analysis_with_llm(agent) -> None:
    # Setup
    await agent.initialize()
    agent._encode_image = MagicMock(return_value="fake-base64-image")

    task = Task(
        id="task-1",
        type="analyze_screenshot",
        agent_type=AgentType.VISUAL_CONTEXT,
        payload={
            "screenshot_path": "/tmp/test.png",
            "workflow_state": "settings",
            "user_role": "admin",
        },
        engagement_id="test-session",
    )

    # Mock LLM response
    mock_response = {
        "content": '```json\n[{"label": "Delete Data", "confidence": 0.9, "type": "destructive"}]\n```',
        "cost": 0.01,
    }
    agent.ctx.llm_client.complete.return_value = mock_response

    # Act
    result = await agent._execute(task)

    # Assert
    assert result["status"] == "success"
    assert result["critical_ops_found"] == 1

    # Check LLM call format
    assert agent.ctx.llm_client.complete.call_count == 2
    messages = agent.ctx.llm_client.complete.call_args_list[1][0][0]

    # Verify image URL is correctly formatted
    assert (
        "data:image/png;base64,fake-base64-image" in messages[0]["content"][1]["image_url"]["url"]
    )


@pytest.mark.asyncio
async def test_execute_view_comparison_with_llm(agent) -> None:
    # Setup
    await agent.initialize()
    agent._encode_image = MagicMock(return_value="fake-base64-image")

    task = Task(
        id="task-2",
        type="compare_views",
        agent_type=AgentType.VISUAL_CONTEXT,
        payload={
            "view_user_a": "va-1",
            "view_user_b": "va-2",
            "path_user_a": "/tmp/admin.png",
            "path_user_b": "/tmp/guest.png",
        },
        engagement_id="test-session",
    )

    # Mock LLM response
    mock_response = {"content": '```json\n["Guest sees admin panel link"]\n```', "cost": 0.01}
    agent.ctx.llm_client.complete.return_value = mock_response

    # Act
    result = await agent._execute(task)

    # Assert
    assert result["status"] == "success"
    assert result["anomalies_detected"] == 1

    # Check LLM call format - should have 2 images
    assert agent.ctx.llm_client.complete.call_count == 2
    messages = agent.ctx.llm_client.complete.call_args_list[1][0][0]
    assert messages[0]["content"][1]["type"] == "image_url"
    assert messages[0]["content"][2]["type"] == "image_url"
