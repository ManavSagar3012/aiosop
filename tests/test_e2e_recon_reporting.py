import asyncio
import json
import os
import socket
from datetime import datetime

import pytest

from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.config import settings
from ai_osop.core.enums import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import Asset, Endpoint, ScopeDefinition, SessionState, Task
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory


class MockAgentContext:
    def __init__(self, session_memory, graph_memory, llm_client, engagement_id):
        self.agent_id = "reporting-agent-001"
        self.agent_type = AgentType.REPORTING
        self.session_id = "test-session"
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.llm_client = llm_client
        self.status = "idle"
        self.current_task = None


def is_db_available():
    """Helper to check if local databases are running."""
    for port in [5432, 7687, 6379]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("127.0.0.1", port))
        except Exception:
            s.close()
            return False
        s.close()
    return True


@pytest.mark.skipif(
    not is_db_available(), reason="Database services (Postgres, Neo4j, Redis) are not running."
)
@pytest.mark.asyncio
async def test_e2e_recon_to_reporting_pipeline():
    """
    E2E Integration Test:
    1. Create a test engagement session.
    2. Simulate recon by writing an Asset and an Endpoint to GraphMemory.
    3. Run ReportingAgent to compile a report.
    4. Assert stats & graph are correctly populated (>0).
    5. Clean up.
    """
    engagement_id = "eng-test-e2e-integration-run"

    # 1. Connect to memories
    sm = SessionMemory()
    await sm.connect()

    gm = GraphMemory()
    await gm.connect()

    try:
        # 2. Create and persist test engagement state
        scope = ScopeDefinition(
            engagement_id="test-e2e-run",
            domains=["e2e-test-domain.com"],
            allowed_techniques=["recon"],
            authorization_ref="e2e-authorized",
        )
        state = SessionState(
            session_id=engagement_id,
            scope=scope,
            roe={"mode": "e2e-test"},
            phase="reconnaissance",
            agents={},
        )
        await sm.persist_session_state(state)

        # 3. Simulate recon task and persist findings
        # Create recon task
        recon_task = Task(
            id="task-e2e-recon-1",
            type="full_recon",
            agent_type=AgentType.RECON,
            engagement_id=engagement_id,
            payload={"domain": "e2e-test-domain.com"},
        )
        await sm.store_task(recon_task)
        await gm.upsert_task(recon_task)

        # Persist a discovered subdomain asset
        subdomain_asset = Asset(
            id=f"asset-subdomain-e2e",
            type="subdomain",
            value="app.e2e-test-domain.com",
            source="amass+subfinder",
            confidence=0.9,
            engagement_id=engagement_id,
        )
        await gm.add_asset(subdomain_asset)

        # Persist a discovered web endpoint
        web_endpoint = Endpoint(
            id="endpoint-e2e-1",
            type="web",
            url="https://app.e2e-test-domain.com/login",
            method="GET",
            confidence=1.0,
            engagement_id=engagement_id,
            source="scan_base",
        )
        await gm.add_endpoint(web_endpoint)

        # Complete recon task
        recon_task.status = "completed"
        await sm.store_task(recon_task)
        await gm.upsert_task(recon_task)

        # 4. Generate the report via ReportingAgent
        ctx = MockAgentContext(sm, gm, LiteLLMClient(), engagement_id)
        agent = ReportingAgent(ctx)
        await agent.initialize()

        report_task = Task(
            id="task-e2e-report-1",
            type="generate_report",
            agent_type=AgentType.REPORTING,
            engagement_id=engagement_id,
            payload={"version": "v1.0-e2e"},
        )
        ctx.current_task = report_task

        result = await agent._execute(report_task)
        assert result["status"] == "success"

        # 5. Assert report files on disk are correct
        report_json_path = f"reports/{engagement_id}/report-{engagement_id}-v1.0-e2e.json"
        assert os.path.exists(report_json_path)

        with open(report_json_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        # Assert stats are correctly mapped and > 0!
        assert report_data["stats"]["assets_count"] == 1
        assert report_data["stats"]["endpoints_count"] == 1

        # Assert attack graph is correctly populated with nodes and edges
        report_graph_path = f"reports/{engagement_id}/report-{engagement_id}-v1.0-e2e.graph.html"
        assert os.path.exists(report_graph_path)
        with open(report_graph_path, "r", encoding="utf-8") as f:
            graph_html = f.read()

        # The graph must contain our simulated asset and endpoint IDs
        assert "asset-subdomain-e2e" in graph_html
        assert "endpoint-e2e-1" in graph_html

        # Assert both certificates exist on disk
        cert_quality_path = f"reports/{engagement_id}/MISSION_QUALITY_CERTIFICATE.md"
        cert_surface_path = f"reports/{engagement_id}/ATTACK_SURFACE_EXPANSION_CERTIFICATE.md"
        assert os.path.exists(cert_quality_path)
        assert os.path.exists(cert_surface_path)
    finally:
        # 6. Cleanup database records
        # Clean Neo4j
        async with gm._driver.session() as s:
            await s.run("MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n", eid=engagement_id)

        # Clean PostgreSQL
        async with sm._async_session() as session:
            from sqlalchemy import text

            await session.execute(
                text("DELETE FROM audit_logs WHERE engagement_id = :eid"), {"eid": engagement_id}
            )
            await session.execute(
                text("DELETE FROM tasks WHERE engagement_id = :eid"), {"eid": engagement_id}
            )
            await session.execute(
                text("DELETE FROM session_states WHERE session_id = :eid"), {"eid": engagement_id}
            )
            await session.commit()

        await sm.close()
        await gm.close()

        # Clean reports directory
        reports_dir = os.path.join("reports", engagement_id)
        if os.path.exists(reports_dir):
            for f in os.listdir(reports_dir):
                os.remove(os.path.join(reports_dir, f))
            os.rmdir(reports_dir)
