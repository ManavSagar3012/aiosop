import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "test-reporting-agent"
    ctx.agent_type = AgentType.REPORTING
    ctx.session_id = "test-session"

    ctx.llm_client = AsyncMock()
    ctx.session_memory = SimpleNamespace(
        load_session_state=AsyncMock(
            return_value=SimpleNamespace(
                session_id="test-session",
                phase="reporting",
                scope=SimpleNamespace(
                    authorization_ref="signed-test-authorization",
                    domains=["example.test"],
                    ips=[],
                ),
            )
        )
    )

    ctx.graph_memory = AsyncMock()
    ctx.graph_memory.get_graph_stats.return_value = {"assets": 5, "endpoints": 20}

    class MockNeo4jSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def run(self, query, **kwargs):
            mock_result = AsyncMock()
            mock_node = MagicMock()
            mock_node.get.side_effect = lambda k, d=None: {
                "id": "vuln-1",
                "title": "Validated finding",
                "severity": "high",
                "vuln_type": "xss",
                "engagement_id": "test-session",
                "validated": True,
                "evidence": json.dumps([{"type": "scanner", "observed_at": "2026-10-14"}]),
            }.get(k, d)
            mock_node.labels = ["Vulnerability", "Asset"]
            mock_result.data.return_value = [{"v": mock_node, "n": mock_node}]
            return mock_result

    mock_driver = MagicMock()
    mock_driver.session.return_value = MockNeo4jSession()
    ctx.graph_memory._driver = mock_driver

    return ctx


@pytest.mark.asyncio
async def test_generate_report(mock_context, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Setup dummy templates for testing
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "executive.md.j2").write_text("Exec: {{ risk_narrative }}")
    (template_dir / "technical.md.j2").write_text(
        "Tech: {% for v in findings %}{{ v.title }}{% endfor %}"
    )
    (template_dir / "attack_graph.html.j2").write_text("Graph: {{ graph_json }}")

    agent = ReportingAgent(mock_context)
    await agent._setup_resources()

    # Override template dir to our temp one
    agent.exporter.env.loader.searchpath = [str(template_dir)]

    task = Task(
        type="generate_report",
        priority=5,
        agent_type=AgentType.REPORTING,
        payload={"version": "v1.1"},
        engagement_id="test-session",
    )
    # Set current task in context
    agent.ctx.current_task = task

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["version"] == "v1.1"
    assert result["requires_approval"] is True
    assert "report-test-session-v1.1" in agent.generated_reports

    report_data = agent.generated_reports["report-test-session-v1.1"]
    assert "1 graph-marked finding" in report_data["markdown"]
    assert "source authenticity is UNKNOWN" in report_data["markdown"]
    assert "Tech: Validated finding" in report_data["markdown"]
    assert "Graph:" in report_data["graph_html"]
    assert "<script>alert(1)</script>" not in report_data["markdown"]
    assert result["signature_status"] == "not_signed"
    assert result["verification_status"] == "graph_marked_candidates_unverified"
    assert result["findings_included"] == 1
    mock_context.llm_client.complete.assert_not_awaited()
    for extension, path in result["report_paths"].items():
        assert (
            hashlib.sha256(Path(path).read_bytes()).hexdigest()
            == result["artifact_sha256"][extension]
        )
    manifest = json.loads(Path(result["report_paths"]["manifest"]).read_text(encoding="utf-8"))
    assert manifest["artifacts"] == {
        extension: digest
        for extension, digest in result["artifact_sha256"].items()
        if extension != "manifest"
    }
    assert manifest["signature_status"] == "not_signed"
    assert (
        json.loads(Path(result["report_path"]).read_text(encoding="utf-8"))["findings"][0][
            "validated"
        ]
        is False
    )


@pytest.mark.asyncio
async def test_compile_evidence(mock_context):
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()

    task = Task(
        type="compile_evidence",
        priority=5,
        agent_type=AgentType.REPORTING,
        payload={"evidence": ["test payload data"]},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert len(result["compiled_evidence"]) == 1
    assert result["compiled_evidence"][0]["content"] == "test payload data"
    # Check SHA-256 hash of "test payload data"
    import hashlib

    expected_hash = hashlib.sha256(b"test payload data").hexdigest()
    assert result["compiled_evidence"][0]["sha256"] == expected_hash


def _report_task(version="v1.0"):
    return Task(
        type="generate_report",
        priority=5,
        agent_type=AgentType.REPORTING,
        payload={"version": version},
        engagement_id="test-session",
    )


def _set_graph_nodes(context, nodes):
    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return False

        async def run(self, query, **kwargs):
            assert "v.validated = true" in query
            assert kwargs == {"eid": "test-session", "limit": 201}
            return SimpleNamespace(data=AsyncMock(return_value=[{"v": node} for node in nodes]))

    context.graph_memory._driver = SimpleNamespace(session=lambda: Session())


@pytest.mark.asyncio
async def test_no_verified_findings_never_implies_safe_target(mock_context, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _set_graph_nodes(
        mock_context,
        [
            {
                "id": "vuln-unconfirmed",
                "engagement_id": "test-session",
                "validated": False,
                "title": "A scanner suspicion",
                "severity": "critical",
                "evidence": [{"type": "scanner"}],
            },
            {
                "id": "vuln-out-of-scope",
                "engagement_id": "other-engagement",
                "validated": True,
                "title": "Someone else's verified vulnerability",
                "severity": "critical",
                "evidence": [{"type": "scanner"}],
            },
            {
                "id": "vuln-unsupported",
                "engagement_id": "test-session",
                "validated": True,
                "title": "No linked evidence",
                "severity": "high",
                "evidence": [],
            },
        ],
    )
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task()
    result = await agent._execute(agent.ctx.current_task)
    assert result["status"] == "success"
    assert result["findings_included"] == 0
    assert result["verification_status"] == "no_verified_findings"
    assert (
        "No graph-marked vulnerabilities"
        in agent.generated_reports[result["report_id"]]["markdown"]
    )
    assert "does not demonstrate" in agent.generated_reports[result["report_id"]]["markdown"]
    mock_context.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_verified_report_has_actual_evidence_digest_without_raw_secrets(
    mock_context, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    secret = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    evidence = [{"type": "http", "authorization": secret, "raw_request": "password=secret-value"}]
    _set_graph_nodes(
        mock_context,
        [
            {
                "id": "vuln-real",
                "engagement_id": "test-session",
                "validated": True,
                "title": "Restricted endpoint Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
                "description": "Never show password=secret-value",
                "severity": "critical",
                "vuln_type": "idor",
                "endpoint_id": "endpoint-1",
                "evidence": json.dumps(evidence),
            }
        ],
    )
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task()
    result = await agent._execute(agent.ctx.current_task)
    context = json.loads(Path(result["report_path"]).read_text(encoding="utf-8"))
    finding = context["findings"][0]
    expected = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert finding["evidence_hash"] == expected
    assert finding["event_id"] == "Not recorded"
    assert finding["severity"] == "CRITICAL"
    for file_path in result["report_paths"].values():
        content = Path(file_path).read_text(encoding="utf-8")
        assert secret not in content
        assert "secret-value" not in content
        assert "<script>alert(1)</script>" not in content
        assert "Response: 200 OK" not in content
    assert not any(node["event_id"].startswith("evt-") for node in context["findings"])


@pytest.mark.asyncio
async def test_graph_failure_is_not_published_as_no_findings(mock_context, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_context.graph_memory.get_graph_stats.side_effect = ConnectionError("neo4j down")
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task()
    with pytest.raises(AgentException, match="could not be read"):
        await agent._execute(agent.ctx.current_task)
    assert not list(tmp_path.rglob("report-*.json"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "evidence",
    ["{not-json", "null", "{}", "[]", "[{}]", '[{"type":"scan"},{}]'],
)
async def test_malformed_or_missing_evidence_never_becomes_verified_finding(
    mock_context, tmp_path, monkeypatch, evidence
):
    monkeypatch.chdir(tmp_path)
    _set_graph_nodes(
        mock_context,
        [
            {
                "id": "vuln-no-proof",
                "engagement_id": "test-session",
                "validated": True,
                "title": "Potential finding",
                "severity": "critical",
                "evidence": evidence,
            }
        ],
    )
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task()
    result = await agent._execute(agent.ctx.current_task)
    assert result["findings_included"] == 0
    assert result["verification_status"] == "no_verified_findings"


@pytest.mark.asyncio
async def test_report_storage_failure_cannot_claim_success(mock_context, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _set_graph_nodes(mock_context, [])
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task()

    def failed_mkdir(*args, **kwargs):
        raise OSError("read-only report disk")

    monkeypatch.setattr("ai_osop.agents.reporting_agent.Path.mkdir", failed_mkdir)
    with pytest.raises(AgentException, match="could not be persisted"):
        await agent._execute(agent.ctx.current_task)
    assert agent.generated_reports == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope,phase",
    [
        (SimpleNamespace(authorization_ref=None, domains=["example.test"], ips=[]), "reporting"),
        (SimpleNamespace(authorization_ref="signed", domains=[], ips=[]), "reporting"),
        (SimpleNamespace(authorization_ref="signed", domains=["example.test"], ips=[]), "halted"),
    ],
)
async def test_revoked_scope_cannot_emit_report(mock_context, tmp_path, monkeypatch, scope, phase):
    monkeypatch.chdir(tmp_path)
    mock_context.session_memory.load_session_state.return_value.scope = scope
    mock_context.session_memory.load_session_state.return_value.phase = phase
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task()
    with pytest.raises(AgentException, match="not currently authorized"):
        await agent._execute(agent.ctx.current_task)
    mock_context.graph_memory.get_graph_stats.assert_not_awaited()
    assert not list(tmp_path.rglob("report-*.json"))


@pytest.mark.asyncio
async def test_unsafe_version_is_rejected_before_file_access(mock_context, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    agent.ctx.current_task = _report_task("../escaping")
    with pytest.raises(AgentException, match="Unsafe report identifier"):
        await agent._execute(agent.ctx.current_task)
    mock_context.graph_memory.get_graph_stats.assert_not_awaited()


@pytest.mark.asyncio
async def test_compiled_evidence_masks_secrets_without_changing_source_digest(mock_context):
    agent = ReportingAgent(mock_context)
    await agent._setup_resources()
    source = "Authorization: Bearer abcdefghijklmnopqrstuv password=private-value"
    result = await agent._compile_evidence({"evidence": [source]})
    assert result["compiled_evidence"][0]["sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert "private-value" not in result["compiled_evidence"][0]["content"]
    assert "abcdefghijklmnopqrstuv" not in result["compiled_evidence"][0]["content"]
