"""Burp agent must never promote unavailable or synthetic scanner evidence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Endpoint, Vulnerability
from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.mcp.protocol import MCPExecuteResponse


def agent():
    instance = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    graph = SimpleNamespace(
        add_asset=AsyncMock(), add_endpoint=AsyncMock(), add_vulnerability=AsyncMock()
    )
    instance.ctx = SimpleNamespace(
        graph_memory=graph,
        mcp_registry=SimpleNamespace(
            execute_tool=AsyncMock(
                return_value=SimpleNamespace(status="success", result={"findings": []})
            )
        ),
        session_memory=SimpleNamespace(get_session_state=AsyncMock(return_value=None)),
        current_task=None,
    )
    instance.burp_adapter = SimpleNamespace(
        scan_target=AsyncMock(return_value=SimpleNamespace(status="success")),
        get_scan_issues=AsyncMock(return_value=[]),
        get_sitemap=AsyncMock(return_value=[]),
        get_proxy_history=AsyncMock(return_value=[]),
        intruder_attack=AsyncMock(return_value=SimpleNamespace(status="success")),
    )
    instance.findings = {}
    instance._get_relevant_skills = AsyncMock(return_value=[])
    instance.think = AsyncMock(return_value="provider opinion only")
    return instance, graph


def candidate(*, tool_source="burp_scanner", verified=True):
    return Vulnerability(
        id="vuln-burp-unverified",
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="Provider-only candidate",
        description="opaque",
        tool_source=tool_source,
        confidence=0.9,
        engagement_id="eng-owned-burp",
        validated=verified,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failed", ["denied", "exception"])
async def test_burp_dispatch_failure_is_unknown_without_discovery_or_followup(failed):
    instance, graph = agent()
    if failed == "exception":
        instance.burp_adapter.scan_target.side_effect = OSError("secret provider payload")
    else:
        instance.burp_adapter.scan_target.return_value.status = "error"
    result = await instance._execute_burp_scan(
        {"engagement_id": "eng-owned-burp", "url": "https://owned.test/path"}
    )
    assert result["status"] == "execution_unknown"
    assert result["validation_state"] == "UNKNOWN"
    assert result["findings_count"] == 0
    assert "secret" not in str(result)
    graph.add_asset.assert_not_awaited()
    graph.add_endpoint.assert_not_awaited()
    graph.add_vulnerability.assert_not_awaited()
    instance.burp_adapter.get_scan_issues.assert_not_awaited()


@pytest.mark.asyncio
async def test_observation_failure_is_unknown_not_successful_empty_scan():
    instance, graph = agent()
    instance.burp_adapter.get_scan_issues.side_effect = OSError("private upstream")
    result = await instance._execute_burp_scan(
        {"engagement_id": "eng-owned-burp", "url": "https://owned.test"}
    )
    assert result["status"] == "execution_unknown"
    assert "private" not in str(result)
    graph.add_asset.assert_not_awaited()
    instance.burp_adapter.get_sitemap.assert_not_awaited()


@pytest.mark.asyncio
async def test_empty_scan_never_invents_simulated_vulnerabilities_and_scope_seed_is_unverified():
    instance, graph = agent()
    result = await instance._execute_burp_scan(
        {"engagement_id": "eng-owned-burp", "url": "https://owned.test"}
    )
    assert result["status"] == "success"
    assert result["validation_state"] == "candidate_unverified"
    assert result["findings_count"] == 0
    graph.add_vulnerability.assert_not_awaited()
    asset = graph.add_asset.await_args.args[0]
    assert asset.confidence == 0.0 and asset.source == "scan_scope_seed_unverified"
    endpoint = graph.add_endpoint.await_args_list[0].args[0]
    assert endpoint.confidence == 0.0


@pytest.mark.asyncio
async def test_global_proxy_history_does_not_leak_foreign_hosts_or_query_substrings():
    instance, graph = agent()
    instance.burp_adapter.get_proxy_history.return_value = [
        {"url": "https://evil.test/path?redirect=owned.test"},
        {"url": "https://owned.test.evil.test/secret"},
        {"url": "https://owned.test:444/private-different-service"},
        {"url": "http://owned.test/private-downgraded-scheme"},
        {"url": "https://owned.test/safe", "method": "GET"},
    ]
    instance.burp_adapter.get_sitemap.return_value = [
        Endpoint(url="https://evil.test/secret", engagement_id="eng-owned-burp"),
        Endpoint(url="https://owned.test/allowed", engagement_id="eng-owned-burp"),
    ]
    result = await instance._execute_burp_scan(
        {"engagement_id": "eng-owned-burp", "url": "https://owned.test"}
    )
    assert result["status"] == "success"
    assert result["endpoints_count"] == 2
    actual = [entry.args[0].url for entry in graph.add_endpoint.await_args_list]
    assert not any(
        "evil.test" in value or ":444" in value or "http://" in value for value in actual
    )


@pytest.mark.asyncio
async def test_burp_provider_candidate_cannot_set_independent_verified_or_return_private_body():
    instance, graph = agent()
    instance.burp_adapter.get_scan_issues.return_value = [candidate()]
    result = await instance._execute_burp_scan(
        {"engagement_id": "eng-owned-burp", "url": "https://owned.test"}
    )
    assert result["findings_count"] == 1
    assert result["findings"] == [
        {"id": "vuln-burp-unverified", "verification_status": "candidate_unverified"}
    ]
    persisted = graph.add_vulnerability.await_args.args[0]
    assert persisted.validated is False
    assert persisted.finding_status.value == "candidate"
    assert persisted.validation_state == "UNKNOWN"


@pytest.mark.asyncio
async def test_graph_write_uncertainty_is_not_success_or_safe_to_retry():
    instance, graph = agent()
    graph.add_vulnerability.side_effect = OSError("neo4j connection lost after write")
    instance.burp_adapter.get_scan_issues.return_value = [candidate()]
    result = await instance._execute_burp_scan(
        {"engagement_id": "eng-owned-burp", "url": "https://owned.test"}
    )
    assert result["status"] == "execution_unknown"
    assert result["reason"] == "burp_graph_projection_partial"
    assert "connection lost" not in str(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["error", "success"])
async def test_intruder_dispatch_refuses_untrusted_remote_receipt_body(status):
    instance, _ = agent()
    instance.burp_adapter.intruder_attack.return_value = SimpleNamespace(
        status=status, model_dump=lambda: {"private_headers": "Authorization: secret"}
    )
    result = await instance._execute_intruder_fuzz({"url": "https://owned.test"})
    assert result["status"] == ("success" if status == "success" else "execution_unknown")
    assert "secret" not in str(result)
    assert "mcp_response" not in result


@pytest.mark.asyncio
async def test_adapter_declined_observation_is_not_converted_to_false_empty_success():
    registry = SimpleNamespace(
        execute_tool=AsyncMock(
            return_value=SimpleNamespace(status="error", result=None, error="raw secret")
        )
    )
    adapter = BurpMCPAdapter(registry)
    for operation in (
        adapter.get_scan_issues("https://owned.test"),
        adapter.get_sitemap("owned.test"),
        adapter.get_proxy_history(),
    ):
        with pytest.raises(Exception, match="unavailable") as denied:
            await operation
        assert "raw secret" not in str(denied.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("failed", ["exception", "declined", "malformed", "missing"])
async def test_nuclei_missing_remote_receipt_cannot_create_graph_finding(failed):
    instance, graph = agent()
    registry = instance.ctx.mcp_registry
    if failed == "exception":
        registry.execute_tool.side_effect = OSError("private upstream result")
    elif failed == "declined":
        registry.execute_tool.return_value.status = "error"
    elif failed == "malformed":
        registry.execute_tool.return_value.result = {"findings": "secret raw response"}
    else:
        registry.execute_tool.return_value.result = {}
    result = await instance._execute_nuclei_scan(
        {
            "engagement_id": "eng-owned-burp",
            "targets": ["https://owned.test"],
        }
    )
    assert result["status"] == "execution_unknown"
    assert "private" not in str(result) and "secret" not in str(result)
    graph.add_vulnerability.assert_not_awaited()


@pytest.mark.asyncio
async def test_nuclei_foreign_scan_findings_are_not_persisted_or_returned():
    instance, graph = agent()
    instance.ctx.mcp_registry.execute_tool.return_value.result = {
        "findings": [
            {
                "template_id": "sqli",
                "matched_at": "https://evil.test/path?name=owned.test",
                "info": {"name": "foreign private target", "description": "private"},
            },
            {
                "template_id": "sqli",
                "matched_at": "https://owned.test/path",
                "info": {"name": "owned candidate", "description": "private receipt"},
            },
        ]
    }
    result = await instance._execute_nuclei_scan(
        {
            "engagement_id": "eng-owned-burp",
            "targets": ["https://owned.test"],
        }
    )
    assert result["status"] == "success"
    assert result["validation_state"] == "candidate_unverified"
    assert result["findings_count"] == 1
    assert "private" not in str(result)
    assert graph.add_vulnerability.await_count == 1
    assert graph.add_vulnerability.await_args.args[0].validated is False


@pytest.mark.asyncio
async def test_simple_triage_cannot_claim_heuristically_confirmed_finding_or_raise_missing_metadata():
    instance, _ = agent()
    vuln = candidate(verified=False)
    instance.findings[vuln.id] = vuln
    instance._check_false_positive = AsyncMock(return_value=False)
    result = await instance._execute_triage({"finding_id": vuln.id})
    assert result["status"] == "success"
    assert result["triage_result"] == "not_flagged_by_heuristic"
    assert result["independent_effect_verified"] is False
    assert vuln.validated is False and vuln.finding_status.value == "candidate"


@pytest.mark.asyncio
async def test_cross_tool_similarity_never_promotes_a_provider_candidate_to_verified():
    instance, _ = agent()
    vuln = candidate(verified=False)
    instance.findings[vuln.id] = vuln
    instance.ctx.graph_memory.correlate_vulnerabilities = AsyncMock(return_value=[])
    instance._find_similar_findings = AsyncMock(
        return_value=[
            vuln,
            candidate(verified=False).model_copy(update={"id": "vuln-other"}),
        ]
    )
    result = await instance._execute_correlation({"engagement_id": "eng-owned-burp"})
    assert result["status"] == "success"
    assert result["confirmed_findings"] == 0
    assert result["correlated_candidates"] == 1
    assert vuln.validated is False and vuln.validation_state == "UNKNOWN"
