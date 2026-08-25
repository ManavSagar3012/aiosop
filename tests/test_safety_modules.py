"""Integration tests for new safety modules (T1.1-T3.4)."""

import asyncio
import json
import time

import pytest

from ai_osop.core.config import AgentType


# ── Tool Call Validator ────────────────────────────────────────────────────────


class TestToolCallValidator:
    """Tests for ToolCallValidator (T1.1)."""

    def test_allows_appropriate_server(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        result = v.validate(
            AgentType.RECON,
            {"server": "recon-mcp", "name": "scan", "parameters": {}},
        )
        assert result.allowed

    def test_blocks_inappropriate_server(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        result = v.validate(
            AgentType.RECON,
            {"server": "security-bridge", "name": "exploit", "parameters": {}},
        )
        assert not result.allowed
        assert "cannot use server" in result.reason

    def test_blocks_unknown_server(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        v._known_servers = {"recon-mcp", "nuclei-mcp"}
        result = v.validate(
            AgentType.RECON,
            {"server": "fake-server", "name": "scan", "parameters": {}},
        )
        assert not result.allowed
        assert "Unknown MCP server" in result.reason

    def test_allows_internal_tools(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        result = v.validate(
            AgentType.RECON,
            {"server": "internal", "name": "store_asset", "parameters": {}},
        )
        assert result.allowed

    def test_detects_command_injection(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        result = v.validate(
            AgentType.RECON,
            {"server": "recon-mcp", "name": "scan", "parameters": {"url": "http://x | bash"}},
        )
        assert not result.allowed
        assert "injection" in result.reason.lower()

    def test_truncates_long_params(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        long_value = "x" * 3000
        result = v.validate(
            AgentType.RECON,
            {"server": "recon-mcp", "name": "scan", "parameters": {"url": long_value}},
        )
        assert result.allowed
        assert len(result.sanitized_params["url"]) <= 2048

    def test_validates_complete_action_plan(self):
        from ai_osop.safety.tool_call_validator import ToolCallValidator

        v = ToolCallValidator()
        plan = {"action": "complete", "reasoning": {"why_chosen": "done"}}
        result = v.validate_action_plan(AgentType.RECON, plan)
        assert result.allowed

    def test_all_agent_types_have_policy(self):
        from ai_osop.safety.tool_call_validator import AGENT_TOOL_POLICY

        for agent_type in AgentType:
            assert agent_type in AGENT_TOOL_POLICY, f"Missing policy for {agent_type}"


# ── Output Schema ──────────────────────────────────────────────────────────────


class TestOutputSchema:
    """Tests for output schema enforcement (T1.2)."""

    def test_valid_tool_action(self):
        from ai_osop.safety.output_schema import validate_action_plan

        plan = json.dumps({
            "action": "tool",
            "reasoning": {"observation": "test", "why_chosen": "because"},
            "tool_call": {"server": "recon-mcp", "name": "scan", "parameters": {}},
        })
        result = validate_action_plan(plan)
        assert result["action"] == "tool"

    def test_valid_complete_action(self):
        from ai_osop.safety.output_schema import validate_action_plan

        plan = json.dumps({
            "action": "complete",
            "reasoning": {"why_chosen": "done"},
            "conclusion": "Task finished",
        })
        result = validate_action_plan(plan)
        assert result["action"] == "complete"

    def test_rejects_invalid_json(self):
        from ai_osop.safety.output_schema import validate_action_plan

        with pytest.raises(ValueError, match="not valid JSON"):
            validate_action_plan("not json")

    def test_rejects_missing_action(self):
        from ai_osop.safety.output_schema import validate_action_plan

        with pytest.raises(ValueError, match="Missing required field 'action'"):
            validate_action_plan(json.dumps({"reasoning": {"why_chosen": "test"}}))

    def test_rejects_invalid_action(self):
        from ai_osop.safety.output_schema import validate_action_plan

        with pytest.raises(ValueError, match="Invalid action"):
            validate_action_plan(json.dumps({"action": "hack", "reasoning": {"why_chosen": "test"}}))

    def test_rejects_missing_reasoning(self):
        from ai_osop.safety.output_schema import validate_action_plan

        with pytest.raises(ValueError, match="reasoning"):
            validate_action_plan(json.dumps({"action": "complete"}))

    def test_rejects_tool_without_tool_call(self):
        from ai_osop.safety.output_schema import validate_action_plan

        with pytest.raises(ValueError, match="tool_call"):
            validate_action_plan(json.dumps({
                "action": "tool",
                "reasoning": {"why_chosen": "test"},
            }))

    def test_rejects_non_dict_output(self):
        from ai_osop.safety.output_schema import validate_action_plan

        with pytest.raises(ValueError, match="JSON object"):
            validate_action_plan(json.dumps([1, 2, 3]))

    def test_auto_fills_conclusion(self):
        from ai_osop.safety.output_schema import validate_action_plan

        result = validate_action_plan(json.dumps({
            "action": "complete",
            "reasoning": {"why_chosen": "done"},
        }))
        assert "conclusion" in result

    def test_sanitize_strips_control_chars(self):
        from ai_osop.safety.output_schema import sanitize_tool_params

        params = {"url": "http://x\x00\x01test"}
        result = sanitize_tool_params(params)
        assert "\x00" not in result["url"]
        assert "\x01" not in result["url"]


# ── Stagnation Detector ────────────────────────────────────────────────────────


class TestStagnationDetector:
    """Tests for agent stagnation detection (T2.1)."""

    def test_no_stagnation_with_few_observations(self):
        from ai_osop.orchestrator.stagnation_detector import StagnationDetector

        d = StagnationDetector()
        for i in range(3):
            d.record_observation("agent-1", "task-1", f"tool_{i}", f"result_{i}", 0.5 + i * 0.1, i)
        report = d.check_stagnation("agent-1", "task-1", 3, 0.7)
        assert report is None

    def test_detects_repetition(self):
        from ai_osop.orchestrator.stagnation_detector import StagnationDetector

        d = StagnationDetector(repetition_threshold=3)
        for i in range(5):
            d.record_observation("agent-1", "task-1", "scan", "same_result", 0.3, i)
        report = d.check_stagnation("agent-1", "task-1", 5, 0.3)
        assert report is not None
        assert report.stagnation_type == "repetition"
        assert report.severity == "high"

    def test_detects_token_burn(self):
        from ai_osop.orchestrator.stagnation_detector import StagnationDetector

        d = StagnationDetector(token_burn_threshold=5)
        for i in range(10):
            d.record_observation("agent-1", "task-1", f"tool_{i % 3}", f"result_{i}", 0.3 + i * 0.01, i)
        report = d.check_stagnation("agent-1", "task-1", 12, 0.35)
        assert report is not None
        assert report.stagnation_type == "token_burn"

    def test_detects_confidence_plateau(self):
        from ai_osop.orchestrator.stagnation_detector import StagnationDetector

        d = StagnationDetector()
        for i in range(6):
            d.record_observation("agent-1", "task-1", f"tool_{i}", f"result_{i}", 0.50, i)
        report = d.check_stagnation("agent-1", "task-1", 6, 0.50)
        assert report is not None
        assert report.stagnation_type == "confidence_plateau"

    def test_clear_agent(self):
        from ai_osop.orchestrator.stagnation_detector import StagnationDetector

        d = StagnationDetector()
        d.record_observation("agent-1", "task-1", "scan", "result", 0.5, 0)
        d.clear_agent("agent-1")
        assert "agent-1" not in d._history

    def test_get_stats(self):
        from ai_osop.orchestrator.stagnation_detector import StagnationDetector

        d = StagnationDetector()
        d.record_observation("agent-1", "task-1", "scan", "result", 0.5, 0)
        stats = d.get_stats()
        assert stats["tracked_agents"] == 1
        assert stats["total_observations"] == 1


# ── Effort Tracker ─────────────────────────────────────────────────────────────


class TestEffortTracker:
    """Tests for effort budget tracking (T2.2)."""

    def test_start_and_record(self):
        from ai_osop.core.effort_tracker import EffortTracker

        t = EffortTracker()
        t.start_tracking("f1", "eng-1", "agent-1", "task-1", 0.3)
        t.record_iteration("f1", "scan", tokens=1000, confidence=0.4)
        effort = t.get_effort("f1")
        assert effort.iterations == 1
        assert effort.tokens_used == 1000
        assert effort.confidence_current == 0.4

    def test_multiple_iterations(self):
        from ai_osop.core.effort_tracker import EffortTracker

        t = EffortTracker()
        t.start_tracking("f1", "eng-1", "agent-1", "task-1")
        for i in range(5):
            t.record_iteration("f1", f"tool_{i}", tokens=500, confidence=0.3 + i * 0.1)
        effort = t.get_effort("f1")
        assert effort.iterations == 5
        assert effort.tokens_used == 2500
        assert effort.confidence_peak == 0.7

    def test_over_budget_detection(self):
        from ai_osop.core.effort_tracker import EffortTracker, MAX_ITERATIONS

        t = EffortTracker()
        t.start_tracking("f1", "eng-1", "agent-1", "task-1")
        for i in range(MAX_ITERATIONS + 1):
            t.record_iteration("f1", "scan", tokens=100, confidence=0.3)
        effort = t.get_effort("f1")
        assert effort.is_over_budget

    def test_completion(self):
        from ai_osop.core.effort_tracker import EffortTracker

        t = EffortTracker()
        t.start_tracking("f1", "eng-1", "agent-1", "task-1")
        t.record_iteration("f1", "scan", tokens=500, confidence=0.8)
        t.complete_tracking("f1", final_confidence=0.9)
        effort = t.get_effort("f1")
        assert effort.status == "completed"

    def test_engagement_summary(self):
        from ai_osop.core.effort_tracker import EffortTracker

        t = EffortTracker()
        t.start_tracking("f1", "eng-1", "agent-1", "task-1")
        t.start_tracking("f2", "eng-1", "agent-1", "task-2")
        t.record_iteration("f1", "scan", tokens=500, confidence=0.8)
        t.record_iteration("f2", "nuclei", tokens=300, confidence=0.6)
        summary = t.get_engagement_summary("eng-1")
        assert summary["finding_count"] == 2
        assert summary["total_tokens"] == 800


# ── Effectiveness Tracker ──────────────────────────────────────────────────────


class TestEffectivenessTracker:
    """Tests for tool effectiveness tracking (T3.1/T3.2)."""

    def test_record_and_query(self):
        from ai_osop.core.effectiveness_tracker import EffectivenessTracker

        t = EffectivenessTracker()
        t.record_execution("nuclei", "web", "xss", "eng-1", yielded_finding=True, finding_validated=True)
        score = t.get_effectiveness("nuclei", "web", "xss")
        assert score.total_runs == 1
        assert score.findings_validated == 1
        assert score.composite_score > 0

    def test_low_yield_detection(self):
        from ai_osop.core.effectiveness_tracker import EffectivenessTracker

        t = EffectivenessTracker()
        for i in range(10):
            t.record_execution("bad_tool", "web", "xss", f"eng-{i}", yielded_finding=False)
        score = t.get_effectiveness("bad_tool", "web", "xss")
        assert score.is_low_yield
        assert t.should_skip_tool("bad_tool", "web", "xss", min_runs=5)

    def test_high_yield_detection(self):
        from ai_osop.core.effectiveness_tracker import EffectivenessTracker

        t = EffectivenessTracker()
        for i in range(10):
            t.record_execution("good_tool", "web", "sqli", f"eng-{i}",
                             yielded_finding=True, finding_validated=True, confidence=0.9)
        score = t.get_effectiveness("good_tool", "web", "sqli")
        assert score.is_high_yield

    def test_recommendations(self):
        from ai_osop.core.effectiveness_tracker import EffectivenessTracker

        t = EffectivenessTracker()
        t.record_execution("nuclei", "web", "xss", "eng-1", yielded_finding=True, finding_validated=True)
        t.record_execution("burp", "web", "xss", "eng-1", yielded_finding=True, finding_validated=False)
        recs = t.get_recommendations("web", ["xss"], max_results=5)
        assert len(recs) >= 1
        assert recs[0].composite_score >= recs[-1].composite_score


# ── Reproduction Generator ─────────────────────────────────────────────────────


class TestReproductionGenerator:
    """Tests for reproduction script generation (T2.3/T2.4)."""

    def test_generates_sqli_script(self):
        from ai_osop.core.reproduction_generator import ReproductionGenerator

        class FakeFinding:
            id = "vuln-1"
            title = "SQL Injection in login"
            category = "sqli"
            target = "http://example.com/login"
            description = "SQL injection via username param"
            evidence = []
            cvss_score = 8.5
            cwe_id = "CWE-89"
            tool_source = "nuclei"
            confidence = 0.9
            engagement_id = "eng-1"

        gen = ReproductionGenerator()
        script = gen.generate_script(FakeFinding())
        assert "SQL Injection" in script
        assert "example.com" in script
        assert "requests" in script

    def test_generates_xss_script(self):
        from ai_osop.core.reproduction_generator import ReproductionGenerator

        class FakeFinding:
            id = "vuln-2"
            title = "Reflected XSS"
            category = "xss"
            target = "http://example.com/search"
            description = "XSS via q param"
            evidence = []
            cvss_score = 6.5
            cwe_id = "CWE-79"
            tool_source = "nuclei"
            confidence = 0.8
            engagement_id = "eng-1"

        gen = ReproductionGenerator()
        script = gen.generate_script(FakeFinding())
        assert "XSS" in script
        assert "alert" in script

    def test_creates_evidence_package(self):
        from ai_osop.core.reproduction_generator import ReproductionGenerator

        class FakeFinding:
            id = "vuln-3"
            title = "Test vuln"
            category = "sqli"
            target = "http://test.com"
            description = "Test"
            evidence = [{"request": "GET /test", "response": "200 OK"}]
            cvss_score = 7.0
            cwe_id = "CWE-89"
            tool_source = "nuclei"
            confidence = 0.85
            engagement_id = "eng-1"
            severity = "high"

        gen = ReproductionGenerator()
        package = gen.create_evidence_package(FakeFinding())
        assert package.finding_id == "vuln-3"
        assert len(package.request_response_pairs) == 1
        assert len(package.reproduction_script) > 0

    def test_renders_markdown(self):
        from ai_osop.core.reproduction_generator import ReproductionGenerator

        class FakeFinding:
            id = "vuln-4"
            title = "Test"
            category = "xss"
            target = "http://test.com"
            description = "Desc"
            evidence = []
            cvss_score = 5.0
            cwe_id = ""
            tool_source = "nuclei"
            confidence = 0.7
            engagement_id = "eng-1"
            severity = "medium"

        gen = ReproductionGenerator()
        package = gen.create_evidence_package(FakeFinding())
        md = gen.render_markdown_report(package)
        assert "# Vulnerability Report" in md
        assert "Test" in md


# ── Self Test Runner ───────────────────────────────────────────────────────────


class TestSelfTestRunner:
    """Tests for adversarial self-testing (T3.3)."""

    @pytest.mark.asyncio
    async def test_run_all(self):
        from ai_osop.safety.self_test import SelfTestRunner

        runner = SelfTestRunner()
        suite = await runner.run_all()
        assert suite.total > 0
        assert suite.passed + suite.failed == suite.total

    @pytest.mark.asyncio
    async def test_scope_enforcement_test(self):
        from ai_osop.safety.self_test import SelfTestRunner

        runner = SelfTestRunner()
        result = await runner._test_scope_enforcement()
        assert result.passed
        assert result.severity == "critical"

    @pytest.mark.asyncio
    async def test_approval_gate_test(self):
        from ai_osop.safety.self_test import SelfTestRunner

        runner = SelfTestRunner()
        result = await runner._test_approval_gate()
        assert result.passed
        assert result.severity == "critical"

    @pytest.mark.asyncio
    async def test_prompt_injection_defense_test(self):
        from ai_osop.safety.self_test import SelfTestRunner

        runner = SelfTestRunner()
        result = await runner._test_prompt_injection_defense()
        assert result.passed

    @pytest.mark.asyncio
    async def test_tool_call_validator_test(self):
        from ai_osop.safety.self_test import SelfTestRunner

        runner = SelfTestRunner()
        result = await runner._test_tool_call_validator()
        assert result.passed


# ── Agent Pool Manager ─────────────────────────────────────────────────────────


class TestAgentPoolManager:
    """Tests for per-engagement agent pools (T3.4)."""

    def test_create_and_get_pool(self):
        from ai_osop.orchestrator.agent_pool import AgentPoolManager

        m = AgentPoolManager()
        pool = m.create_pool("eng-1", max_concurrent_agents=3)
        assert pool.engagement_id == "eng-1"
        assert pool.quota.max_concurrent_agents == 3
        assert m.get_pool("eng-1") is pool

    def test_claim_and_release_agent(self):
        from ai_osop.orchestrator.agent_pool import AgentPoolManager

        m = AgentPoolManager()
        pool = m.create_pool("eng-1", max_concurrent_agents=2)
        assert asyncio.get_event_loop().run_until_complete(pool.claim_agent("agent-1"))
        assert pool.quota.active_agents == 1
        assert asyncio.get_event_loop().run_until_complete(pool.claim_agent("agent-2"))
        assert pool.quota.active_agents == 2
        # Third should fail
        assert not asyncio.get_event_loop().run_until_complete(pool.claim_agent("agent-3"))

    def test_global_status(self):
        from ai_osop.orchestrator.agent_pool import AgentPoolManager

        m = AgentPoolManager()
        m.create_pool("eng-1")
        m.create_pool("eng-2")
        status = m.get_global_status()
        assert status["engagement_count"] == 2

    def test_priority_order(self):
        from ai_osop.orchestrator.agent_pool import AgentPoolManager

        m = AgentPoolManager()
        m.create_pool("eng-low", priority=1)
        m.create_pool("eng-high", priority=10)
        order = m.get_priority_order()
        assert order[0] == "eng-high"
        assert order[1] == "eng-low"

    def test_remove_pool(self):
        from ai_osop.orchestrator.agent_pool import AgentPoolManager

        m = AgentPoolManager()
        m.create_pool("eng-1")
        m.remove_pool("eng-1")
        assert m.get_pool("eng-1") is None
