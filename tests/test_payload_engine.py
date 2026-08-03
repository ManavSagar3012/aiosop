import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import VulnClass
from ai_osop.core.models import Payload
from ai_osop.payload_engine.engine import AdaptivePayloadEngine


@pytest.fixture
def mock_mcp():
    return AsyncMock()


@pytest.fixture
def mock_llm():
    client = AsyncMock()
    # Mock LLM response for payload generation
    client.complete.return_value = {
        "content": '{"payloads": ["llm_variant_1", "llm_variant_2"]}',
        "cost": 0.01,
    }
    return client


@pytest.fixture
def engine(mock_mcp, mock_llm):
    return AdaptivePayloadEngine(mcp_adapter=mock_mcp, llm_client=mock_llm)


@pytest.mark.asyncio
async def test_generate_initial_population(engine) -> None:
    context = {"target": "http://test.com", "engagement_id": "eng-1"}
    population = await engine.generate_initial_population(
        vuln_type=VulnClass.SQLI, context=context, population_size=10
    )

    assert len(population) == 10
    assert any(p.strategy == "template" for p in population)
    assert all(p.vuln_type == VulnClass.SQLI for p in population)


@pytest.mark.asyncio
async def test_mutation_operators(engine) -> None:
    original = Payload(
        vuln_type=VulnClass.SQLI,
        content="SELECT * FROM users",
        content_hash="abc",
        context={},
        engagement_id="eng-1",
    )

    mutated = await engine._mutate(original, VulnClass.SQLI, {})

    assert mutated.content != original.content
    assert mutated.generation == original.generation + 1
    assert mutated.parent_id == original.id


@pytest.mark.asyncio
async def test_evolve_population(engine) -> None:
    context = {"target": "http://test.com", "engagement_id": "eng-1"}
    initial_population = await engine.generate_initial_population(
        vuln_type=VulnClass.SQLI, context=context, population_size=10
    )

    # Run 2 generations
    evolved = await engine.evolve_population(
        population=initial_population, vuln_type=VulnClass.SQLI, context=context, generations=2
    )

    assert len(evolved) == 10
    # Some should be genetic strategy now
    assert any(p.strategy == "genetic" for p in evolved)
    # Fitness scores should be populated
    assert all(p.fitness_score >= 0.0 for p in evolved)


@pytest.mark.asyncio
async def test_waf_learning(engine) -> None:
    target = "http://waf-target.com"
    blocked = [
        Payload(
            vuln_type=VulnClass.SQLI,
            content="UNION SELECT",
            content_hash="h1",
            context={},
            engagement_id="e1",
        )
    ]
    allowed = [
        Payload(
            vuln_type=VulnClass.SQLI,
            content="UnIoN SeLeCt",
            content_hash="h2",
            context={},
            engagement_id="e1",
        )
    ]

    profile = await engine.learn_waf_profile(target, blocked, allowed)

    assert profile["confidence"] > 0
    assert "case_randomization" in profile["suggested_strategies"]
    assert engine._waf_profiles[target] == profile


@pytest.mark.asyncio
async def test_waf_character_probing(engine) -> None:
    # Mock AsyncClient
    client_mock = AsyncMock()

    # Configure mock request response behaviors
    async def mock_request(method, url, **kwargs):
        resp = AsyncMock()
        params = kwargs.get("params") or kwargs.get("data") or {}
        val = params.get("q", "")

        if "baseline" in val:
            resp.status_code = 200
            resp.text = val
        elif "'" in val:
            resp.status_code = 403  # WAF Block
            resp.text = "Forbidden"
        elif "<" in val:
            resp.status_code = 200
            resp.text = "test value"  # Char "<" is filtered out from response
        else:
            resp.status_code = 200
            resp.text = val
        return resp

    client_mock.request = AsyncMock(side_effect=mock_request)
    engine.prober.client = client_mock

    # Run character probing
    char_map = await engine.probe_target_characters(
        target_hash="test-target",
        url="http://example.com/api",
        param_name="q",
        method="GET",
    )

    assert char_map["'"] == "blocked"
    assert char_map["<"] == "filtered"
    assert char_map[";"] == "allowed"

    # Test mutation respects the WAF character map
    original = Payload(
        vuln_type=VulnClass.SQLI,
        content="UNION SELECT 'value'",
        content_hash="orig-hash",
        context={"target_hash": "test-target"},
        engagement_id="eng-1",
    )

    # Mutate payload — since "'" is blocked, the engine should force an encoding variation
    mutated = await engine._mutate(original, VulnClass.SQLI, {"target_hash": "test-target"})
    assert len(mutated.encoding_chain) > 0
    assert any(enc in mutated.encoding_chain for enc in ["url", "hex", "unicode"])


def test_payload_engine_includes_blind_templates():
    from ai_osop.payload_engine.engine import PayloadTemplateLibrary

    lib = PayloadTemplateLibrary()
    for cls in ("blind_xss", "blind_sqli", "blind_ssti"):
        templates = lib.templates_for(cls)
        assert templates, f"missing template family {cls}"


def test_blind_templates_embed_oast_callback_placeholder():
    from ai_osop.payload_engine.engine import PayloadTemplateLibrary

    lib = PayloadTemplateLibrary()
    for cls in ("blind_xss", "blind_sqli", "blind_ssti"):
        templates = lib.templates_for(cls)
        for family in templates:
            for payload in templates[family]:
                assert (
                    "{{OAST_CALLBACK_URL}}" in payload
                ), f"{cls}/{family} payload missing OAST placeholder: {payload!r}"
