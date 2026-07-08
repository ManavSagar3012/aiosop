import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.config import VulnClass
from ai_osop.core.knowledge_engine import SecurityKnowledgeEngine
from ai_osop.memory.graph_memory import GraphMemory


def test_knowledge_engine_init_default():
    """Verify that SecurityKnowledgeEngine can be instantiated with default database."""
    engine = SecurityKnowledgeEngine()
    assert engine.filepath.name == "knowledge_base.json"
    assert "vulnerabilities" in engine._data
    assert "technology_matrix" in engine._data
    assert "recommendation_chains" in engine._data


def test_knowledge_engine_init_missing_file(tmp_path, caplog):
    """Verify that loading a non-existent file path initializes empty database and logs warning."""
    missing_file = tmp_path / "does_not_exist.json"
    with caplog.at_level(logging.WARNING):
        engine = SecurityKnowledgeEngine(filepath=missing_file)
    assert engine._data == {}
    assert "Knowledge base JSON file not found at" in caplog.text


def test_knowledge_engine_init_corrupt_file(tmp_path, caplog):
    """Verify that loading an invalid JSON file initializes empty database and logs error."""
    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("invalid json {", encoding="utf-8")
    with caplog.at_level(logging.ERROR):
        engine = SecurityKnowledgeEngine(filepath=corrupt_file)
    assert engine._data == {}
    assert "Failed to load knowledge base JSON from" in caplog.text


def test_knowledge_engine_init_custom_file(tmp_path):
    """Verify that loading a valid custom JSON file populates database correctly."""
    custom_file = tmp_path / "custom.json"
    custom_data = {
        "vulnerabilities": {
            "sqli": {
                "title": "Custom SQLi",
                "description": "Custom SQL Injection description",
                "cwe": ["CWE-89"],
                "capec": ["CAPEC-66"],
                "mitre_attack": ["T1190"],
                "owasp_wstg": ["WSTG-INPV-05"],
            }
        },
        "technology_matrix": {"laravel": ["sqli"]},
        "recommendation_chains": {"sqli": ["rce"]},
    }
    custom_file.write_text(json.dumps(custom_data), encoding="utf-8")

    engine = SecurityKnowledgeEngine(filepath=custom_file)
    assert engine._data == custom_data


@pytest.mark.parametrize(
    "vuln_class, expected_title",
    [
        (VulnClass.SQLI, "SQL Injection (SQLi)"),
        (VulnClass.JWT_ABUSE, "JSON Web Token (JWT) Abuse"),
        (VulnClass.SSRF, "Server-Side Request Forgery (SSRF)"),
        (VulnClass.IDOR, "Insecure Direct Object References (IDOR)"),
    ],
)
def test_knowledge_engine_mappings_valid(vuln_class, expected_title):
    """Verify mappings retrieval for various valid VulnClass values."""
    engine = SecurityKnowledgeEngine()
    mapping = engine.get_vuln_mappings(vuln_class)
    assert mapping["title"] == expected_title
    assert isinstance(mapping["description"], str)
    assert isinstance(mapping["cwe"], list)
    assert isinstance(mapping["capec"], list)
    assert isinstance(mapping["mitre_attack"], list)
    assert isinstance(mapping["owasp_wstg"], list)


def test_knowledge_engine_mappings_string_input():
    """Verify mappings retrieval using string input matching VulnClass value."""
    engine = SecurityKnowledgeEngine()
    mapping = engine.get_vuln_mappings("sqli")
    assert mapping["title"] == "SQL Injection (SQLi)"


def test_knowledge_engine_mappings_unknown():
    """Verify that mapping retrieval for an unknown vulnerability class returns fallback."""
    engine = SecurityKnowledgeEngine()
    mapping = engine.get_vuln_mappings("unknown_nonexistent_class")
    assert "Unknown" in mapping["title"]
    assert mapping["description"] == "No metadata available for this vulnerability class."
    assert mapping["cwe"] == []
    assert mapping["capec"] == []
    assert mapping["mitre_attack"] == []
    assert mapping["owasp_wstg"] == []


@pytest.mark.parametrize(
    "tech, expected_vulns",
    [
        ("laravel", [VulnClass.SQLI, VulnClass.XSS, VulnClass.CSRF]),
        ("nextjs", [VulnClass.XSS, VulnClass.SSRF, VulnClass.IDOR]),
        ("redis", [VulnClass.NETWORK_ANOMALY, VulnClass.EXPOSED_SECRET]),
    ],
)
def test_knowledge_engine_tech_recommendations(tech, expected_vulns):
    """Verify technology recommendations return relevant vulnerability classes."""
    engine = SecurityKnowledgeEngine()
    recommendations = engine.get_tech_recommendations(tech)
    # Check that the expected enums are in the returned list
    for expected in expected_vulns:
        assert expected in recommendations


def test_knowledge_engine_tech_recommendations_case_insensitive():
    """Verify technology recommendations are case-insensitive and handle whitespace."""
    engine = SecurityKnowledgeEngine()
    recs1 = engine.get_tech_recommendations("  Laravel  ")
    recs2 = engine.get_tech_recommendations("LARAVEL")
    assert recs1 == recs2
    assert len(recs1) > 0


def test_knowledge_engine_tech_recommendations_unknown():
    """Verify that unknown/empty technology recommendation requests return empty list."""
    engine = SecurityKnowledgeEngine()
    assert engine.get_tech_recommendations("unknown_tech") == []
    assert engine.get_tech_recommendations("") == []
    assert engine.get_tech_recommendations(None) == []


@pytest.mark.parametrize(
    "vuln_class, expected_next",
    [
        (VulnClass.SQLI, [VulnClass.RCE, VulnClass.LFI]),
        (VulnClass.XSS, [VulnClass.CSRF, VulnClass.JWT_ABUSE]),
        (VulnClass.SSRF, [VulnClass.RCE, VulnClass.CLOUD_VULN]),
        (VulnClass.IDOR, [VulnClass.BOLA, VulnClass.BROKEN_ACCESS_CONTROL]),
    ],
)
def test_knowledge_engine_next_steps(vuln_class, expected_next):
    """Verify recommended next scanning steps for various VulnClass values."""
    engine = SecurityKnowledgeEngine()
    next_steps = engine.get_next_steps(vuln_class)
    for expected in expected_next:
        assert expected in next_steps


def test_knowledge_engine_next_steps_nonexistent():
    """Verify that next step recommendation for a nonexistent class returns empty list."""
    engine = SecurityKnowledgeEngine()
    assert engine.get_next_steps("nonexistent_vuln_type") == []


def test_knowledge_engine_next_steps_unknown_class():
    """Verify next steps recommendation for UNKNOWN VulnClass."""
    engine = SecurityKnowledgeEngine()
    next_steps = engine.get_next_steps(VulnClass.UNKNOWN)
    assert VulnClass.VULN_SCAN in next_steps


def test_knowledge_engine_robustness_empty_invalid():
    """Verify robustness and error handling for empty/invalid inputs."""
    engine = SecurityKnowledgeEngine()

    # Missing technology matrix handling gracefully
    with patch.dict(engine._data, {"technology_matrix": {}}, clear=True):
        assert engine.get_tech_recommendations("laravel") == []

    # Invalid strings in technology matrix are skipped (recovered safely)
    with patch.dict(
        engine._data, {"technology_matrix": {"test_tech": ["invalid_enum_val", "sqli"]}}, clear=True
    ):
        recs = engine.get_tech_recommendations("test_tech")
        assert recs == [VulnClass.SQLI]

    # Missing recommendation chains handled gracefully
    with patch.dict(engine._data, {"recommendation_chains": {}}, clear=True):
        assert engine.get_next_steps(VulnClass.SQLI) == []

    # Invalid strings in recommendation chains are skipped (recovered safely)
    with patch.dict(
        engine._data, {"recommendation_chains": {"sqli": ["invalid_enum_val", "rce"]}}, clear=True
    ):
        next_steps = engine.get_next_steps(VulnClass.SQLI)
        assert next_steps == [VulnClass.RCE]


@pytest.mark.asyncio
async def test_graph_memory_import_knowledge_base():
    """Verify that import_knowledge_base runs Cypher queries to import the KB."""
    # Check if the method exists on GraphMemory
    if not hasattr(GraphMemory, "import_knowledge_base"):
        pytest.skip("import_knowledge_base is not implemented yet in GraphMemory")

    # Set up mock session and driver
    queries_run = []

    class MockResult:
        async def single(self):
            return None

        async def consume(self):
            return None

        async def data(self):
            return []

        def __aiter__(self):
            async def gen():
                if False:
                    yield None

            return gen()

    class MockSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return False

        async def run(self, query, parameters=None):
            queries_run.append((query, parameters))
            return MockResult()

    mock_driver = MagicMock()
    mock_driver.session = MagicMock(return_value=MockSession())

    # Instantiate GraphMemory and inject mock driver
    gm = GraphMemory()
    gm._driver = mock_driver

    # Call the import method
    await gm.import_knowledge_base()

    # Assert that it executed queries
    assert len(queries_run) > 0
    # Verify that we run Cypher queries targeting VulnClass or Vulnerability nodes
    # and creating relationships
    queries_str = " ".join([q[0] for q in queries_run]).lower()
    assert "merge" in queries_str
