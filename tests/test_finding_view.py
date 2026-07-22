"""Unit tests for finding_view.py - view normalization layer.

Tests cover:
- to_finding_view() with Vulnerability model, dict, and object input
- URL / method / param fallback logic
- Evidence decoding (JSON string, list, malformed)
- CWE / CVSS backfill from taxonomy
- MITRE ATT&CK technique ID backfill
- Real detector value wins over taxonomy fallback
- Unknown vuln_type -> no fabrication
"""

import json
from typing import Any, Dict

import pytest

from ai_osop.core.enums import Severity, VulnClass
from ai_osop.core.finding_view import FindingView, to_finding_view
from ai_osop.core.models import Vulnerability
from ai_osop.core.vuln_taxonomy import taxon_for

# ---- helpers ----


def _node(**over: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "id": "vuln-test-1",
        "vuln_type": "sqli",
        "severity": "high",
        "evidence": [
            {
                "type": "sqli_oracle",
                "url": "http://target/endpoint",
                "parameter": "id",
                "payload": "' OR 1=1--",
            }
        ],
    }
    base.update(over)
    return base


def _vuln(**over: Any) -> Vulnerability:
    base = dict(
        id="vuln-model-1",
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        cwe="CWE-89",
        title="SQLi in id parameter",
        description="Test description",
        evidence=[{"type": "sqli_oracle", "url": "http://target/endpoint", "parameter": "id"}],
        tool_source="test",
        confidence=0.95,
        validated=True,
        engagement_id="eng-test-1",
    )
    base.update(over)
    return Vulnerability(**base)


class TestInputCoercion:
    def test_dict_input(self) -> None:
        view = to_finding_view(_node())
        assert view["id"] == "vuln-test-1"
        assert view["category"] == "sqli"

    def test_vulnerability_model_input(self) -> None:
        v = _vuln()
        view = to_finding_view(v)
        assert view["category"] == VulnClass.SQLI
        assert view["cwe"] == "CWE-89"

    def test_object_with_attributes(self) -> None:
        class _Obj:
            def __init__(self):
                self.id = "v4"
                self.vuln_type = "ssrf"
                self.severity = "high"
                self.evidence = [{"url": "http://obj/target"}]

        view = to_finding_view(_Obj())
        assert view["url"] == "http://obj/target"
        assert view["category"] == "ssrf"

    def test_empty_dict_returns_view_with_defaults(self) -> None:
        view = to_finding_view({})
        assert view["url"] is None
        assert view["method"] == "GET"
        assert view["param"] is None
        assert view["title"] == "Finding"
        assert view["category"] is None


class TestUrlFallback:
    def test_node_url_wins_over_evidence(self) -> None:
        view = to_finding_view(_node(url="http://primary"))
        assert view["url"] == "http://primary"

    def test_evidence_url_fallback(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"url": "http://ev"}]})
        assert view["url"] == "http://ev"

    def test_evidence_matched_at_fallback(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"matched_at": "http://ma"}]})
        assert view["url"] == "http://ma"

    def test_no_url_anywhere(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"type": "test"}]})
        assert view["url"] is None


class TestMethod:
    def test_default_is_get(self) -> None:
        view = to_finding_view({"id": "x"})
        assert view["method"] == "GET"

    def test_node_method_wins(self) -> None:
        view = to_finding_view({"id": "x", "method": "POST", "evidence": [{"method": "GET"}]})
        assert view["method"] == "POST"

    def test_evidence_method_fallback(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"method": "PUT"}]})
        assert view["method"] == "PUT"


class TestEvidence:
    def test_json_string_evidence(self) -> None:
        view = to_finding_view({"id": "x", "evidence": json.dumps([{"url": "http://json"}])})
        assert view["url"] == "http://json"

    def test_malformed_json_evidence(self) -> None:
        view = to_finding_view({"id": "x", "evidence": "{not-json}"})
        assert view["evidence"] == []

    def test_non_list_evidence(self) -> None:
        view = to_finding_view({"id": "x", "evidence": "string"})
        assert view["evidence"] == []


class TestCvssCweBackfill:
    def test_taxonomy_backfill_for_known_type(self) -> None:
        view = to_finding_view({"id": "x", "vuln_type": "sqli", "severity": "high"})
        assert view["cvss_score"] == 9.8
        assert view["cwe"] == "CWE-89"
        assert view["cvss_vector"].startswith("CVSS:3.1/")

    def test_real_value_wins_over_taxonomy(self) -> None:
        view = to_finding_view(
            {"id": "x", "vuln_type": "sqli", "cvss_score": 5.0, "cwe": "CWE-999"}
        )
        assert view["cvss_score"] == 5.0
        assert view["cwe"] == "CWE-999"

    def test_unknown_type_falls_back_to_severity_table(self) -> None:
        view = to_finding_view({"id": "x", "vuln_type": "unknown", "severity": "low"})
        assert view["cwe"] is None
        assert view["cvss_score"] == 3.0

    def test_info_severity_maps_to_zero_cvss(self) -> None:
        view = to_finding_view({"id": "x", "vuln_type": "unknown", "severity": "info"})
        assert view["cvss_score"] == 0.0


class TestMitreBackfill:
    def test_taxonomy_backfill_for_known_type(self) -> None:
        view = to_finding_view({"id": "x", "vuln_type": "sqli", "severity": "high"})
        assert view["mitre_technique_id"] == "T1190"
        assert view["mitre_tactic"] is None

    def test_real_value_wins_over_taxonomy(self) -> None:
        view = to_finding_view(
            {
                "id": "x",
                "vuln_type": "sqli",
                "mitre_technique_id": "T9999",
                "mitre_tactic": "Custom",
            }
        )
        assert view["mitre_technique_id"] == "T9999"
        assert view["mitre_tactic"] == "Custom"

    def test_unknown_type_has_no_mitre(self) -> None:
        view = to_finding_view({"id": "x", "vuln_type": "unknown", "severity": "low"})
        assert view["mitre_technique_id"] is None
        assert view["mitre_tactic"] is None


class TestTitle:
    def test_node_title_is_used(self) -> None:
        view = to_finding_view({"id": "x", "title": "My Finding", "vuln_type": "sqli"})
        assert view["title"] == "My Finding"

    def test_falls_back_to_category(self) -> None:
        view = to_finding_view({"id": "x", "vuln_type": "sqli"})
        assert view["title"] == "sqli"

    def test_falls_back_to_default(self) -> None:
        view = to_finding_view({"id": "x"})
        assert view["title"] == "Finding"


class TestParam:
    def test_param_from_parameter_key(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"parameter": "user_id"}]})
        assert view["param"] == "user_id"

    def test_param_from_injection_key(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"injection": "imageUrl"}]})
        assert view["param"] == "imageUrl"

    def test_param_from_store_field(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"store_field": "comment"}]})
        assert view["param"] == "comment"

    def test_param_none_when_missing(self) -> None:
        view = to_finding_view({"id": "x", "evidence": [{"type": "ssrf"}]})
        assert view["param"] is None
