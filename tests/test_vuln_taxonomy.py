"""Unit tests for vuln_taxonomy.py - CWE/CVSS/MITRE mapping.

Tests cover:
- normalize_type() with aliases
- taxon_for() lookups for every taxonomy entry
- taxon_for() with aliases, unknown types, and None
- MITRE ATT&CK technique ID mappings
- Structural invariants (all entries have valid CWE, CVSS, etc.)
"""

from ai_osop.core.vuln_taxonomy import VulnTaxon, normalize_type, taxon_for


class TestNormalizeType:
    def test_direct_key_passthrough(self) -> None:
        assert normalize_type("sqli") == "sqli"
        assert normalize_type("xss") == "xss"
        assert normalize_type("ssrf") == "ssrf"

    def test_alias_resolution(self) -> None:
        assert normalize_type("sql_injection") == "sqli"
        assert normalize_type("cross_site_scripting") == "xss"
        assert normalize_type("server_side_request_forgery") == "ssrf"
        assert normalize_type("insecure_direct_object_reference") == "idor"
        assert normalize_type("bola") == "idor"
        assert normalize_type("jwt") == "jwt_abuse"

    def test_case_and_whitespace_normalization(self) -> None:
        assert normalize_type("  SQL_INJECTION  ") == "sqli"

    def test_none_returns_empty_string(self) -> None:
        assert normalize_type(None) == ""


class TestTaxonFor:
    def test_known_types_return_correct_taxon(self) -> None:
        t = taxon_for("sqli")
        assert t is not None
        assert t.cwe == "CWE-89"
        assert t.cvss_score == 9.8
        assert t.severity == "critical"

        t = taxon_for("ssrf")
        assert t is not None
        assert t.cwe == "CWE-918"
        assert t.cvss_score == 8.5

        t = taxon_for("xss")
        assert t is not None
        assert t.cwe == "CWE-79"
        assert t.cvss_score == 6.1

    def test_known_types_have_cvss_vector(self) -> None:
        for vuln_type in [
            "sqli",
            "xss",
            "stored_xss",
            "idor",
            "broken_access_control",
            "mass_assignment",
            "jwt_abuse",
            "csrf",
            "authentication_weakness",
            "ssrf",
            "xxe",
            "open_redirect",
            "redirect_chain",
        ]:
            t = taxon_for(vuln_type)
            assert t is not None, f"Missing taxonomy for {vuln_type}"
            assert t.cvss_vector.startswith(
                "CVSS:3.1/"
            ), f"{vuln_type}: cvss_vector={t.cvss_vector!r}"
            assert t.cvss_score > 0, f"{vuln_type}: cvss_score must be positive"

    def test_alias_resolves_to_same_taxon(self) -> None:
        assert taxon_for("sqli") is taxon_for("sql_injection")
        assert taxon_for("idor") is taxon_for("bola")
        assert taxon_for("jwt_abuse") is taxon_for("jwt")

    def test_unknown_type_returns_none(self) -> None:
        assert taxon_for("unknown") is None
        assert taxon_for("bogus_vuln_type") is None

    def test_none_returns_none(self) -> None:
        assert taxon_for(None) is None


class TestMitreMapping:
    def test_sqli_is_exploit_public_facing_app(self) -> None:
        assert taxon_for("sqli").mitre_id == "T1190"

    def test_xss_is_drive_by_compromise(self) -> None:
        assert taxon_for("xss").mitre_id == "T1189"
        assert taxon_for("stored_xss").mitre_id == "T1189"

    def test_idor_is_data_from_information_repos(self) -> None:
        assert taxon_for("idor").mitre_id == "T1213"

    def test_jwt_abuse_is_steal_app_access_token(self) -> None:
        assert taxon_for("jwt_abuse").mitre_id == "T1528"

    def test_csrf_is_user_execution_malicious_url(self) -> None:
        assert taxon_for("csrf").mitre_id == "T1204.001"
        assert taxon_for("open_redirect").mitre_id == "T1204.001"

    def test_auth_weakness_is_valid_accounts(self) -> None:
        assert taxon_for("authentication_weakness").mitre_id == "T1078"

    def test_unknown_type_has_empty_mitre_id(self) -> None:
        t = taxon_for("unknown")
        assert t is None


class TestTaxonStructure:
    def test_all_entries_have_valid_cwe(self) -> None:
        for vuln_type in [
            "sqli",
            "xss",
            "stored_xss",
            "idor",
            "broken_access_control",
            "mass_assignment",
            "jwt_abuse",
            "csrf",
            "authentication_weakness",
            "ssrf",
            "xxe",
            "open_redirect",
            "redirect_chain",
        ]:
            t = taxon_for(vuln_type)
            assert t is not None
            assert t.cwe.startswith("CWE-"), f"{vuln_type}: invalid CWE {t.cwe}"

    def test_all_entries_have_valid_severity(self) -> None:
        valid = {"critical", "high", "medium", "low", "info"}
        for vuln_type in [
            "sqli",
            "xss",
            "stored_xss",
            "idor",
            "broken_access_control",
            "mass_assignment",
            "jwt_abuse",
            "csrf",
            "authentication_weakness",
            "ssrf",
            "xxe",
            "open_redirect",
            "redirect_chain",
        ]:
            t = taxon_for(vuln_type)
            assert t is not None
            assert t.severity in valid, f"{vuln_type}: invalid severity {t.severity}"

    def test_all_entries_are_vultaxon_instance(self) -> None:
        for vuln_type in [
            "sqli",
            "xss",
            "stored_xss",
            "idor",
            "broken_access_control",
            "mass_assignment",
            "jwt_abuse",
            "csrf",
            "authentication_weakness",
            "ssrf",
            "xxe",
            "open_redirect",
            "redirect_chain",
        ]:
            t = taxon_for(vuln_type)
            assert isinstance(t, VulnTaxon), f"{vuln_type}: not a VulnTaxon"
