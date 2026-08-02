"""Canonical vulnerability taxonomy: CWE + CVSS 3.1 for each vuln_type.

Single source of truth so reports are submission-grade even when a detector
did not populate cwe/cvss at write time. finding_view backfills *only when the
node has no value of its own* — real detector-provided CWE/CVSS always wins.

CVSS vectors are conservative base scores for the typical shape of each class
on a web target; a detector that knows better (e.g. auth-bypass SQLi vs blind)
should still set its own cvss_score/cvss_vector and this table will defer to it.
"""

from __future__ import annotations

from typing import Dict, NamedTuple, Optional

import structlog

logger = structlog.get_logger(__name__)


class VulnTaxon(NamedTuple):
    cwe: str
    cvss_vector: str
    cvss_score: float
    severity: str  # canonical severity implied by the base score
    mitre_id: str = ""  # MITRE ATT&CK technique ID, e.g. "T1190"


# Keyed by normalized vuln_type. Keep keys lowercase/underscored.
_TAXONOMY: Dict[str, VulnTaxon] = {
    "sqli": VulnTaxon(
        "CWE-89", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical", "T1190"
    ),
    "xss": VulnTaxon(
        "CWE-79", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium", "T1189"
    ),
    "stored_xss": VulnTaxon(
        "CWE-79", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", 8.3, "high", "T1189"
    ),
    "idor": VulnTaxon(
        "CWE-639", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "medium", "T1213"
    ),
    "broken_access_control": VulnTaxon(
        "CWE-284", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "high", "T1190"
    ),
    "mass_assignment": VulnTaxon(
        "CWE-915", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "high", "T1190"
    ),
    "jwt_abuse": VulnTaxon(
        "CWE-347", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "critical", "T1528"
    ),
    "csrf": VulnTaxon(
        "CWE-352", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5, "medium", "T1204.001"
    ),
    "authentication_weakness": VulnTaxon(
        "CWE-287", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high", "T1078"
    ),
    "ssrf": VulnTaxon(
        "CWE-918", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", 8.5, "high", "T1190"
    ),
    "xxe": VulnTaxon(
        "CWE-611", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high", "T1190"
    ),
    "open_redirect": VulnTaxon(
        "CWE-601", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.7, "medium", "T1204.001"
    ),
    "redirect_chain": VulnTaxon(
        "CWE-601", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.7, "medium", "T1204.001"
    ),
}

# Common aliases seen from different detectors -> canonical key.
_ALIASES = {
    "sql_injection": "sqli",
    "sqli_oracle": "sqli",
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    "insecure_direct_object_reference": "idor",
    "bola": "idor",
    "access_control": "broken_access_control",
    "bfla": "broken_access_control",
    "jwt": "jwt_abuse",
    "jwt_none": "jwt_abuse",
    "server_side_request_forgery": "ssrf",
    "xml_external_entity": "xxe",
    "openredirect": "open_redirect",
    "redirect": "open_redirect",
}


def normalize_type(vuln_type: Optional[str]) -> str:
    key = str(vuln_type or "").strip().lower()
    return _ALIASES.get(key, key)


def taxon_for(vuln_type: Optional[str]) -> Optional[VulnTaxon]:
    """Return the taxonomy entry for a vuln_type, or None if unmapped
    (e.g. 'unknown') — callers must tolerate None and not fabricate data."""
    return _TAXONOMY.get(normalize_type(vuln_type))


if __name__ == "__main__":
    assert taxon_for("sqli").cwe == "CWE-89"
    assert taxon_for("sql_injection").cwe == "CWE-89"  # alias
    assert taxon_for("jwt_abuse").cvss_score == 9.1
    assert taxon_for("csrf").cvss_vector.startswith("CVSS:3.1/")
    assert taxon_for("unknown") is None  # unmapped -> no fabrication
    assert taxon_for(None) is None
    logger.info("vuln_taxonomy_self_test_passed")
