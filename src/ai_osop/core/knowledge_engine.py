"""
Security Knowledge Engine
Unified mapping engine connecting frameworks, vulnerability classes, CWEs, CAPEC, MITRE ATT&CK, and OWASP WSTG.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai_osop.core.config import VulnClass

logger = logging.getLogger(__name__)


class SecurityKnowledgeEngine:
    """
    Security Knowledge Engine maps Vulnerability Classes to frameworks,
    vulnerability classes, CWEs, CAPEC techniques, MITRE ATT&CK techniques,
    OWASP WSTG/ASVS, and follow-up recommendation strategies.
    """

    def __init__(self, filepath: Optional[Path] = None) -> None:
        if filepath is None:
            filepath = Path(__file__).parent / "knowledge_base.json"

        self.filepath = filepath
        self._data: Dict[str, Any] = {}
        self.load_database()

    def load_database(self) -> None:
        """Safely load the mapping database from JSON."""
        try:
            if not self.filepath.exists():
                logger.warning(
                    "Knowledge base JSON file not found at %s. Initializing empty database.",
                    self.filepath,
                )
                self._data = {}
                return

            with open(self.filepath, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except Exception as e:
            logger.error(
                "Failed to load knowledge base JSON from %s: %s. Initializing empty database.",
                self.filepath,
                e,
            )
            self._data = {}

    def get_vuln_mappings(self, vuln_type: VulnClass) -> Dict[str, Any]:
        """
        Get mappings (CWE, CAPEC, MITRE ATT&CK, OWASP WSTG) for a specific vulnerability class.

        If missing or unmapped, returns a fallback dictionary with empty fields.
        """
        # Convert VulnClass enum or string to lowercase string representation
        vuln_key = (
            vuln_type.value.lower() if hasattr(vuln_type, "value") else str(vuln_type).lower()
        )

        vulns_data = self._data.get("vulnerabilities", {})
        mapping = vulns_data.get(vuln_key)

        if not mapping:
            return {
                "title": f"Unknown {vuln_key.replace('_', ' ').title()}",
                "description": "No metadata available for this vulnerability class.",
                "cwe": [],
                "capec": [],
                "mitre_attack": [],
                "owasp_wstg": [],
            }

        return {
            "title": mapping.get("title", f"Unknown {vuln_key.replace('_', ' ').title()}"),
            "description": mapping.get("description", "No description available."),
            "cwe": list(mapping.get("cwe", [])),
            "capec": list(mapping.get("capec", [])),
            "mitre_attack": list(mapping.get("mitre_attack", [])),
            "owasp_wstg": list(mapping.get("owasp_wstg", [])),
        }

    def get_tech_recommendations(self, tech: str) -> List[VulnClass]:
        """
        Get vulnerability classes most relevant to the specified technology framework.

        If technology is unknown or unmapped, returns an empty list.
        """
        if not tech:
            return []

        tech_key = tech.lower().strip()
        tech_matrix = self._data.get("technology_matrix", {})
        vuln_strings = tech_matrix.get(tech_key, [])

        recommendations: List[VulnClass] = []
        for v_str in vuln_strings:
            try:
                recommendations.append(VulnClass(v_str))
            except ValueError:
                # Safe recovery if the JSON contains unknown VulnClass strings
                logger.debug("Skipping unknown VulnClass string in technology_matrix: %s", v_str)

        return recommendations

    def get_next_steps(self, vuln_type: VulnClass) -> List[VulnClass]:
        """
        Get recommended next vulnerability scanning tasks/types to follow up.

        If missing or unmapped, returns an empty list.
        """
        vuln_key = (
            vuln_type.value.lower() if hasattr(vuln_type, "value") else str(vuln_type).lower()
        )
        recommendation_chains = self._data.get("recommendation_chains", {})
        next_step_strings = recommendation_chains.get(vuln_key, [])

        next_steps: List[VulnClass] = []
        for ns_str in next_step_strings:
            try:
                next_steps.append(VulnClass(ns_str))
            except ValueError:
                # Safe recovery if the JSON contains unknown VulnClass strings
                logger.debug(
                    "Skipping unknown VulnClass string in recommendation_chains: %s", ns_str
                )

        return next_steps
