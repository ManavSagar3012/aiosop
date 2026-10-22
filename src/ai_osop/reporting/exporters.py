"""
Report Exporters
Generates structured and styled reports from template data, including
SARIF v2.1.0 and CycloneDX VEX formats with cryptographic evidence linkage.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional
import uuid

import markdown
from jinja2 import Environment, FileSystemLoader

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


class ReportExporter:
    """Manages the rendering and exporting of assessment reports."""

    def __init__(self, template_dir: str):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def hash_evidence(self, content: str) -> str:
        """Create SHA-256 hash of evidence for chain of custody."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def generate_markdown(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render a Jinja2 template to Markdown."""
        template = self.env.get_template(template_name)
        return template.render(**context)

    def export_json(self, data: Dict[str, Any]) -> str:
        """Export raw structured data as JSON."""
        return json.dumps(data, indent=2)

    def markdown_to_html(self, markdown_text: str) -> str:
        """Convert Markdown report to styled HTML."""
        html_content = markdown.markdown(markdown_text, extensions=["tables", "fenced_code"])
        # Simple CSS wrapper for styled output
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 2rem; color: #24292e;
    }}
    h1, h2, h3 {{ color: #111; }}
    code {{
        background: #f6f8fa; padding: 0.2em 0.4em; border-radius: 3px;
        font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 85%;
    }}
    pre {{ background: #f6f8fa; padding: 16px; overflow: auto; border-radius: 3px; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
    th, td {{ border: 1px solid #dfe2e5; padding: 6px 13px; }}
    th {{ background-color: #f6f8fa; font-weight: 600; }}
</style>
</head>
<body>
{html_content}
</body>
</html>"""

    def render_attack_graph(self, graph_data: Dict[str, Any], engagement_id: str) -> str:
        """Render the D3.js interactive attack graph."""
        template = self.env.get_template("attack_graph.html.j2")
        return template.render(engagement_id=engagement_id, graph_json=json.dumps(graph_data))

    def export_sarif(
        self,
        findings: List[Dict[str, Any]],
        engagement_id: str = "",
        app_name: str = "AI-OSOP Security Platform",
    ) -> Dict[str, Any]:
        """Export findings to OASIS SARIF v2.1.0 format with cryptographic evidence linkage."""
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "informational": "note",
            "info": "note",
        }

        for finding in findings:
            rule_id = str(
                finding.get("cwe") or finding.get("category") or finding.get("type") or "OSOP-VULN"
            )
            rule_name = str(finding.get("title") or finding.get("name") or "Security Vulnerability")
            severity = str(finding.get("severity", "medium")).lower()
            level = level_map.get(severity, "warning")

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": rule_name,
                    "shortDescription": {"text": rule_name},
                    "fullDescription": {"text": str(finding.get("description") or rule_name)},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": ["security", "verified-pentest", finding.get("category", "general")]
                    },
                }

            endpoint_uri = str(
                finding.get("endpoint") or finding.get("url") or finding.get("target") or "/"
            )
            evidence_hashes = finding.get("evidence_hashes") or []
            if isinstance(evidence_hashes, str):
                evidence_hashes = [evidence_hashes]
            merkle_root = str(
                finding.get("merkle_root") or finding.get("evidence_merkle_root") or ""
            )

            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": str(
                            finding.get("description")
                            or finding.get("title")
                            or "Verified Vulnerability"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": endpoint_uri,
                                    "uriBaseId": "%SRCROOT%",
                                }
                            }
                        }
                    ],
                    "properties": {
                        "finding_id": str(finding.get("id") or ""),
                        "verification_status": str(
                            finding.get("verification_status")
                            or finding.get("status")
                            or "candidate"
                        ),
                        "cvss_score": float(
                            finding.get("cvss") or finding.get("severity_score") or 5.0
                        ),
                        "reproduction_curl": str(
                            finding.get("reproduction_curl")
                            or finding.get("reproduction_steps")
                            or ""
                        ),
                        "evidence_hashes": evidence_hashes,
                        "evidence_merkle_root": merkle_root,
                        "engagement_id": str(engagement_id or finding.get("engagement_id") or ""),
                    },
                }
            )

        return {
            "$schema": SARIF_SCHEMA_URL,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": app_name,
                            "version": "1.0.0",
                            "informationUri": "https://github.com/ai-osop/ai-osop",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def export_cyclonedx_vex(
        self,
        findings: List[Dict[str, Any]],
        engagement_id: str = "",
        project_name: str = "Assessment Target",
    ) -> Dict[str, Any]:
        """Export findings to CycloneDX VEX (v1.5) JSON format with Merkle root hashes."""
        vex_state_map = {
            "verified": "exploitable",
            "rejected": "false_positive",
            "validation_pending": "in_triage",
            "candidate": "in_triage",
            "inconclusive": "in_triage",
        }

        vulnerabilities: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            status_raw = str(
                finding.get("verification_status") or finding.get("status") or "candidate"
            ).lower()
            vex_state = vex_state_map.get(status_raw, "in_triage")
            fid = str(finding.get("id") or f"vuln-{uuid.uuid4().hex[:8]}")
            merkle_root = str(
                finding.get("merkle_root") or finding.get("evidence_merkle_root") or ""
            )
            evidence_hashes = finding.get("evidence_hashes") or []
            if isinstance(evidence_hashes, str):
                evidence_hashes = [evidence_hashes]

            vuln_entry: Dict[str, Any] = {
                "bom-ref": fid,
                "id": fid,
                "source": {"name": "AI-OSOP"},
                "description": str(
                    finding.get("description") or finding.get("title") or "Vulnerability"
                ),
                "ratings": [
                    {
                        "source": {"name": "AI-OSOP"},
                        "score": float(finding.get("cvss") or finding.get("severity_score") or 5.0),
                        "severity": str(finding.get("severity", "medium")).lower(),
                        "method": "CVSSv31",
                    }
                ],
                "affects": [
                    {
                        "ref": str(
                            finding.get("endpoint") or finding.get("url") or "urn:target:endpoint"
                        )
                    }
                ],
                "analysis": {
                    "state": vex_state,
                    "detail": (
                        f"Status: {status_raw}. " f"Evidence Merkle root: {merkle_root or 'none'}"
                    ),
                    "firstIssued": now_iso,
                    "lastUpdated": now_iso,
                },
                "properties": [
                    {"name": "evidence_merkle_root", "value": merkle_root},
                    {
                        "name": "reproduction_curl",
                        "value": str(
                            finding.get("reproduction_curl")
                            or finding.get("reproduction_steps")
                            or ""
                        ),
                    },
                    {"name": "evidence_hashes", "value": json.dumps(evidence_hashes)},
                    {
                        "name": "engagement_id",
                        "value": str(engagement_id or finding.get("engagement_id") or ""),
                    },
                ],
            }
            vulnerabilities.append(vuln_entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "component": {
                    "type": "application",
                    "name": project_name,
                },
                "tools": [
                    {
                        "vendor": "AI-OSOP",
                        "name": "AI-OSOP Security Engine",
                        "version": "1.0.0",
                    }
                ],
                "properties": [
                    {"name": "engagement_id", "value": engagement_id},
                    {"name": "attested", "value": "true"},
                ],
            },
            "vulnerabilities": vulnerabilities,
        }

    def generate_attestation_manifest(
        self,
        report_bytes: bytes,
        authority_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a cryptographically signed manifest for a generated report."""
        report_sha256 = hashlib.sha256(report_bytes).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        if authority_key:
            signature = hmac.new(
                authority_key.encode("utf-8"),
                report_sha256.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            algorithm = "HMAC-SHA256"
        else:
            signature = report_sha256
            algorithm = "SHA-256"

        return {
            "sha256": report_sha256,
            "algorithm": algorithm,
            "signature": signature,
            "attested_at": timestamp,
            "byte_count": len(report_bytes),
        }
