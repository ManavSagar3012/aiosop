"""ATT&CK / OWASP taxonomy mapping for findings.

Maps a vuln_type to an ATT&CK technique (T-code + name) and an OWASP 2021
category so the technical report carries standard identifiers a triager or
client can pivot from. Unknown vuln_types fall back to generic values.
"""

from typing import Any, Dict

# vuln_type -> (ATT&CK technique id, technique name)
ATTACK_TECHNIQUE_MAP: Dict[str, tuple] = {
    "sqli": ("T1190", "Exploit Public-Facing Application"),
    "ssrf": ("T1190", "Exploit Public-Facing Application"),
    "xss": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "jwt_abuse": ("T1558", "Steal or Forge Authentication Tokens"),
    "session": ("T1558", "Steal or Forge Authentication Tokens"),
    "broken_access_control": ("T1213", "Data from Information Repositories"),
    "idor": ("T1213", "Data from Information Repositories"),
    "rce": ("T1210", "Exploitation of Remote Services"),
    "exposed_secret": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "subdomain_takeover": ("T1584", "Compromise Infrastructure"),
}
DEFAULT_ATTACK = ("T1190", "Exploit Public-Facing Application")

# vuln_type -> OWASP 2021 category label
OWASP_MAP: Dict[str, str] = {
    "sqli": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "ssrf": "A10:2021-Server-Side Request Forgery",
    "idor": "A01:2021-Broken Access Control",
    "broken_access_control": "A01:2021-Broken Access Control",
    "jwt_abuse": "A07:2021-Identification and Authentication Failures",
    "session": "A07:2021-Identification and Authentication Failures",
    "exposed_secret": "A02:2021-Cryptographic Failures",
    "rce": "A01:2021-Broken Access Control",
    "subdomain_takeover": "A01:2021-Broken Access Control",
}
DEFAULT_OWASP = "A01:2021-Broken Access Control"


def enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Add attack_id / attack_name / owasp to a finding dict (in place)."""
    vuln_type = str(finding.get("vuln_type", "unknown"))
    attack_id, attack_name = ATTACK_TECHNIQUE_MAP.get(vuln_type, DEFAULT_ATTACK)
    finding["attack_id"] = attack_id
    finding["attack_name"] = attack_name
    finding["owasp"] = OWASP_MAP.get(vuln_type, DEFAULT_OWASP)
    return finding
