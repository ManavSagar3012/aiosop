"""
AI-OSOP Task-Skill Map and Scan Profiles

Extracted from config.py to keep settings focused on configuration
rather than routing tables.
"""

TASK_SKILL_MAP = {
    "full_recon": ["recon", "subdomain_enum", "osint_recon"],
    "dns_enumeration": ["subdomain_enum"],
    "port_scan": ["recon", "vuln_scanning"],
    "burp_scan": [
        "xss",
        "sqli",
        "jwt",
        "ssrf",
        "idor",
        "api",
        "web_pentest",
        "api_security",
        "bola_testing",
        "auth_testing",
        "graphql_security",
    ],
    "nuclei_scan": [
        "xss",
        "sqli",
        "ssrf",
        "rce",
        "lfi",
        "xxe",
        "web_pentest",
        "api_security",
        "serverless_security",
        "kubernetes_security",
    ],
    "validate_exploit": [
        "sqli",
        "xss",
        "ssrf",
        "rce",
        "idor",
        "jwt",
        "sqli_exploitation",
        "xss_testing",
        "ssrf_exploitation",
        "jwt_security",
    ],
    "web_pentest": ["web_pentest"],
    "api_security": [
        "api_security",
        "bola_testing",
        "auth_testing",
        "graphql_security",
    ],
    "ad_pentest": ["active_directory", "lateral_movement", "privilege_escalation"],
    "cloud_pentest": ["cloud_pentest", "serverless_security", "kubernetes_security"],
    "infra_scan": ["vuln_scanning"],
    "oauth_audit": ["oauth2_security"],
    "dependency_scan": ["sca_scanning"],
    "container_scan": ["container_security", "kubernetes_security"],
    "osint_recon": ["osint_recon", "subdomain_enum"],
    "traffic_analysis": ["network_traffic_analysis", "threat_hunting"],
    "incident_response": ["incident_response", "forensics", "threat_hunting"],
    # Phase 1 authenticated-surface chain: skills the WORKFLOW agent should reason
    # with while mapping / capturing the authenticated attack surface.
    "map_workflow": ["web_pentest", "auth_testing", "api_security"],
    "capture_authenticated_surface": ["idor", "bola_testing", "auth_testing"],
    "extract_har_api_inventory": ["api_security", "api"],
    # Phase 2 differential authorization / BOLA foundation.
    "run_diff_auth_analysis": ["idor", "bola_testing", "auth_testing"],
}


NUCLEI_SCAN_PROFILES = {
    # "fast": tags bound the template load (=> completes in-budget); severity is left
    # open so real findings across severities still surface (a strict high+ floor would
    # drop most of a target's info/low hits and yield a misleading "0 findings").
    "fast": {"severity": "", "tags": "misconfig,exposure,default-login,cve,takeover"},
    # "standard": broader templates but capped to actionable severities.
    "standard": {"severity": "critical,high,medium", "tags": ""},
    # "deep": full template set — exhaustive, long-running (raise the task timeout).
    "deep": {"severity": "", "tags": ""},
}
