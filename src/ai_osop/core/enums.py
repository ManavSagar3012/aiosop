"""
AI-OSOP Shared Enums

Extracted from config.py into a dedicated module to keep the settings
class focused on configuration while allowing enums to be imported without
pulling in the full Settings hierarchy.

Every enum in this file was originally defined in, and is still re-exported
from, config.py for backward compatibility.
"""

from enum import Enum


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    AUDIT = "AUDIT"


class AgentType(str, Enum):
    RECON = "recon"
    VULN_ANALYSIS = "vuln_analysis"
    PAYLOAD_MUTATION = "payload_mutation"
    EXPLOIT_VALIDATION = "exploit_validation"
    ATTACK_CHAIN = "attack_chain"
    REPORTING = "reporting"
    HUMAN_OVERSIGHT = "human_oversight"
    CONTEXT_MANAGER = "context_manager"
    WORKFLOW = "workflow"
    STATEFUL_LOGIC = "stateful_logic"
    VISUAL_CONTEXT = "visual_context"
    SAST_ANALYSIS = "sast_analysis"
    CLOUD_SPECIALIST = "cloud_specialist"
    CONCURRENCY = "concurrency"
    NEXTJS_SPECIALIST = "nextjs_specialist"
    REACT_SPECIALIST = "react_specialist"
    RETRIEVAL = "retrieval"
    SSTI_SCANNER = "ssti_scanner"
    SSRF_SCANNER = "ssrf_scanner"
    CSRF_SCANNER = "csrf_scanner"
    JWT_SCANNER = "jwt_scanner"
    SMUGGLING_SCANNER = "smuggling_scanner"
    RACE_SCANNER = "race_scanner"
    UPLOAD_SCANNER = "upload_scanner"
    POLLUTION_SCANNER = "pollution_scanner"
    WEBSOCKET_SCANNER = "websocket_scanner"
    SAML_SCANNER = "saml_scanner"
    TAKEOVER_SCANNER = "takeover_scanner"


class VulnClass(str, Enum):
    UNKNOWN = "unknown"
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    IDOR = "idor"
    CSRF = "csrf"
    MASS_ASSIGNMENT = "mass_assignment"
    GRAPHQL = "graphql"
    JWT_ABUSE = "jwt_abuse"
    RCE = "rce"
    LFI = "lfi"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    OAUTH2 = "oauth2"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    BOLA = "bola"
    AUTHENTICATION_WEAKNESS = "authentication_weakness"
    SCA_VULN = "sca_vuln"
    CONTAINER_VULN = "container_vuln"
    ACTIVE_DIRECTORY = "active_directory"
    CLOUD_VULN = "cloud_vuln"
    OSINT_LEAK = "osint_leak"
    NETWORK_ANOMALY = "network_anomaly"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUBDOMAIN_ENUM = "subdomain_enum"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    EXPOSED_SECRET = "exposed_secret"
    RACE_CONDITION = "race_condition"
    REQUEST_SMUGGLING = "request_smuggling"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    FILE_UPLOAD = "file_upload"
    NOSQL_INJECTION = "nosql_injection"
    CACHE_POISONING = "cache_poisoning"
    OPEN_REDIRECT = "open_redirect"
    AI_MCP_SECURITY = "ai_mcp_security"
    CLOUD_MISCONFIG = "cloud_misconfig"
    VULN_SCAN = "vuln_scan"
    GRAPHQL_SECURITY = "graphql_security"
    SERVERLESS_SECURITY = "serverless_security"
    KUBERNETES_SECURITY = "kubernetes_security"
    MOBILE_SECURITY = "mobile_security"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    FORENSICS = "forensics"
    SAST_SINK = "sast_sink"


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


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementPhase(str, Enum):
    INITIALIZED = "initialized"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    HALTED = "halted"


VALID_TRANSITIONS = {
    EngagementPhase.INITIALIZED: [
        EngagementPhase.RECONNAISSANCE,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.RECONNAISSANCE: [
        EngagementPhase.VULNERABILITY_DISCOVERY,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.VULNERABILITY_DISCOVERY: [
        EngagementPhase.EXPLOITATION,
        EngagementPhase.REPORTING,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.EXPLOITATION: [
        EngagementPhase.POST_EXPLOITATION,
        EngagementPhase.REPORTING,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.POST_EXPLOITATION: [
        EngagementPhase.REPORTING,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.REPORTING: [EngagementPhase.COMPLETED, EngagementPhase.HALTED],
    EngagementPhase.COMPLETED: [],
    EngagementPhase.HALTED: [],
}



class AgentState(str, Enum):
    IDLE = "idle"
    ASSIGNED = "assigned"
    RUNNING = "running"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    RECOVERING = "recovering"
