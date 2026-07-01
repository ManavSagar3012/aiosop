import logging

"""
AI-OSOP Core Configuration
Production-grade settings with Vault integration, scope enforcement, and LLM routing.
"""

from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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


class Settings(BaseSettings):
    """Central configuration loaded from environment + Vault."""

    # Infrastructure
    app_name: str = "ai-osop"
    environment: str = Field(default="development", validation_alias="OSOP_ENV")
    log_level: LogLevel = Field(
        default=LogLevel.INFO, validation_alias="OSOP_LOG_LEVEL"
    )

    # Database
    neo4j_uri: str = Field(
        default="bolt://localhost:7687", validation_alias="OSOP_NEO4J_URI"
    )
    neo4j_user: str = Field(default="neo4j", validation_alias="OSOP_NEO4J_USER")
    neo4j_password: str = Field(
        default="change-me-local", validation_alias="OSOP_NEO4J_PASSWORD"
    )

    postgres_uri: str = Field(
        default="postgresql+asyncpg://osop:osop@localhost:5432/osop",
        validation_alias="OSOP_POSTGRES_URI",
    )

    redis_uri: str = Field(
        default="redis://localhost:6379/0", validation_alias="OSOP_REDIS_URI"
    )

    # Agent / Safety
    agent_cleanup_timeout_seconds: float = Field(
        default=10.0, validation_alias="OSOP_AGENT_CLEANUP_TIMEOUT"
    )

    # LLM / AI
    llm_primary_provider: str = Field(
        default="openai", validation_alias="OSOP_LLM_PRIMARY"
    )
    llm_primary_model: str = Field(
        default="gpt-4o", validation_alias="OSOP_LLM_PRIMARY_MODEL"
    )
    llm_fallback_model: str = Field(
        default="gpt-4o-mini", validation_alias="OSOP_LLM_FALLBACK_MODEL"
    )
    llm_api_key_path: str = Field(
        default="secret/data/llm/openai", validation_alias="OSOP_LLM_KEY_PATH"
    )
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.1  # Low temperature for deterministic security reasoning
    mock_llm: bool = Field(default=False, validation_alias="OSOP_MOCK_LLM")
    # OSOP-P0-02: simulated/mock findings must NEVER reach the real corpus, reports, or
    # dashboard metrics unless explicitly opted in (e.g. pipeline self-tests). Persistence
    # of a simulated Vulnerability is refused when this is False (the default).
    allow_simulated_findings: bool = Field(
        default=False, validation_alias="OSOP_ALLOW_SIMULATED_FINDINGS"
    )

    # MCP
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8200
    mcp_request_timeout: int = 30
    # Bound browser-mcp calls so a down service fails fast (-> retry engine)
    # instead of hanging until the task reaper fires.
    browser_mcp_timeout: int = 30
    # Nuclei template scans run for minutes; the 30s default silently times them
    # out to zero findings, so give them a dedicated generous bound.
    nuclei_mcp_timeout: int = 900
    # OAST interaction server (R1). public_host is the configurable-hybrid knob:
    # 127.0.0.1 for local validation, a real domain when running against external targets.
    oast_public_host: str = "127.0.0.1"
    oast_port: int = 8099
    oast_scheme: str = "http"
    oast_mcp_timeout: int = 30

    # Safety
    sandbox_runtime: str = "docker"  # docker | containerd | kata
    sandbox_network_mode: str = "isolated"
    sandbox_cpu_limit: str = "2"
    sandbox_memory_limit: str = "4Gi"

    # Orchestration
    max_concurrent_agents: int = 50
    max_tasks_per_second: int = 100
    task_default_timeout: int = 300
    approval_timeout_seconds: int = 1800  # 30 minutes
    temporal_enabled: bool = Field(
        default=False, validation_alias="OSOP_TEMPORAL_ENABLED"
    )
    temporal_address: str = Field(
        default="localhost:7233", validation_alias="OSOP_TEMPORAL_ADDRESS"
    )
    temporal_namespace: str = Field(
        default="default", validation_alias="OSOP_TEMPORAL_NAMESPACE"
    )
    temporal_task_queue: str = Field(
        default="ai-osop-tasks", validation_alias="OSOP_TEMPORAL_TASK_QUEUE"
    )

    # Burp Suite
    burp_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_BURP_MCP_HOST"
    )
    burp_mcp_port: int = Field(default=8081, validation_alias="OSOP_BURP_MCP_PORT")
    burp_api_key: Optional[str] = Field(
        default=None, validation_alias="OSOP_BURP_API_KEY"
    )

    # PATCH (AIOSOP-SEC-001, 2026-06-15): API bearer-token shared secret —
    # stopgap kept as fallback when OSOP_JWT_SECRET is unset.
    api_token: Optional[str] = Field(default=None, validation_alias="OSOP_API_TOKEN")

    # PATCH (AIOSOP-SEC-001 hard fix, 2026-06-15): JWT auth.
    # If OSOP_JWT_SECRET is set, verify_token uses JWT validation (HS256 by
    # default; OSOP_JWT_ALGORITHM can override). Tokens must include `sub`,
    # `role`, `exp`, and (when OSOP_JWT_AUDIENCE/_ISSUER are set) `aud`/`iss`.
    # Falls back to api_token shared-secret equality when JWT secret is unset,
    # preserving the dev workflow without re-opening the auth-bypass hole.
    jwt_secret: Optional[str] = Field(default=None, validation_alias="OSOP_JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", validation_alias="OSOP_JWT_ALGORITHM")
    jwt_audience: Optional[str] = Field(
        default=None, validation_alias="OSOP_JWT_AUDIENCE"
    )
    jwt_issuer: Optional[str] = Field(default=None, validation_alias="OSOP_JWT_ISSUER")

    recon_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_RECON_MCP_HOST"
    )
    recon_mcp_port: int = Field(default=8082, validation_alias="OSOP_RECON_MCP_PORT")
    payload_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_PAYLOAD_MCP_HOST"
    )
    payload_mcp_port: int = Field(
        default=8083, validation_alias="OSOP_PAYLOAD_MCP_PORT"
    )
    nuclei_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_NUCLEI_MCP_HOST"
    )
    nuclei_mcp_port: int = Field(default=8084, validation_alias="OSOP_NUCLEI_MCP_PORT")
    shodan_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_SHODAN_MCP_HOST"
    )
    shodan_mcp_port: int = Field(default=8085, validation_alias="OSOP_SHODAN_MCP_PORT")
    shodan_api_key: Optional[str] = Field(
        default=None, validation_alias="OSOP_SHODAN_API_KEY"
    )
    h1_api_identifier: Optional[str] = Field(
        default=None, validation_alias="OSOP_H1_API_IDENTIFIER"
    )
    h1_api_key: Optional[str] = Field(default=None, validation_alias="OSOP_H1_API_KEY")
    bc_api_key: Optional[str] = Field(default=None, validation_alias="OSOP_BC_API_KEY")

    # Bug-bounty platform sync (AIOSOP-AUDIT-2026-06-16). Defaults to SIMULATION so
    # that CI, autonomous runs, and the test-suite never fire live network calls to
    # HackerOne/Bugcrowd — and, critically, never submit AI-generated vulnerability
    # reports to a live program. Set OSOP_BUG_BOUNTY_SIMULATION=false to enable real
    # platform calls (requires valid h1/bc credentials).
    bug_bounty_simulation: bool = Field(
        default=False, validation_alias="OSOP_BUG_BOUNTY_SIMULATION"
    )

    browser_mcp_host: str = Field(
        default="127.0.0.1", validation_alias="OSOP_BROWSER_MCP_HOST"
    )
    browser_mcp_port: int = Field(
        default=8091, validation_alias="OSOP_BROWSER_MCP_PORT"
    )
    security_bridge_host: str = Field(
        default="localhost", validation_alias="OSOP_SECURITY_BRIDGE_HOST"
    )
    security_bridge_port: int = Field(
        default=8087, validation_alias="OSOP_SECURITY_BRIDGE_PORT"
    )
    threat_intel_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_THREAT_INTEL_MCP_HOST"
    )
    threat_intel_mcp_port: int = Field(
        default=8086, validation_alias="OSOP_THREAT_INTEL_MCP_PORT"
    )
    source_map_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_SOURCE_MAP_MCP_HOST"
    )
    source_map_mcp_port: int = Field(
        default=8096, validation_alias="OSOP_SOURCE_MAP_MCP_PORT"
    )
    cloud_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_CLOUD_MCP_HOST"
    )
    cloud_mcp_port: int = Field(default=8097, validation_alias="OSOP_CLOUD_MCP_PORT")
    turbo_intruder_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_TURBO_INTRUDER_MCP_HOST"
    )
    turbo_intruder_mcp_port: int = Field(
        default=8098, validation_alias="OSOP_TURBO_INTRUDER_MCP_PORT"
    )

    # Recon
    recon_max_subdomains: int = 10000
    recon_nmap_top_ports: int = 1000
    recon_rate_limit_per_sec: int = 100

    # Payload Engine
    payload_max_population: int = 100
    payload_max_generations: int = 50
    payload_mutation_rate: float = 0.3
    payload_crossover_rate: float = 0.7

    # Audit
    audit_log_retention_days: int = 2555  # 7 years
    audit_signing_key_path: str = "secret/data/audit/signing"
    audit_secret_key: Optional[str] = Field(default=None, validation_alias="OSOP_AUDIT_SECRET_KEY")

    # Data Retention
    retention_enabled: bool = True
    neo4j_retention_days: int = 365
    postgres_task_retention_days: int = 90
    postgres_session_retention_days: int = 30
    postgres_approval_retention_days: int = 90
    redis_hot_ttl_hours: int = 168  # 7 days
    redis_session_ttl_hours: int = 24

    # Session encryption (Fernet) for cookies, bearer tokens, CSRF tokens at rest
    session_encryption_key: Optional[str] = Field(
        default=None, validation_alias="OSOP_SESSION_ENCRYPTION_KEY"
    )

    # CORS
    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:5173"],
        validation_alias="OSOP_CORS_ALLOWED_ORIGINS",
    )

    # Observability (Sprint 6)
    otel_enabled: bool = Field(default=False, validation_alias="OSOP_OTEL_ENABLED")
    otel_endpoint: str = Field(
        default="localhost:4317", validation_alias="OSOP_OTEL_ENDPOINT"
    )
    otel_service_name: str = Field(
        default="ai-osop", validation_alias="OSOP_OTEL_SERVICE_NAME"
    )
    otel_environment: str = Field(
        default="dev", validation_alias="OSOP_OTEL_ENVIRONMENT"
    )

    correlation_id_enabled: bool = Field(
        default=True, validation_alias="OSOP_CORRELATION_ID_ENABLED"
    )
    metrics_enabled: bool = Field(default=True, validation_alias="OSOP_METRICS_ENABLED")
    trace_propagation_enabled: bool = Field(
        default=True, validation_alias="OSOP_TRACE_PROPAGATION_ENABLED"
    )
    otel_sampling_rate: float = Field(
        default=1.0, validation_alias="OSOP_OTEL_SAMPLING_RATE"
    )

    # Sentry
    sentry_dsn: Optional[str] = Field(default=None, validation_alias="SENTRY_DSN")
    sentry_traces_sample_rate: float = Field(
        default=1.0, validation_alias="SENTRY_TRACES_SAMPLE_RATE"
    )
    sentry_profiles_sample_rate: float = Field(
        default=0.0, validation_alias="SENTRY_PROFILES_SAMPLE_RATE"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()


# --- Nuclei scan profiles (Sprint 0) -------------------------------------------------
# Bound scan breadth so a nuclei task finishes within the agent/task timeout instead of
# running the full ~13k-template set (the "NUCLEI-FANOUT" timeout -> retry -> orphaned
# subprocess failure). vuln_agent applies "fast" by default when a caller supplies no
# template/severity/tag scoping; callers wanting exhaustive coverage pass profile="deep"
# or explicit templates/severity/tags.
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


_INSECURE_DEV_SIGNING_KEY = b"dev-insecure-scope-signing-key"
_PROD_ENVIRONMENTS = {"production", "prod", "staging", "stage"}


def scope_signing_key() -> bytes:
    """SINGLE source of truth for the HMAC key that signs scope manifests AND the
    audit-event chain (GAP-2-4 / OSOP-P0-03).

    Every signer and verifier (engagement_manager.sign, task_scheduler.verify,
    approval_coordinator, session_memory audit chain) MUST use this so signing and
    verification can never diverge.

    Fail-closed in production: if ``OSOP_AUDIT_SECRET_KEY`` is unset we refuse to fall
    back to a public constant in a production/staging environment (that would make every
    scope signature and audit record forgeable). In development/test we return a clearly
    labelled insecure key and log loudly so local runs still work.
    """
    key = getattr(settings, "audit_secret_key", None)
    if key:
        return key.encode() if isinstance(key, str) else key
    env = (getattr(settings, "environment", "") or "").lower()
    if env in _PROD_ENVIRONMENTS:
        raise RuntimeError(
            "OSOP_AUDIT_SECRET_KEY is not set. Refusing to sign/verify with an insecure "
            "default in a production environment (scope + audit integrity would be forgeable)."
        )
    logger = logging.getLogger(__name__)
    logger.warning("scope_signing_key_insecure_default: using insecure dev key.")
    return _INSECURE_DEV_SIGNING_KEY


_WEAK_SECRET_VALUES = {"change-me-local", "changeme", "change-me", "default-insecure-audit-key"}


def assert_production_secrets() -> None:
    """Fail closed at startup if insecure default secrets are present in a production
    environment (OSOP-P2-11 / OSOP-P0-03). Called from the API lifespan so a misconfigured
    production deployment refuses to boot rather than silently running with a public Neo4j
    password or a forgeable audit/scope key. No-op in development/test."""
    env = (getattr(settings, "environment", "") or "").lower()
    if env not in _PROD_ENVIRONMENTS:
        return
    problems = []
    if (getattr(settings, "neo4j_password", "") or "") in _WEAK_SECRET_VALUES:
        problems.append("OSOP_NEO4J_PASSWORD is a weak/default value")
    if not getattr(settings, "audit_secret_key", None):
        problems.append("OSOP_AUDIT_SECRET_KEY is not set")
    if problems:
        raise RuntimeError(
            "Refusing to start in a production environment with insecure secrets: "
            + "; ".join(problems)
        )


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

PHASE_POLICY = {
    EngagementPhase.INITIALIZED: {
        "requires_manual_approval": True,
        "automatic_next_phase": None,
    },
    EngagementPhase.RECONNAISSANCE: {
        "requires_manual_approval": False,
        "automatic_next_phase": EngagementPhase.VULNERABILITY_DISCOVERY,
    },
    EngagementPhase.VULNERABILITY_DISCOVERY: {
        "requires_manual_approval": True,
        "automatic_next_phase": None,
    },
    EngagementPhase.EXPLOITATION: {
        "requires_manual_approval": True,
        "automatic_next_phase": None,
    },
    EngagementPhase.POST_EXPLOITATION: {
        "requires_manual_approval": True,
        "automatic_next_phase": None,
    },
    EngagementPhase.REPORTING: {
        "requires_manual_approval": True,
        "automatic_next_phase": None,
    },
    EngagementPhase.COMPLETED: {
        "requires_manual_approval": False,
        "automatic_next_phase": None,
    },
    EngagementPhase.HALTED: {
        "requires_manual_approval": False,
        "automatic_next_phase": None,
    },
}


class AgentState(str, Enum):
    IDLE = "idle"
    ASSIGNED = "assigned"
    RUNNING = "running"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    RECOVERING = "recovering"
