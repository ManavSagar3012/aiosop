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


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    IDOR = "idor"
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
    VULN_SCAN = "vuln_scan"
    GRAPHQL_SECURITY = "graphql_security"
    SERVERLESS_SECURITY = "serverless_security"
    KUBERNETES_SECURITY = "kubernetes_security"
    MOBILE_SECURITY = "mobile_security"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    FORENSICS = "forensics"

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
    "api_security": ["api_security", "bola_testing", "auth_testing", "graphql_security"],
    "ad_pentest": ["active_directory", "lateral_movement", "privilege_escalation"],
    "cloud_pentest": ["cloud_pentest", "serverless_security", "kubernetes_security"],
    "infra_scan": ["vuln_scanning"],
    "oauth_audit": ["oauth2_security"],
    "dependency_scan": ["sca_scanning"],
    "container_scan": ["container_security", "kubernetes_security"],
    "osint_recon": ["osint_recon", "subdomain_enum"],
    "traffic_analysis": ["network_traffic_analysis", "threat_hunting"],
    "incident_response": ["incident_response", "forensics", "threat_hunting"],
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
    log_level: LogLevel = Field(default=LogLevel.INFO, validation_alias="OSOP_LOG_LEVEL")

    # Database
    neo4j_uri: str = Field(default="bolt://localhost:7687", validation_alias="OSOP_NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", validation_alias="OSOP_NEO4J_USER")
    neo4j_password: str = Field(default="change-me-local", validation_alias="OSOP_NEO4J_PASSWORD")

    postgres_uri: str = Field(
        default="postgresql+asyncpg://osop:osop@localhost:5432/osop",
        validation_alias="OSOP_POSTGRES_URI",
    )

    redis_uri: str = Field(default="redis://localhost:6379/0", validation_alias="OSOP_REDIS_URI")

    # LLM / AI
    llm_primary_provider: str = Field(default="openai", validation_alias="OSOP_LLM_PRIMARY")
    llm_primary_model: str = Field(default="gpt-4o", validation_alias="OSOP_LLM_PRIMARY_MODEL")
    llm_fallback_model: str = Field(
        default="gpt-4o-mini", validation_alias="OSOP_LLM_FALLBACK_MODEL"
    )
    llm_api_key_path: str = Field(
        default="secret/data/llm/openai", validation_alias="OSOP_LLM_KEY_PATH"
    )
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.1  # Low temperature for deterministic security reasoning
    mock_llm: bool = Field(default=True, validation_alias="OSOP_MOCK_LLM")

    # MCP
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8088
    mcp_request_timeout: int = 30

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
    temporal_enabled: bool = Field(default=False, validation_alias="OSOP_TEMPORAL_ENABLED")
    temporal_address: str = Field(
        default="localhost:7233", validation_alias="OSOP_TEMPORAL_ADDRESS"
    )
    temporal_namespace: str = Field(default="default", validation_alias="OSOP_TEMPORAL_NAMESPACE")
    temporal_task_queue: str = Field(
        default="ai-osop-tasks", validation_alias="OSOP_TEMPORAL_TASK_QUEUE"
    )

    # Burp Suite
    burp_mcp_host: str = Field(default="localhost", validation_alias="OSOP_BURP_MCP_HOST")
    burp_mcp_port: int = Field(default=8081, validation_alias="OSOP_BURP_MCP_PORT")
    burp_api_key: Optional[str] = Field(default=None, validation_alias="OSOP_BURP_API_KEY")

    recon_mcp_host: str = Field(default="localhost", validation_alias="OSOP_RECON_MCP_HOST")
    recon_mcp_port: int = Field(default=8082, validation_alias="OSOP_RECON_MCP_PORT")
    payload_mcp_host: str = Field(default="localhost", validation_alias="OSOP_PAYLOAD_MCP_HOST")
    payload_mcp_port: int = Field(default=8083, validation_alias="OSOP_PAYLOAD_MCP_PORT")
    nuclei_mcp_host: str = Field(default="localhost", validation_alias="OSOP_NUCLEI_MCP_HOST")
    nuclei_mcp_port: int = Field(default=8084, validation_alias="OSOP_NUCLEI_MCP_PORT")
    shodan_mcp_host: str = Field(default="localhost", validation_alias="OSOP_SHODAN_MCP_HOST")
    shodan_mcp_port: int = Field(default=8085, validation_alias="OSOP_SHODAN_MCP_PORT")
    shodan_api_key: Optional[str] = Field(default=None, validation_alias="OSOP_SHODAN_API_KEY")

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

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
