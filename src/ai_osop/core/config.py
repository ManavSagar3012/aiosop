import logging

"""
AI-OSOP Core Configuration
Production-grade settings with Vault integration, scope enforcement, and LLM routing.
"""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Backward-compatible re-exports from the split modules.
# Importing from ``ai_osop.core.config`` still works for all existing consumers.
from ai_osop.core.enums import (  # noqa: F401
    AgentState,
    AgentType,
    EngagementPhase,
    LogLevel,
    Severity,
    VulnClass,
)  # noqa: F401
from ai_osop.core.task_skills import NUCLEI_SCAN_PROFILES, TASK_SKILL_MAP  # noqa: F401


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

    # AIOSOP-POSTGRES-PORT-001 (2026-07-12): default port changed from 5432 to
    # 15432 to match docker-compose.yml, which remaps to avoid conflict with
    # wslrelay.exe (or local PostgreSQL) on dev hosts running WSL2. The env var
    # OSOP_POSTGRES_URI overrides this when set.
    postgres_uri: str = Field(
        default="postgresql+asyncpg://osop:osop@localhost:15432/osop",
        validation_alias="OSOP_POSTGRES_URI",
    )

    redis_uri: str = Field(default="redis://localhost:6379/0", validation_alias="OSOP_REDIS_URI")

    # Agent / Safety
    agent_cleanup_timeout_seconds: float = Field(
        default=10.0, validation_alias="OSOP_AGENT_CLEANUP_TIMEOUT"
    )

    # LLM / AI
    llm_primary_provider: str = Field(default="openai", validation_alias="OSOP_LLM_PRIMARY")
    llm_primary_model: str = Field(default="gpt-4o", validation_alias="OSOP_LLM_PRIMARY_MODEL")
    llm_fallback_model: str = Field(
        default="gpt-4o-mini", validation_alias="OSOP_LLM_FALLBACK_MODEL"
    )
    # Embedding model for semantic memory (skills, payload recall, findings knowledge).
    # Configurable per provider instead of hardcoded; defaults to an OpenAI model.
    # For a local/Ollama deployment set OSOP_LLM_EMBEDDING_MODEL to a pulled embed
    # model (e.g. "ollama/nomic-embed-text").
    llm_embedding_model: str = Field(
        default="text-embedding-3-small", validation_alias="OSOP_LLM_EMBEDDING_MODEL"
    )
    # Embedding vector dimension — MUST match the embedding model output and the
    # pgvector column width. Defaults to 1536 (text-embedding-3-small). If you
    # switch models set this to match (e.g. nomic-embed-text -> 768) and use a
    # fresh DB or migrate the vector columns, or inserts will fail on a size mismatch.
    llm_embedding_dim: int = Field(default=1536, validation_alias="OSOP_LLM_EMBEDDING_DIM")
    # P2b calibration feedback loop: how often (seconds) the orchestrator polls
    # bug-bounty platforms for submission outcomes and folds them into the corpus,
    # so confidence calibration learns from real accept/reject ground truth. 0
    # disables the poller. Default hourly. A no-op without bug-bounty credentials.
    bug_bounty_outcome_sync_interval_seconds: int = Field(
        default=3600, validation_alias="OSOP_BUG_BOUNTY_OUTCOME_SYNC_INTERVAL"
    )
    # Chain-first consume loop: how often (seconds) the orchestrator reads unpromoted
    # primitives from the ledger, escalates + composes them into chains, and runs each
    # chain through the Triager Gate so only reproducible, gate-passed chains become
    # report-ready. 0 disables the pass. A no-op without a wired primitive ledger.
    chain_analysis_interval_seconds: int = Field(
        default=900, validation_alias="OSOP_CHAIN_ANALYSIS_INTERVAL"
    )
    llm_api_key_path: str = Field(
        default="secret/data/llm/openai", validation_alias="OSOP_LLM_KEY_PATH"
    )
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.1  # Low temperature for deterministic security reasoning
    # AIOSOP-LLM-TIMEOUT-001 (2026-07-03): bound every LLM completion HTTP call.
    # litellm.acompletion previously passed NO timeout, so a stalled provider blocked
    # forever (not an exception -> the fallback branch never fired). Runtime evidence:
    # recon's think() hung the full 300s task budget (think_START logged, think_DONE
    # never), starving port-scan/crawl/Wayback/Shodan and getting reaped at ~953s.
    # Bound each call so a hang degrades instead of stalling the pipeline. Primary +
    # fallback are each bounded, so worst case is 2x this value.
    llm_completion_timeout: int = Field(default=60, validation_alias="OSOP_LLM_COMPLETION_TIMEOUT")
    # AIOSOP-LLM-CONCURRENCY-001: cap simultaneous LLM completions. The cloud-proxied
    # Ollama models serve a handful of concurrent requests fine (~6 in ~12s, verified),
    # but a 100-task scanner fan-out fires 30+ agent reasoning calls at once, oversubscribing
    # the shared proxy so EVERY call slows/queues and no LLM-driven scan (sqli/xss/csrf/jwt)
    # completes within its budget — while single-shot burp/recon still finish. A global
    # semaphore keeps the backend in its healthy-parallelism band: excess calls wait a beat
    # instead of thrashing the proxy, so scans complete and free their slots. Tune per backend.
    llm_max_concurrency: int = Field(default=8, validation_alias="OSOP_LLM_MAX_CONCURRENCY")
    # AIOSOP-LLM-WARM-001 (2026-07-03): the timeouts we saw were NOT "Ollama down" —
    # Ollama is up and the models are pulled. They were COLD-LOAD latency: loading a
    # 2-5GB model into memory takes ~60s, and with a different primary/fallback model
    # each think() could cold-load twice and blow the 60s bound. Two mitigations:
    #   1. keep_alive: tell Ollama to keep the model resident so it loads once, not per
    #      call. "30m" = keep for 30 min of idle; "-1" = never unload. Passed only to
    #      ollama/* models (ignored by cloud providers). Default "30m" (NOT "-1") on
    #      purpose: this host is memory-constrained (the 5.2GB primary OOMs under
    #      full-stack load), so pinning a model forever could starve MCP scans/other
    #      components. 30m keeps it warm across back-to-back engagements yet releases
    #      it during long idle.
    #   2. warm-up at startup (LiteLLMClient.warm_up) so the first real engagement call
    #      hits an already-resident model.
    llm_keep_alive: str = Field(default="30m", validation_alias="OSOP_LLM_KEEP_ALIVE")
    # Advisory reasoning (agent think()) does not need the full 4096-token budget, and
    # on a reasoning model like qwen3 a large budget means a long <think> trace that
    # blows the latency bound. Cap think() generation separately. Raised from the
    # original 512: 512 was too small to reason through even a short multi-step attack
    # chain (W7). 1536 gives think() room for a real hypothesis while still capping the
    # latency blowup on the local reasoning model — the right trade until reasoning is
    # routed to a capable API model (see llm_reasoning_model). Operator-tunable; lower
    # it again only if a cold-load/latency regression appears on the pinned local model.
    llm_reasoning_max_tokens: int = Field(
        default=1536, validation_alias="OSOP_LLM_REASONING_MAX_TOKENS"
    )
    # W7: route reasoning-path calls (agent think() / hypothesis generation) to a
    # capable model while bulk calls stay on the cheap local backend. 512-token think()
    # on a memory-starved 8b local model is why "all agent think() degraded". When set,
    # think() calls this model INSTEAD of the primary; when empty (default) think()
    # uses the primary model exactly as before — NO behavior change unless an operator
    # explicitly pins a reasoning model (e.g. a frontier API model). This is the
    # routing half of W7's "raise budget AND route reasoning to a capable model"; the
    # bulk/local path is untouched. Example: OSOP_LLM_REASONING_MODEL=claude-opus-4-8
    # with the provider key configured, keeping OSOP_LLM_* on the local Ollama for bulk.
    llm_reasoning_model: str = Field(default="", validation_alias="OSOP_LLM_REASONING_MODEL")
    # AIOSOP-REPORT-TRUNC-001 (2026-07-03): cap per-finding evidence in the RENDERED
    # report. Raw nuclei/burp evidence embeds full HTTP request+response bodies (often
    # the whole captured page), so one finding's evidence can exceed 200KB and 58
    # findings bloated a report to 7-8MB — impractical for HackerOne submission and
    # heavy to render (injected via dangerouslySetInnerHTML). The full evidence stays
    # in the graph/vault and the evidence hash is computed over the FULL text; only the
    # rendered excerpt is truncated.
    report_evidence_max_chars: int = Field(
        default=4000, validation_alias="OSOP_REPORT_EVIDENCE_MAX_CHARS"
    )
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
    # AIOSOP-BROWSER-CONCURRENCY-001: process-wide cap on concurrent browser-mcp
    # calls. Every agent (register/authenticate/capture + xss/csrf/... scanners)
    # drives ONE shared Chromium through the single browser-mcp server. With the
    # 40-task inflight cap, that server and the single-process target were driven
    # into crash-loops under load (observed: Juice Shop RestartCount 13, HTTP 000,
    # browser-mcp "Server disconnected"). Gating browser ops to a handful in flight
    # keeps the shared browser and the target alive without throttling non-browser
    # scan work (sqlmap/nuclei run unbounded by this).
    browser_mcp_max_concurrency: int = Field(
        default=4, validation_alias="OSOP_BROWSER_MCP_MAX_CONCURRENCY"
    )
    # AIOSOP-MCP-TIMEOUT-001 (2026-07-03): bound the MCP initialize/get_state HTTP calls.
    # These previously passed NO aiohttp timeout and inherited the 5-minute (300s) client
    # default, so a hung browser-mcp initialize (Chromium launch) blocked the calling agent
    # ~300s and was only caught by the 343s stuck-task reaper (the xss_scan hang). Init can
    # be heavier than a normal request (browser launch), hence a dedicated, generous bound.
    mcp_initialize_timeout: int = 60

    # AIOSOP-REAPER-001 (2026-07-20): the AgentReaper previously hardcoded
    # ``interval=15`` and ``heartbeat_timeout=60`` (reliability/agent_reaper.py).
    # That is too aggressive for slow external targets where one round-trip can
    # exceed 60s under network backpressure — a healthy agent mid-sqlmap-probe
    # gets marked dead and its task requeued, doubling load and producing
    # spurious ``agent_dead`` warnings. Make both knobs configurable so a
    # deployment can tune them to its target profile without a code change.
    agent_reaper_interval_seconds: int = Field(
        default=15, validation_alias="OSOP_AGENT_REAPER_INTERVAL_SECONDS"
    )
    agent_reaper_heartbeat_timeout_seconds: int = Field(
        default=60, validation_alias="OSOP_AGENT_REAPER_HEARTBEAT_TIMEOUT_SECONDS"
    )
    # AIOSOP-GOVERNED-EGRESS-001 (2026-07-20): bug-bounty programs (e.g. Syfe/H1)
    # require a research-identity header on every request to prod so their WAF can
    # allow-list the researcher's traffic. Empty name => header disabled (the
    # governed client simply skips it), so this is safe-by-default off and opt-in
    # per deployment. Value is typically "X-HackerOne-Research: <h1-username>".
    research_header_name: str = Field(default="", validation_alias="OSOP_RESEARCH_HEADER_NAME")
    research_header_value: str = Field(default="", validation_alias="OSOP_RESEARCH_HEADER_VALUE")
    # AIOSOP-GOVERNED-EGRESS-002 (B2): bounty-safe per-target request rate for the
    # governed scan client. The orchestrator's task-admission limiter defaults to
    # 10 req/s/target — fine for internal throughput, but reads as an automated
    # attack against a real program. Scan egress uses a dedicated, politer limiter
    # at these values. 2 req/s with a small burst keeps a scan defensibly
    # "manual-paced" while staying usable; raise per engagement if the program's
    # rules of engagement explicitly permit faster scanning.
    scan_target_rate_per_second: float = Field(
        default=2.0, validation_alias="OSOP_SCAN_TARGET_RATE_PER_SECOND"
    )
    scan_target_burst: int = Field(default=4, validation_alias="OSOP_SCAN_TARGET_BURST")
    # AIOSOP-EGRESS-TLS-001 (W5): governed egress must verify TLS by default. A
    # security product that disables certificate validation on its own outbound
    # traffic is MITM-exposable and undermines the "governed egress" promise.
    # Bug-bounty targets frequently present self-signed/invalid certs, so verify
    # is NOT removed wholesale — instead insecure TLS becomes an explicit,
    # audited opt-in: the governed client refuses ``verify=False`` unless the
    # caller passes ``allow_insecure=True`` OR the operator sets this to False,
    # and every insecure connection is logged so it is never silent. Default
    # True (verify). Set OSOP_TLS_VERIFY=false only for a deployment where every
    # target is known-bad-cert (e.g. an internal lab); the audit log still
    # records each downgrade.
    tls_verify: bool = Field(default=True, validation_alias="OSOP_TLS_VERIFY")
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
    max_concurrent_agents: int = (
        80  # Sprint 0: increased from 50 to accommodate doubled agent pool (67 agents)
    )
    max_tasks_per_second: int = 100
    task_default_timeout: int = 300
    # AIOSOP-SCALE-001 (2026-07-12): admission control. Without this cap, the
    # phase monitor creates 100+ tasks in a single VULNERABILITY_DISCOVERY entry,
    # all of them flood the pending queue and compete for ~80 agent slots. Tasks
    # beyond the cap stay pending in Redis until in-flight slots free up, keeping
    # the agent pool responsive instead of saturated by lock-contention misses.
    max_inflight_tasks_per_engagement: int = Field(
        default=40, validation_alias="OSOP_MAX_INFLIGHT_TASKS"
    )
    approval_timeout_seconds: int = 1800  # 30 minutes
    temporal_enabled: bool = Field(default=False, validation_alias="OSOP_TEMPORAL_ENABLED")
    temporal_address: str = Field(
        default="localhost:7233", validation_alias="OSOP_TEMPORAL_ADDRESS"
    )
    temporal_namespace: str = Field(default="default", validation_alias="OSOP_TEMPORAL_NAMESPACE")
    temporal_task_queue: str = Field(
        default="ai-osop-tasks", validation_alias="OSOP_TEMPORAL_TASK_QUEUE"
    )

    # Graph integrity sweep interval (seconds). The orchestrator runs the
    # ``graph_integrity_checker`` on a background loop to surface orphan /
    # ghost nodes at runtime and self-heal them via archive (soft-delete).
    # Default 600s (10min): frequent enough to catch drift before an operator
    # relies on a corrupt graph, rare enough to add negligible Neo4j load.
    # Set to 0 to disable the sweep (the first-tick check still runs once at
    # startup so a corrupt graph is always flagged before serving traffic).
    graph_integrity_check_interval_seconds: int = Field(
        default=600, validation_alias="OSOP_GRAPH_INTEGRITY_INTERVAL"
    )

    # Burp Suite
    burp_mcp_host: str = Field(default="localhost", validation_alias="OSOP_BURP_MCP_HOST")
    burp_mcp_port: int = Field(default=8081, validation_alias="OSOP_BURP_MCP_PORT")
    burp_api_key: Optional[str] = Field(default=None, validation_alias="OSOP_BURP_API_KEY")

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
    jwt_audience: Optional[str] = Field(default=None, validation_alias="OSOP_JWT_AUDIENCE")
    jwt_issuer: Optional[str] = Field(default=None, validation_alias="OSOP_JWT_ISSUER")

    recon_mcp_host: str = Field(default="localhost", validation_alias="OSOP_RECON_MCP_HOST")
    recon_mcp_port: int = Field(default=8082, validation_alias="OSOP_RECON_MCP_PORT")
    payload_mcp_host: str = Field(default="localhost", validation_alias="OSOP_PAYLOAD_MCP_HOST")
    payload_mcp_port: int = Field(default=8083, validation_alias="OSOP_PAYLOAD_MCP_PORT")
    nuclei_mcp_host: str = Field(default="localhost", validation_alias="OSOP_NUCLEI_MCP_HOST")
    nuclei_mcp_port: int = Field(default=8084, validation_alias="OSOP_NUCLEI_MCP_PORT")
    shodan_mcp_host: str = Field(default="localhost", validation_alias="OSOP_SHODAN_MCP_HOST")
    shodan_mcp_port: int = Field(default=8085, validation_alias="OSOP_SHODAN_MCP_PORT")
    shodan_api_key: Optional[str] = Field(default=None, validation_alias="OSOP_SHODAN_API_KEY")
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
        # FIX (audit 2026-08-01): default was False while the docstring + adapter
        # claimed "Defaults to SIMULATION". Because settings.bug_bounty_simulation
        # always exists, the adapter's getattr(settings, ..., True) never used its
        # safe True default — this field's False won, so simulation was effectively
        # DISABLED out of the box, and the findings router hardcodes
        # live_submit_approved=True. The only thing stopping a live -> HackerOne
        # submission was absent credentials. Flip the default to True so the safe
        # (simulation) behavior is real; set OSOP_BUG_BOUNTY_SIMULATION=false to
        # enable live platform calls (still requires credentials + approval).
        default=True, validation_alias="OSOP_BUG_BOUNTY_SIMULATION"
    )

    browser_mcp_host: str = Field(default="127.0.0.1", validation_alias="OSOP_BROWSER_MCP_HOST")
    browser_mcp_port: int = Field(default=8091, validation_alias="OSOP_BROWSER_MCP_PORT")
    security_bridge_host: str = Field(
        default="localhost", validation_alias="OSOP_SECURITY_BRIDGE_HOST"
    )
    security_bridge_port: int = Field(default=8087, validation_alias="OSOP_SECURITY_BRIDGE_PORT")
    threat_intel_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_THREAT_INTEL_MCP_HOST"
    )
    threat_intel_mcp_port: int = Field(default=8086, validation_alias="OSOP_THREAT_INTEL_MCP_PORT")
    source_map_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_SOURCE_MAP_MCP_HOST"
    )
    source_map_mcp_port: int = Field(default=8096, validation_alias="OSOP_SOURCE_MAP_MCP_PORT")
    cloud_mcp_host: str = Field(default="localhost", validation_alias="OSOP_CLOUD_MCP_HOST")
    cloud_mcp_port: int = Field(default=8097, validation_alias="OSOP_CLOUD_MCP_PORT")
    turbo_intruder_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_TURBO_INTRUDER_MCP_HOST"
    )
    turbo_intruder_mcp_port: int = Field(
        default=8098, validation_alias="OSOP_TURBO_INTRUDER_MCP_PORT"
    )
    session_memory_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_SESSION_MEMORY_MCP_HOST"
    )
    session_memory_mcp_port: int = Field(
        default=8090, validation_alias="OSOP_SESSION_MEMORY_MCP_PORT"
    )
    reporting_mcp_host: str = Field(default="localhost", validation_alias="OSOP_REPORTING_MCP_HOST")
    reporting_mcp_port: int = Field(default=8092, validation_alias="OSOP_REPORTING_MCP_PORT")
    # Governed client and safety settings
    hackerone_research_username: Optional[str] = Field(
        default=None, validation_alias="OSOP_H1_RESEARCH_USERNAME"
    )
    allow_external_liveness_probing: bool = Field(
        default=False, validation_alias="OSOP_ALLOW_EXTERNAL_LIVENESS_PROBING"
    )

    oast_mcp_host: str = Field(default="localhost", validation_alias="OSOP_OAST_MCP_HOST")
    attack_graph_mcp_host: str = Field(
        default="localhost", validation_alias="OSOP_ATTACK_GRAPH_MCP_HOST"
    )
    attack_graph_mcp_port: int = Field(default=8093, validation_alias="OSOP_ATTACK_GRAPH_MCP_PORT")
    oast_mcp_host: str = Field(default="localhost", validation_alias="OSOP_OAST_MCP_HOST")
    oast_mcp_port: int = Field(default=8099, validation_alias="OSOP_OAST_MCP_PORT")
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
    # Phase-1 issue #15: session-state retention was hardcoded to 7 days in
    # retention_service._cleanup_postgres. Operator-tunable like every other
    # retention window; default 30 days matches the session retention window.
    session_state_retention_days: int = Field(
        default=30, validation_alias="OSOP_SESSION_STATE_RETENTION_DAYS"
    )
    redis_hot_ttl_hours: int = 168  # 7 days
    redis_session_ttl_hours: int = (
        2  # Sprint 0: reduced from 24h to 2h to prevent stale engagement accumulation; 2h is enough for most engagements
    )
    # AIOSOP-RECOVERY-AGE-001 (2026-07-12): restart recovery (load_all_active_tasks)
    # re-queues EVERY non-terminal task in Postgres regardless of age. An abandoned
    # engagement (observed live: a 2-day-old eng- whose sqli_scan tasks kept getting
    # resurrected across restarts) then hijacks the whole scanner-agent pool on every
    # boot, starving live engagements. The per-task _recovery_attempts cap (=3) does not
    # help here because the engagement keeps regenerating fresh work. Bound recovery to
    # tasks created within this window; older tasks are left non-terminal in the DB but
    # never resurrected. Default 24h comfortably covers a real multi-hour pentest.
    # ponytail: age proxy for "engagement still active"; switch to a phase check
    # (skip HALTED/COMPLETED/ABORTED engagements) if long idle-then-resume is needed.
    recovery_max_age_hours: int = Field(default=24, validation_alias="OSOP_RECOVERY_MAX_AGE_HOURS")

    # Session encryption (Fernet) for cookies, bearer tokens, CSRF tokens at rest
    session_encryption_key: Optional[str] = Field(
        default=None, validation_alias="OSOP_SESSION_ENCRYPTION_KEY"
    )

    # CORS
    # AIOSOP-CORS-001 (2026-07-03): include BOTH localhost and 127.0.0.1 on the Vite
    # dev/preview port. The dashboard dev server binds 127.0.0.1 (see ui package.json
    # `vite --host 127.0.0.1`), and for CORS `localhost` and `127.0.0.1` are DISTINCT
    # origins — allowing only one silently blocked every browser->API fetch, so the
    # dashboard rendered DISCONNECTED / all-zeros despite live data (runtime-proven).
    cors_allowed_origins: list[str] = Field(
        default=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        validation_alias="OSOP_CORS_ALLOWED_ORIGINS",
    )

    # Observability (Sprint 6)
    otel_enabled: bool = Field(default=False, validation_alias="OSOP_OTEL_ENABLED")
    otel_endpoint: str = Field(default="localhost:4317", validation_alias="OSOP_OTEL_ENDPOINT")
    otel_service_name: str = Field(default="ai-osop", validation_alias="OSOP_OTEL_SERVICE_NAME")
    otel_environment: str = Field(default="dev", validation_alias="OSOP_OTEL_ENVIRONMENT")

    correlation_id_enabled: bool = Field(
        default=True, validation_alias="OSOP_CORRELATION_ID_ENABLED"
    )
    metrics_enabled: bool = Field(default=True, validation_alias="OSOP_METRICS_ENABLED")
    trace_propagation_enabled: bool = Field(
        default=True, validation_alias="OSOP_TRACE_PROPAGATION_ENABLED"
    )
    otel_sampling_rate: float = Field(default=1.0, validation_alias="OSOP_OTEL_SAMPLING_RATE")

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
# AIOSOP-LOGHYGIENE-001 (2026-07-03): warn ONCE per process about the insecure dev
# key instead of on every scope_signing_key() call. This function runs on every
# exploit-class task assignment, audit-chain append, and session store, so the prior
# per-call WARNING produced dozens of identical lines per engagement.
_insecure_key_warned = False


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
    global _insecure_key_warned
    if not _insecure_key_warned:
        logging.getLogger(__name__).warning(
            "scope_signing_key_insecure_default: using insecure dev key; set "
            "OSOP_AUDIT_SECRET_KEY to override. This is refused in production/staging."
        )
        _insecure_key_warned = True
    return _INSECURE_DEV_SIGNING_KEY


_WEAK_SECRET_VALUES = {"change-me-local", "changeme", "change-me", "default-insecure-audit-key"}


def assert_production_secrets() -> None:
    """Fail closed at startup if insecure default secrets are present in a production
    environment (OSOP-P2-11 / OSOP-P0-03). Called from the API lifespan so a misconfigured
    production deployment refuses to boot rather than silently running with a public Neo4j
    password or a forgeable audit/scope key.

    In *any* environment, a WARNING is emitted when weak/default secrets are detected so
    operators running a dev stack are never silently exposed.
    """
    _log = logging.getLogger(__name__)
    env = (getattr(settings, "environment", "") or "").lower()
    problems = []
    if (getattr(settings, "neo4j_password", "") or "") in _WEAK_SECRET_VALUES:
        problems.append("OSOP_NEO4J_PASSWORD is a weak/default value")
    if (
        not getattr(settings, "audit_secret_key", None)
        or getattr(settings, "audit_secret_key", "") in _WEAK_SECRET_VALUES
    ):
        problems.append("OSOP_AUDIT_SECRET_KEY is missing or weak/default value")
    if (
        not getattr(settings, "jwt_secret", None)
        or getattr(settings, "jwt_secret", "") in _WEAK_SECRET_VALUES
    ):
        problems.append("OSOP_JWT_SECRET is missing or weak/default value")
    if not problems:
        return
    if env in _PROD_ENVIRONMENTS:
        raise RuntimeError(
            "Refusing to start in a production environment with insecure secrets: "
            + "; ".join(problems)
        )
    # Non-production: warn loudly but allow startup (dev/test environments may rely on defaults)
    for p in problems:
        _log.warning("AIOSOP-SEC-WEAK-SECRET [%s env]: %s", env or "unknown", p)


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
