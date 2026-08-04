"""
Agent Registry — extracted from ``main.py`` lifespan to keep the entry point focused.

All agent classes are imported lazily inside ``register_all_agents`` so that
module-level imports in ``main.py`` stay clean and adding a new agent only
requires touching this file (and the config enum).
"""

import logging
from typing import Any, Dict

from ai_osop.agents.attack_chain_agent import AttackChainAgent
from ai_osop.agents.base import AgentContext
from ai_osop.agents.chain_composer_agent import ChainComposerAgent
from ai_osop.agents.chain_executor_agent import ChainExecutorAgent
from ai_osop.agents.cloud_agent import CloudSpecialistAgent
from ai_osop.agents.codeql_agent import CodeQLAgent
from ai_osop.agents.concurrency_agent import ConcurrencyAgent
from ai_osop.agents.context_manager_agent import ContextManagerAgent
from ai_osop.agents.csrf_agent import CSRFAgent
from ai_osop.agents.exploit_agent import ExploitValidationAgent
from ai_osop.agents.graphql_agent import GraphQLAgent
from ai_osop.agents.human_oversight_agent import HumanOversightAgent
from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
from ai_osop.agents.jwt_agent import JWTAgent
from ai_osop.agents.mobile_agent import MobileAnalysisAgent
from ai_osop.agents.nextjs_agent import NextJSSpecialistAgent
from ai_osop.agents.passive_recon_agent import PassiveReconAgent
from ai_osop.agents.payload_agent import PayloadMutationAgent
from ai_osop.agents.pollution_scanner import PollutionScanner
from ai_osop.agents.post_exploit_agent import PostExploitAgent
from ai_osop.agents.race_scanner import RaceScanner
from ai_osop.agents.react_agent import ReactSpecialistAgent
from ai_osop.agents.recon_agent import ReconAgent
from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.agents.retrieval_agent import RetrievalAgent
from ai_osop.agents.saml_agent import SAMLAgent
from ai_osop.agents.smuggling_scanner import SmugglingScanner
from ai_osop.agents.ssrf_agent import SSRFAgent
from ai_osop.agents.ssti_agent import SSTIAgent
from ai_osop.agents.stack_profiler_agent import StackProfilerAgent
from ai_osop.agents.stateful_logic_agent import StatefulLogicAgent
from ai_osop.agents.takeover_agent import TakeoverAgent
from ai_osop.agents.upload_scanner import UploadScanner
from ai_osop.agents.visual_agent import VisualContextAgent
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.agents.websocket_agent import WebSocketAgent
from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.core.enums import AgentType

logger = logging.getLogger("ai_osop.agent_registry")


async def register_all_agents(
    orch,
    session_memory,
    graph_memory,
    vector_memory,
    llm_client,
    mcp_registry,
    rate_limiter,
    threat_intel_adapter,
    state: Dict[str, Any],
) -> None:
    """Instantiate and register all platform agents with the orchestrator."""
    await orch.initialize()

    bootstrap_session_id = "api-bootstrap"

    # Worker counts per agent type — tune per deployment
    _VULN_WORKERS = 10
    _RECON_WORKERS = 4
    _EXPLOIT_WORKERS = 3
    _SSTI_WORKERS = 3
    _SSRF_WORKERS = 3
    _CSRF_WORKERS = 3
    _JWT_WORKERS = 3
    _SMUGGLING_WORKERS = 3
    _RACE_WORKERS = 3
    _UPLOAD_WORKERS = 3
    _POLLUTION_WORKERS = 3
    _WEBSOCKET_WORKERS = 3
    _SAML_WORKERS = 3
    _TAKEOVER_WORKERS = 3
    # WORKFLOW pool drives ALL browser work through a shared Chromium (pages keyed
    # by user_label, so different identities run truly in parallel). The diff-auth
    # chain alone needs register×2 + authenticate×2 concurrently for its two
    # identities; at 3 the 4th auth task waited ~183s for a slot and timed out at
    # 180s, killing the whole csrf/jwt chain downstream. 6 gives that headroom.
    _WORKFLOW_WORKERS = 6

    agents_to_register = [
        (AttackChainAgent, AgentType.ATTACK_CHAIN, "attack-chain-agent-001"),
        (ChainComposerAgent, AgentType.ATTACK_CHAIN, "chain-composer-agent-001"),
        (ChainExecutorAgent, AgentType.ATTACK_CHAIN, "chain-executor-agent-001"),
        (PostExploitAgent, AgentType.EXPLOITATION, "post-exploit-agent-001"),
        (RetrievalAgent, AgentType.RETRIEVAL, "retrieval-agent-001"),
    ]

    for i in range(1, _RECON_WORKERS + 1):
        agents_to_register.append((ReconAgent, AgentType.RECON, f"recon-agent-{i:03d}"))
    for i in range(1, 3):
        agents_to_register.append(
            (PassiveReconAgent, AgentType.RECON, f"passive-recon-agent-{i:03d}")
        )

    for i in range(1, _VULN_WORKERS + 1):
        agents_to_register.append(
            (VulnAnalysisAgent, AgentType.VULN_ANALYSIS, f"vuln-agent-{i:03d}")
        )

    for i in range(1, _EXPLOIT_WORKERS + 1):
        agents_to_register.append(
            (ExploitValidationAgent, AgentType.EXPLOIT_VALIDATION, f"exploit-agent-{i:03d}")
        )

    agents_to_register.extend(
        [
            (HumanOversightAgent, AgentType.HUMAN_OVERSIGHT, "human-oversight-agent-001"),
            (PayloadMutationAgent, AgentType.PAYLOAD_MUTATION, "payload-agent-001"),
            (ReportingAgent, AgentType.REPORTING, "reporting-agent-001"),
            (ContextManagerAgent, AgentType.CONTEXT_MANAGER, "context-manager-agent-001"),
            (ConcurrencyAgent, AgentType.CONCURRENCY, "concurrency-agent-001"),
            (StackProfilerAgent, AgentType.CONTEXT_MANAGER, "stack-profiler-agent-001"),
            (CloudSpecialistAgent, AgentType.CLOUD_SPECIALIST, "cloud-agent-001"),
            (CodeQLAgent, AgentType.SAST_ANALYSIS, "codeql-agent-001"),
            (GraphQLAgent, AgentType.VULN_ANALYSIS, "graphql-agent-001"),
            (JSAnalyzerAgent, AgentType.VULN_ANALYSIS, "js-analyzer-agent-001"),
            (MobileAnalysisAgent, AgentType.VULN_ANALYSIS, "mobile-agent-001"),
            (NextJSSpecialistAgent, AgentType.NEXTJS_SPECIALIST, "nextjs-agent-001"),
            (ReactSpecialistAgent, AgentType.REACT_SPECIALIST, "react-agent-001"),
            (StatefulLogicAgent, AgentType.STATEFUL_LOGIC, "stateful-logic-agent-001"),
            (VisualContextAgent, AgentType.VISUAL_CONTEXT, "visual-agent-001"),
        ]
    )

    for i in range(1, _WORKFLOW_WORKERS + 1):
        agents_to_register.append(
            (PlaywrightAgent, AgentType.WORKFLOW, f"playwright-agent-{i:03d}")
        )

    for i in range(1, _SSTI_WORKERS + 1):
        agents_to_register.append((SSTIAgent, AgentType.SSTI_SCANNER, f"ssti-agent-{i:03d}"))
    for i in range(1, _SSRF_WORKERS + 1):
        agents_to_register.append((SSRFAgent, AgentType.SSRF_SCANNER, f"ssrf-agent-{i:03d}"))
    for i in range(1, _CSRF_WORKERS + 1):
        agents_to_register.append((CSRFAgent, AgentType.CSRF_SCANNER, f"csrf-agent-{i:03d}"))
    for i in range(1, _JWT_WORKERS + 1):
        agents_to_register.append((JWTAgent, AgentType.JWT_SCANNER, f"jwt-agent-{i:03d}"))
    for i in range(1, _SMUGGLING_WORKERS + 1):
        agents_to_register.append(
            (SmugglingScanner, AgentType.SMUGGLING_SCANNER, f"smuggling-agent-{i:03d}")
        )
    for i in range(1, _RACE_WORKERS + 1):
        agents_to_register.append((RaceScanner, AgentType.RACE_SCANNER, f"race-agent-{i:03d}"))
    for i in range(1, _UPLOAD_WORKERS + 1):
        agents_to_register.append(
            (UploadScanner, AgentType.UPLOAD_SCANNER, f"upload-agent-{i:03d}")
        )
    for i in range(1, _POLLUTION_WORKERS + 1):
        agents_to_register.append(
            (PollutionScanner, AgentType.POLLUTION_SCANNER, f"pollution-agent-{i:03d}")
        )
    for i in range(1, _WEBSOCKET_WORKERS + 1):
        agents_to_register.append(
            (WebSocketAgent, AgentType.WEBSOCKET_SCANNER, f"websocket-agent-{i:03d}")
        )
    for i in range(1, _SAML_WORKERS + 1):
        agents_to_register.append((SAMLAgent, AgentType.SAML_SCANNER, f"saml-agent-{i:03d}"))
    for i in range(1, _TAKEOVER_WORKERS + 1):
        agents_to_register.append(
            (TakeoverAgent, AgentType.TAKEOVER_SCANNER, f"takeover-agent-{i:03d}")
        )

    skill_engine = state.get("skill_engine")
    receipt_store = state.get("receipt_store")

    for agent_cls, agent_type, agent_id in agents_to_register:
        ctx = AgentContext(
            agent_id=agent_id,
            agent_type=agent_type,
            session_id=bootstrap_session_id,
            session_memory=session_memory,
            graph_memory=graph_memory,
            vector_memory=vector_memory,
            llm_client=llm_client,
            mcp_registry=mcp_registry,
            rate_limiter=rate_limiter,
            threat_intel_adapter=threat_intel_adapter,
            audit_callback=orch._audit_log,
            coordination_bus=orch.coordination_bus,
        )
        ctx.skill_engine = skill_engine
        agent_inst = agent_cls(ctx)
        # Proof-carrying chains: receipts gated by evidence_receipts_enabled. When
        # the flag is OFF receipt_store is None; agents must treat it as
        # best-effort and never flip a verdict based on receipt success/failure.
        agent_inst.receipt_store = receipt_store
        await orch.register_agent(agent_inst)

    logger.info(
        "registered %d agent instances (%d unique types)",
        len(agents_to_register),
        len(set(a[1] for a in agents_to_register)),
    )
