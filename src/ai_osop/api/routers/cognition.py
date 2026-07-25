"""Cognition API Router — exposes the cognitive architecture to the dashboard.

This router makes the reasoning loop, uncertainty tracker, business context
engine, graph pathfinder, adversarial critic, and WAF character probe
visible to operators via REST endpoints. Every cognitive component that
runs in the backend now has a corresponding API the dashboard can poll.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from ai_osop.api.deps import assert_engagement_access, engagement_id_forms, state, verify_token

router = APIRouter(tags=["cognition"])


@router.get("/engagements/{session_id}/reasoning-trace")
async def get_reasoning_trace(
    session_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return the reasoning trace — every decision the reasoning loop made.

    Each entry shows: step (observe/orient/hypothesize/select/dispatch/
    evaluate/critique/learn), decision, rationale, confidence, alternatives
    considered, alternatives rejected, and result.
    """
    session = await assert_engagement_access(operator, session_id)
    orch = state["orchestrator"]
    rl = getattr(orch, "reasoning_loop", None)
    if rl is None or not hasattr(rl, "trace"):
        return {"session_id": session_id, "count": 0, "trace": []}
    forms = engagement_id_forms(session, session_id)
    entries = rl.trace.get_trace(*forms)
    return {"session_id": session_id, "count": len(entries), "trace": entries}


@router.get("/engagements/{session_id}/uncertainties")
async def get_uncertainties(
    session_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return open uncertainties detected by the UncertaintyTracker.

    Each uncertainty is something the system doesn't know yet:
    'is this endpoint authenticated?', 'what framework is this?', etc.
    """
    session = await assert_engagement_access(operator, session_id)
    orch = state["orchestrator"]
    rl = getattr(orch, "reasoning_loop", None)
    if rl is None or not hasattr(rl, "_uncertainty_tracker"):
        return {"session_id": session_id, "count": 0, "uncertainties": [], "summary": {}}
    tracker = rl._uncertainty_tracker
    forms = engagement_id_forms(session, session_id)
    open_uncs = tracker.get_open_uncertainties(*forms)
    return {
        "session_id": session_id,
        "count": len(open_uncs),
        "uncertainties": [u.__dict__ for u in open_uncs],
        "summary": tracker.get_summary(*forms),
    }


@router.get("/engagements/{session_id}/business-context")
async def get_business_context(
    session_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return the business-context categorization of all endpoints.

    Each endpoint is categorized by business domain (payment/auth/admin/
    file/user/api/config/redirect/static) with a criticality score (1-10),
    recommended tests, and business invariants.
    """
    session = await assert_engagement_access(operator, session_id)
    from ai_osop.core.business_context import batch_categorize

    orch = state["orchestrator"]
    gm = orch.graph_memory
    forms = engagement_id_forms(session, session_id)
    try:
        endpoints = await gm.run_read_query(
            "MATCH (e:Endpoint) WHERE e.engagement_id IN $ids "
            "RETURN e.url AS url, e.path AS path, e.method AS method, "
            "e.query_keys AS query_keys, e.status_code AS status_code, "
            "e.technologies AS technologies, e.auth_required AS auth_required, "
            "e.id AS id LIMIT 500",
            {"ids": forms},
        )
    except Exception:
        endpoints = []
    categorized = batch_categorize(endpoints)
    return {
        "session_id": session_id,
        "count": len(categorized),
        "endpoints": [c.__dict__ for c in categorized],
        "high_value_count": len([c for c in categorized if c.criticality >= 7]),
    }


@router.get("/engagements/{session_id}/attack-chains")
async def get_attack_chains(
    session_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return attack chains discovered by the GraphPathfinder.

    Chains are multi-step attack paths from confirmed vulnerabilities
    to high-value endpoints, discovered via Neo4j graph traversal.
    """
    await assert_engagement_access(operator, session_id)
    from ai_osop.core.graph_pathfinder import GraphPathfinder

    orch = state["orchestrator"]
    pathfinder = GraphPathfinder(orch.graph_memory)
    chains = await pathfinder.find_chains(session_id, max_depth=5)
    return {
        "session_id": session_id,
        "count": len(chains),
        "chains": chains,
    }


@router.get("/engagements/{session_id}/critic-review")
async def get_critic_review(
    session_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return the adversarial critic's review of validated findings.

    The CriticAgent audits every validated finding for false positives,
    missing evidence, and incomplete validation before reporting.
    """
    await assert_engagement_access(operator, session_id)
    from ai_osop.agents.critic_agent import PostEngagementCriticAgent

    orch = state["orchestrator"]
    critic = PostEngagementCriticAgent(orch.session_memory, orch.graph_memory)
    critiques = await critic.audit_findings(session_id)
    return {
        "session_id": session_id,
        "count": len(critiques),
        "critiques": critiques,
    }



@router.get("/engagements/{session_id}/cognition-summary")
async def get_cognition_summary(
    session_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return a unified cognition metrics summary.

    Aggregates: reasoning trace steps, hypothesis counts, uncertainty
    counts, attack chain counts, critic issue counts, and business
    context high-value endpoint counts — all in one call for the
    Cognition Dashboard page.
    """
    session = await assert_engagement_access(operator, session_id)
    forms = engagement_id_forms(session, session_id)
    orch = state["orchestrator"]
    rl = getattr(orch, "reasoning_loop", None)

    # Reasoning trace summary
    trace_summary = {"total_steps": 0, "confirmed": 0, "refuted": 0, "chains": 0, "pivots": 0}
    if rl is not None and hasattr(rl, "trace"):
        trace_summary = rl.trace.get_summary(*forms)

    # Uncertainty summary
    unc_summary = {"total": 0, "resolved": 0, "open": 0}
    if rl is not None and hasattr(rl, "_uncertainty_tracker"):
        unc_summary = rl._uncertainty_tracker.get_summary(*forms)

    # Attack chains
    chain_count = 0
    try:
        from ai_osop.core.graph_pathfinder import GraphPathfinder
        pathfinder = GraphPathfinder(orch.graph_memory)
        chains = await pathfinder.find_chains(session_id, max_depth=5)
        chain_count = len(chains)
    except Exception:
        pass

    # Critic review
    critic_count = 0
    try:
        from ai_osop.agents.critic_agent import PostEngagementCriticAgent
        critic = PostEngagementCriticAgent(orch.session_memory, orch.graph_memory)
        critiques = await critic.audit_findings(session_id)
        critic_count = len(critiques)
    except Exception:
        pass

    # Business context
    high_value = 0
    try:
        from ai_osop.core.business_context import batch_categorize
        endpoints = await orch.graph_memory.run_read_query(
            "MATCH (e:Endpoint) WHERE e.engagement_id IN $ids "
            "RETURN e.url AS url, e.path AS path, e.query_keys AS query_keys "
            "LIMIT 500",
            {"ids": forms},
        )
        categorized = batch_categorize(endpoints)
        high_value = len([c for c in categorized if c.criticality >= 7])
    except Exception:
        pass

    return {
        "session_id": session_id,
        "reasoning_trace": trace_summary,
        "uncertainties": unc_summary,
        "attack_chains": chain_count,
        "critic_issues": critic_count,
        "high_value_endpoints": high_value,
        "dead_ends": getattr(rl, "_dead_ends", 0) if rl else 0,
        "tested_hypotheses": len(getattr(rl, "_tested_hypotheses", set())) if rl else 0,
    }
