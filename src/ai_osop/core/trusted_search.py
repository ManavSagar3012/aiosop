"""Bounded, read-only search discovery over an already authorized MCP registry.

Index links and snippets are untrusted leads. They never become inventory,
verified vulnerability evidence, executable targets, or reportable findings.
No HTTP client, search API key, browser fetcher or LLM is used here.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, SessionState, Task
from ai_osop.safety.scope import ScopeEnforcer, action_requires_approval

_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_TERMS = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,63}\Z")
_MAX_RESULTS = 10
_MCP_TIMEOUT_SECONDS = 8.0


class TrustedSearchDenied(ValueError):
    """Missing, changed, or insufficient signed search authority."""


class TrustedSearchIntent(str, Enum):
    """Bounded operator intent, not an instruction to change search providers."""

    LINKS = "links"
    ANSWER = "answer"
    RESEARCH = "research"


def _trusted_search_intent(value: Any) -> TrustedSearchIntent:
    # In particular, never forward an unknown intent such as PentAGI's
    # `exploit` to a provider that might implement unsafe mode fallbacks.
    if value is None:
        return TrustedSearchIntent.LINKS
    if type(value) is not str:
        raise TrustedSearchDenied("Invalid trusted search intent")
    try:
        return TrustedSearchIntent(value)
    except ValueError as exc:
        raise TrustedSearchDenied("Unsupported trusted search intent") from exc


def _intent_metadata(intent: TrustedSearchIntent) -> Dict[str, Any]:
    # The only registered indexed search accepted here provides URL leads.
    # Neither a snippet nor a page title is a locally verified answer, and
    # forwarding `answer`/`research` could invoke paid providers or a browser.
    return {
        "intent": intent.value,
        "mode": "links",
        "intent_fulfillment": (
            "indexed_links" if intent == TrustedSearchIntent.LINKS else "leads_only"
        ),
        "synthesis_status": "not_performed",
    }


def _bounded_research_handoff(
    intent: TrustedSearchIntent, sources: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Deterministic citation-led research notes, never inferred target facts."""
    if intent == TrustedSearchIntent.LINKS:
        return {}
    notes: List[Dict[str, Any]] = []
    for item in sources[:_MAX_RESULTS]:
        snippet = _safe_text(item.get("untrusted_snippet"), 240).strip()
        title = _safe_text(item.get("title"), 120).strip()
        if not (snippet or title):
            continue
        url = item["url"]
        notes.append(
            {
                "citation_url": url,
                "citation_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                "indexed_claim": snippet or title,
                "origin_tool": item["tool"],
                "origin_engine": item["engine"],
                "trust": "untrusted_index_excerpt",
                "verification": "UNKNOWN",
                "finding_verified": False,
                "reportable": False,
            }
        )
    return {
        "research_handoff": {
            "stages": ["signed_scope_admission", "bounded_index_discovery", "citation_binding"],
            "answer_status": "unverified_excerpts_only" if notes else "UNKNOWN",
            "lead_notes": notes,
            "not_an_answer": True,
            "requires_independent_source_verification": True,
            "finding_verified": False,
            "reportable": False,
        }
    }


def _canonical_link(value: Any, domain: str, enforcer: ScopeEnforcer) -> Optional[str]:
    """Normalize source references as text only; never fetch them."""
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
        if (
            parts.scheme not in {"http", "https"}
            or not host
            or parts.username is not None
            or parts.password is not None
            or (port is not None and port not in {80, 443})
            or not (host == domain or host.endswith("." + domain))
        ):
            return None
        enforcer.validate_target(host)
    except (ValueError, TypeError):
        return None
    except Exception:
        # ScopeEnforcer rejects excluded/out-of-scope references.
        return None
    if any(ord(char) < 32 for char in parts.path):
        return None
    return urlunsplit((parts.scheme, host, parts.path[:256] or "/", "", ""))


def _safe_text(value: Any, length: int) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(ch if ch.isprintable() else " " for ch in value)[:length]


def _search_terms(value: Any) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or _TERMS.fullmatch(value.strip()) is None:
        raise TrustedSearchDenied("Invalid bounded search terms")
    return value.strip()


def _max_results(value: Any) -> int:
    if value is None:
        return 5
    if type(value) is not int or not 1 <= value <= _MAX_RESULTS:
        raise TrustedSearchDenied("Trusted search result limit out of bounds")
    return value


async def _assert_authorized(
    *,
    memory: Any,
    task: Task,
    context: Any,
    domain: str,
    authorization_binding: Optional[Dict[str, str]] = None,
) -> ScopeEnforcer:
    """Verify immutable Task, signed engagement and ROE at the provider boundary."""
    if (
        not isinstance(task, Task)
        or task.agent_type != AgentType.RECON
        or task.type not in {"osint_lookup", "full_recon"}
        or task.payload.get("trusted_search") is not True
        or type(task.payload.get("_authorization_version")) is not int
        or task.payload["_authorization_version"] < 1
        or getattr(context, "current_task", None) is not task
        or getattr(context, "session_id", None) != task.engagement_id
        or not callable(getattr(memory, "assert_signed_authorization", None))
        or not callable(getattr(memory, "load_task_authoritative", None))
    ):
        raise TrustedSearchDenied("Trusted search requires the active signed recon task")

    async def bounded(coro: Any) -> Any:
        return await asyncio.wait_for(coro, timeout=3.0)

    signed = await bounded(
        memory.assert_signed_authorization(
            task.engagement_id, expected_version=task.payload["_authorization_version"]
        )
    )
    session = await bounded(memory.load_session_state(task.engagement_id))
    current = await bounded(memory.load_task_authoritative(task.id))
    if (
        not isinstance(session, SessionState)
        or session.session_id != task.engagement_id
        or session.phase in {"halted", "completed"}
        or session.scope.engagement_id != task.engagement_id
        or not session.scope.authorization_ref
        or not (session.scope.domains or session.scope.ips)
        or type(getattr(signed, "version", None)) is not int
        or signed.version != task.payload["_authorization_version"]
        or not getattr(signed, "authorization_id", None)
        or not getattr(signed, "policy_sha256", None)
        or session.scope.authorization_ref != signed.authorization_id
        or not isinstance(current, Task)
        or current.id != task.id
        or current.engagement_id != task.engagement_id
        or current.agent_type != task.agent_type
        or current.type != task.type
        or current.flow_id != task.flow_id
        or current.approval_required != task.approval_required
        or task.scope_check is not True
        or current.scope_check is not True
        # Scheduled tasks have not yet passed the durable execution claim.
        or current.status != "running"
        or current.payload != task.payload
    ):
        raise TrustedSearchDenied("Signed engagement or persisted recon task changed")
    if authorization_binding is not None:
        observed = {
            "authorization_id": signed.authorization_id,
            "policy_sha256": signed.policy_sha256,
        }
        if authorization_binding and observed != authorization_binding:
            raise TrustedSearchDenied("Signed authorization identity changed during search")
        authorization_binding.update(observed)

    enforcer = ScopeEnforcer(session.scope)
    enforcer.validate_time_window()
    enforcer.validate_target(domain)
    if task.flow_id:
        flow = await bounded(memory.load_flow(task.flow_id))
        pinned_revisions = [
            task.payload[name]
            for name in ("_flow_revision", "planner_flow_revision")
            if name in task.payload
        ]
        if (
            not isinstance(flow, FlowRecord)
            or flow.id != task.flow_id
            or flow.engagement_id != task.engagement_id
            or flow.status != "running"
            or not isinstance(current.assigned_agent_id, str)
            or not current.assigned_agent_id.strip()
            or not isinstance(current.started_at, datetime)
            or current.completed_at is not None
            or not pinned_revisions
            or any(type(revision) is not int for revision in pinned_revisions)
            or any(revision != flow.revision for revision in pinned_revisions)
        ):
            raise TrustedSearchDenied("Trusted search signed Flow revision is no longer active")
    if (
        task.approval_required
        or action_requires_approval(task.type, session.scope)
        or action_requires_approval("web_search", session.scope)
        or action_requires_approval("recon-mcp.web_search", session.scope)
    ):
        approval_id = current.payload.get("approval_id")
        if (
            not isinstance(approval_id, str)
            or not approval_id
            or await bounded(memory.is_task_approved(task.id, task.engagement_id, approval_id))
            is not True
        ):
            raise TrustedSearchDenied("Trusted search task approval is unavailable")
    if getattr(context, "current_task", None) is not task:
        raise TrustedSearchDenied("Trusted search execution context changed")
    return enforcer


async def discover_trusted_search(
    *, context: Any, task: Optional[Task], domain: Optional[str]
) -> Dict[str, Any]:
    """Discover scoped URL leads for typed links/answer/research intents.

    The indexed web_search operation is optional and must be advertised by the
    existing recon MCP service. The built-in Wayback operation supplies a
    secondary archive index. Answer and research intents return unverified
    leads, never a synthesized answer: both dispatch ONLY the links operation.
    No Shodan/paid or direct browser fetch is used.
    """
    if not isinstance(task, Task):
        raise TrustedSearchDenied("Trusted search requires a signed active task")
    domain = domain.lower().rstrip(".") if isinstance(domain, str) else ""
    if _DOMAIN.fullmatch(domain) is None:
        raise TrustedSearchDenied("Trusted search requires a canonical domain")
    intent = _trusted_search_intent(task.payload.get("trusted_search_mode"))
    intent_metadata = _intent_metadata(intent)
    terms = _search_terms(task.payload.get("trusted_search_terms"))
    limit = _max_results(task.payload.get("trusted_search_max_results"))
    memory = context.session_memory
    binding: Dict[str, str] = {}
    enforcer = await _assert_authorized(
        memory=memory,
        task=task,
        context=context,
        domain=domain,
        authorization_binding=binding,
    )
    registry = context.mcp_registry
    get_server = getattr(registry, "get_server", None)
    if not callable(get_server):
        raise TrustedSearchDenied("Authorized MCP registry is unavailable")
    server = get_server("recon-mcp")
    if server is None or not callable(getattr(server, "list_tools", None)):
        return {
            "status": "unknown",
            "validation_state": "UNKNOWN",
            "domain": domain,
            "sources": [],
            "provider_status": "unavailable",
            **intent_metadata,
        }
    # The production adapter initializes the MCP connection using the scope
    # supplied by the task. Rebind it to the authoritative signed scope here.
    enforcer = await _assert_authorized(
        memory=memory,
        task=task,
        context=context,
        domain=domain,
        authorization_binding=binding,
    )
    try:
        initialized = await asyncio.wait_for(
            registry.initialize_server(
                "recon-mcp", enforcer.scope.model_dump(mode="json"), {}, task.engagement_id
            ),
            timeout=_MCP_TIMEOUT_SECONDS,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        await _assert_authorized(
            memory=memory,
            task=task,
            context=context,
            domain=domain,
            authorization_binding=binding,
        )
        return {
            "status": "unknown",
            "validation_state": "UNKNOWN",
            "domain": domain,
            "sources": [],
            "provider_status": "unavailable",
            **intent_metadata,
        }
    await _assert_authorized(
        memory=memory,
        task=task,
        context=context,
        domain=domain,
        authorization_binding=binding,
    )
    if getattr(initialized, "status", None) != "ready":
        return {
            "status": "unknown",
            "validation_state": "UNKNOWN",
            "domain": domain,
            "sources": [],
            "provider_status": "unavailable",
            **intent_metadata,
        }
    try:
        tools = await asyncio.wait_for(server.list_tools(), timeout=3)
    except asyncio.CancelledError:
        raise
    except Exception:
        await _assert_authorized(
            memory=memory,
            task=task,
            context=context,
            domain=domain,
            authorization_binding=binding,
        )
        return {
            "status": "unknown",
            "validation_state": "UNKNOWN",
            "domain": domain,
            "sources": [],
            "provider_status": "unavailable",
            **intent_metadata,
        }
    available = {
        getattr(tool, "name", ""): tool
        for tool in tools
        if getattr(tool, "scope_check", False) is True
        and getattr(tool, "requires_approval", True) is False
    }

    sources: List[Dict[str, Any]] = []
    seen: set[str] = set()
    attempted = 0
    for name in ("web_search", "wayback_urls"):
        tool = available.get(name)
        if tool is None or len(sources) >= limit:
            continue
        if name == "web_search" and "searxng" not in str(getattr(tool, "description", "")).lower():
            # The operator opted into the approved free index adapter, not
            # any provider that reuses the generic search name.
            continue
        parameter_names = {getattr(p, "name", "") for p in getattr(tool, "parameters", [])}
        if name == "web_search" and {"query", "domain", "mode", "max_results"}.issubset(
            parameter_names
        ):
            params: Dict[str, Any] = {
                "query": f"site:{domain}" + (f" {terms}" if terms else ""),
                "mode": "links",
                "max_results": limit,
                "domain": domain,
            }
        elif name == "wayback_urls" and "domain" in parameter_names:
            params = {"domain": domain}
        else:
            continue
        await _assert_authorized(
            memory=memory,
            task=task,
            context=context,
            domain=domain,
            authorization_binding=binding,
        )
        attempted += 1
        try:
            response = await asyncio.wait_for(
                registry.execute_tool(
                    "recon-mcp", name, params, timeout_override=int(_MCP_TIMEOUT_SECONDS)
                ),
                timeout=_MCP_TIMEOUT_SECONDS + 1,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # A failed/unknown remote source is never evidence of no exposure.
            await _assert_authorized(
                memory=memory,
                task=task,
                context=context,
                domain=domain,
                authorization_binding=binding,
            )
            continue
        enforcer = await _assert_authorized(
            memory=memory,
            task=task,
            context=context,
            domain=domain,
            authorization_binding=binding,
        )
        data = getattr(response, "result", None)
        if (
            getattr(response, "status", "") != "success"
            or not isinstance(data, dict)
            or data.get("error")
            or data.get("status", "success") not in {"ok", "success"}
        ):
            continue
        raw = data.get("results", data.get("links")) if name == "web_search" else data.get("urls")
        if not isinstance(raw, list):
            continue
        engine = _safe_text(data.get("engine"), 32)
        if name == "web_search" and engine != "searxng":
            # Other/billed engines must be authorized separately; never
            # implicitly substitute a paid engine through search fallback.
            continue
        for entry in raw[: min(100, limit * 5)]:
            item = entry if isinstance(entry, dict) else {"url": entry}
            link = _canonical_link(item.get("url"), domain, enforcer)
            if not link or link in seen:
                continue
            seen.add(link)
            sources.append(
                {
                    "url": link,
                    "title": _safe_text(item.get("title"), 120),
                    "untrusted_snippet": _safe_text(item.get("snippet"), 240),
                    "provider": "recon-mcp",
                    "tool": name,
                    "engine": engine if name == "web_search" else "wayback",
                    "source": _safe_text(item.get("source"), 64),
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "validation_state": "UNKNOWN",
                    "verified": False,
                    "reportable": False,
                }
            )
            if len(sources) == limit:
                break
    await _assert_authorized(
        memory=memory,
        task=task,
        context=context,
        domain=domain,
        authorization_binding=binding,
    )
    return {
        "status": "success" if sources else "unknown",
        "validation_state": "UNKNOWN",
        "domain": domain,
        **intent_metadata,
        "sources": sources,
        "source_count": len(sources),
        "provider_status": ("returned_index" if sources else "unavailable_or_unconfirmed"),
        "attempted_sources": attempted,
        **_bounded_research_handoff(intent, sources),
    }
