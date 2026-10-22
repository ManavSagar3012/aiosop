"""Pre-execution MCP tool quota boundary.

The configured callback owns atomic, engagement-scoped accounting (typically a
Redis Lua script). This layer never estimates or increments quotas itself and
never exposes callback exceptions, credentials, or tool arguments to callers.
"""

import asyncio
from typing import Any, Awaitable, Callable, Dict, Optional

from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError


# True: reserved one quota unit (or ROE has no quota); False: exhausted.
# The callback must reserve atomically across processes and never debit a
# denied call. Unexpected results, timeouts, and exceptions are fail-closed.
BudgetCallback = Callable[[str, str, Optional[str]], Awaitable[bool]]

_CHECK_TIMEOUT_SECONDS = 3.0
_BOOTSTRAP_ENGAGEMENT = "api-bootstrap"

# Treat network probes as active even if a remote MCP server advertises a
# deliberately permissive scope_check=False tool definition.
_ACTIVE_TOOL_MARKERS = (
    "scan", "crawl", "nmap", "sqlmap", "ffuf", "fuzz",
    "intruder", "probe", "repeater", "attack", "exploit",
    "extension_call", "send_request", "http_request",
    "execute", "command", "shell", "write", "delete", "upload",
    "submit", "terminate", "modify", "post_request", "put_request",
)
_CONSEQUENTIAL_TOOL_MARKERS = (
    "intruder", "sqlmap", "exploit", "attack", "rce",
    "credential", "exfil", "privilege", "persistence",
    "extension_call", "send_to_repeater", "modify_target",
    "execute", "command", "shell", "write", "delete", "upload",
    "submit", "terminate", "post_request", "put_request",
)
_TARGET_KEYS = frozenset(
    ("target", "url", "target_url", "domain", "host", "hostname", "ip", "targets")
)
_TARGET_ALIASES = {
    "url_prefix": "target", "base_url": "target", "start_url": "target",
    "seed_url": "target", "target_host": "target", "target_ip": "target",
    "urls": "targets", "hosts": "targets", "target_urls": "targets",
    "baseurl": "target", "targeturl": "target", "authority": "target",
    "ip_address": "target",
}
_NESTED_KEYS = frozenset((
    "request", "requests", "params", "payload", "config",
    "options", "filters", "input", "headers",
))


def _declared_targets(parameters: Any) -> Dict[str, Any]:
    """Collect declared destinations from common nested MCP argument shapes.

    Only known destination names are treated as targets. A raw request string
    cannot be safely inspected, so a consequential tool also needs an explicit
    destination in one of these fields.
    """
    if not isinstance(parameters, dict):
        raise ValueError("MCP parameters must be an object")
    collected: Dict[str, Any] = {}
    to_check = [(parameters, 0)]
    count = 0
    while to_check:
        data, depth = to_check.pop()
        count += 1
        if count > 48:
            raise ValueError("Too many nested MCP parameter objects")
        for raw_key, value in data.items():
            if not isinstance(raw_key, str):
                raise ValueError("Invalid MCP parameter name")
            key = raw_key.strip().lower()
            if key in _TARGET_KEYS or key in _TARGET_ALIASES:
                normalized = _TARGET_ALIASES.get(key, key)
                # Do not silently ignore a second target named by an alias.
                if normalized in collected and collected[normalized] != value:
                    raise ValueError("Conflicting MCP target declarations")
                collected[normalized] = value
            elif key in _NESTED_KEYS:
                if isinstance(value, dict):
                    if depth >= 4:
                        raise ValueError("Nested MCP arguments exceed bounds")
                    to_check.append((value, depth + 1))
                elif isinstance(value, list):
                    if len(value) > 32 or depth >= 4:
                        raise ValueError("Nested MCP arguments exceed bounds")
                    for entry in value:
                        if isinstance(entry, dict):
                            to_check.append((entry, depth + 1))
    return collected


def _has_opaque_http_request(parameters: Dict[str, Any]) -> bool:
    """Opaque HTTP request strings could conceal a second, unscoped Host."""
    pending = [(parameters, 0)]
    visited = 0
    while pending:
        data, depth = pending.pop()
        visited += 1
        if visited > 48:
            return True
        for raw_key, value in data.items():
            if not isinstance(raw_key, str):
                return True
            key = raw_key.strip().lower()
            if key in {"request", "raw_request", "http_request"} and isinstance(
                value, (str, bytes)
            ):
                return True
            if key in _NESTED_KEYS and depth < 4:
                if isinstance(value, dict):
                    pending.append((value, depth + 1))
                elif isinstance(value, list):
                    pending.extend(
                        (item, depth + 1) for item in value if isinstance(item, dict)
                    )
            elif key in _NESTED_KEYS and depth >= 4:
                return True
    return False


async def check_tool_authorization(
    callback: Optional[BudgetCallback],
    server_id: str,
    tool_name: str,
    parameters: Dict[str, Any],
    context: Dict[str, str],
    *,
    requires_approval: bool = False,
) -> Optional[str]:
    """Reject unsafe direct tool invocations before *either* quota or HTTP.

    The production budget callback is bound to SessionMemory, which already
    provides authoritative session, task and approval reads. Reuse it here
    without broadening the callback signature or trusting supplied MCP args
    for engagement identity or approval. Purely local/no-target mock tools
    remain usable without persistence. Bootstrap is restricted to inert
    discovery/health calls and never permits active target operations.
    """
    if context.get("engagement_id") == _BOOTSTRAP_ENGAGEMENT:
        # No operator can make a target-bearing scan authorized by simply
        # claiming the special initialization session. This context is not
        # cryptographic authorization and cannot spend a target-side action.
        try:
            bootstrap_targets = _declared_targets(parameters)
            has_opaque = _has_opaque_http_request(parameters)
        except (TypeError, ValueError):
            return "scope_denied"
        bootstrap_allowed = {
            "get_status", "get_capabilities", "get_health", "list_tools",
            "list_capabilities", "health", "initialize", "ping",
        }
        if (
            tool_name.lower() not in bootstrap_allowed
            or requires_approval
            or bootstrap_targets
            or has_opaque
        ):
            return "scope_denied"
        return None

    name = f"{server_id}.{tool_name}".lower()
    action = tool_name.lower()
    read_only = action.startswith(("get_", "list_", "read_", "query_", "fetch_", "lookup_"))
    active = not read_only and any(marker in action for marker in _ACTIVE_TOOL_MARKERS)
    consequential = requires_approval or any(
        marker in action for marker in _CONSEQUENTIAL_TOOL_MARKERS
    )
    try:
        targets = _declared_targets(parameters)
    except (ValueError, TypeError):
        return "scope_denied"
    if active and _has_opaque_http_request(parameters):
        return "scope_denied"
    if active and not targets:
        # Even when an MCPConnection has *no* optional quota callback,
        # an active scan/probe cannot be authorized without a concrete
        # destination to validate. Historical no-target mock scans must
        # use an explicitly inert test tool instead.
        return "scope_denied"

    memory = getattr(callback, "__self__", None)
    can_load = callable(getattr(memory, "load_session_state", None))
    # ROE may require approval even for otherwise passive tools. Whenever the
    # durable authority is available, inspect its policy for every call.
    if not (targets or consequential or can_load):
        return None

    engagement_id = context.get("engagement_id")
    if not isinstance(engagement_id, str) or not engagement_id.strip():
        return "scope_context_missing"
    if not can_load:
        return "scope_unavailable"

    try:
        from ai_osop.core.models import SessionState, Task
        from ai_osop.safety.scope import (
            ScopeEnforcer,
            action_requires_approval,
            validate_payload_targets,
        )

        session = await asyncio.wait_for(
            memory.load_session_state(engagement_id),
            timeout=_CHECK_TIMEOUT_SECONDS,
        )
        from ai_osop.memory.session_memory import SessionMemory
        active_authorization = None
        # Redis task mirrors can outlive a PostgreSQL cancellation or change
        # of signed authorization. A real production SessionMemory must never
        # use the hot-cache reader to authorize MCP provider-side actions.
        task_reader = memory.load_task
        if isinstance(memory, SessionMemory):
            task_reader = memory.load_task_authoritative
            active_authorization = await asyncio.wait_for(
                memory.assert_signed_authorization(engagement_id),
                timeout=_CHECK_TIMEOUT_SECONDS,
            )
        if (
            not isinstance(session, SessionState)
            or session.session_id != engagement_id
            or session.phase in {"halted", "completed"}
            or not session.scope.authorization_ref
            or not (session.scope.domains or session.scope.ips)
        ):
            return "scope_denied"
        enforcer = ScopeEnforcer(session.scope)
        enforcer.validate_time_window()
        validate_payload_targets(enforcer, targets, require_target=active)

        if active:
            restrictions = {str(item).lower() for item in session.scope.restrictions}
            if (
                restrictions.intersection({
                    "no_active_scanning", "passive_only", "no_scans",
                    "no_intrusive_scanning", "no_side_effects",
                })
                or session.roe.get("allow_active_scanning") is False
            ):
                return "roe_denied"
            allowed = {
                str(entry).strip().lower()
                for entry in session.scope.allowed_techniques
            }
            if allowed:
                candidates = {
                    action,
                    name,
                    "active_scanning",
                    "automated_scanning",
                }
                if "sqlmap" in action:
                    candidates.update({"sqli", "sql_injection"})
                if "nmap" in action:
                    candidates.add("port_scanning")
                if "fuzz" in action or "ffuf" in action:
                    candidates.update({"fuzzing", "web_fuzzing"})
                if "crawl" in action:
                    candidates.add("crawling")
                if not allowed.intersection(candidates):
                    return "roe_denied"
        if consequential:
            restrictions = {str(item).lower() for item in session.scope.restrictions}
            if restrictions.intersection({"no_exploitation", "no_side_effects"}):
                return "roe_denied"

        must_approve = (
            consequential
            or action_requires_approval(tool_name, session.scope)
            or action_requires_approval(name, session.scope)
        )
        # Even an ordinary non-consequential MCP target call has to inherit
        # the exact policy version that admitted its executing Task. A new,
        # more permissive ROE cannot silently revive an old dispatch.
        task_id = context.get("task_id")
        if active_authorization is not None and task_id:
            if not callable(getattr(memory, "load_task", None)):
                return "scope_unavailable"
            bound_task = await asyncio.wait_for(
                task_reader(task_id), timeout=_CHECK_TIMEOUT_SECONDS
            )
            if (
                not isinstance(bound_task, Task)
                or bound_task.engagement_id != engagement_id
                or bound_task.status not in {"running", "scheduled"}
                or type(bound_task.payload.get("_authorization_version")) is not int
                or bound_task.payload["_authorization_version"] != active_authorization.version
            ):
                return "scope_denied"
        if must_approve:
            task_id = context.get("task_id")
            if not isinstance(task_id, str) or not task_id.strip():
                return "approval_required"
            if not (
                callable(getattr(memory, "load_task", None))
                and callable(getattr(memory, "is_task_approved", None))
            ):
                return "approval_unavailable"
            task = await asyncio.wait_for(
                task_reader(task_id), timeout=_CHECK_TIMEOUT_SECONDS
            )
            if (
                not isinstance(task, Task)
                or task.engagement_id != engagement_id
                or task.id != task_id
                or task.status not in {"running", "scheduled"}
            ):
                return "approval_required"
            if active_authorization is not None and (
                type(task.payload.get("_authorization_version")) is not int
                or task.payload["_authorization_version"] != active_authorization.version
            ):
                return "scope_denied"
            approval_id = task.payload.get("approval_id")
            if not isinstance(approval_id, str) or not approval_id:
                return "approval_required"
            approved = await asyncio.wait_for(
                memory.is_task_approved(task.id, engagement_id, approval_id),
                timeout=_CHECK_TIMEOUT_SECONDS,
            )
            if approved is not True:
                return "approval_required"
        return None
    except asyncio.CancelledError:
        raise
    except (OutOfScopeError, ScopeValidationError):
        return "scope_denied"
    except Exception:
        # Exceptions from scope checks and storage may contain URLs/tokens.
        return "scope_unavailable"


async def check_cancellation_authorization(
    callback: Optional[BudgetCallback],
    server_id: str,
    tool_name: str,
    parameters: Dict[str, Any],
    engagement_id: str,
    task_id: str,
    *,
    requires_approval: bool = False,
) -> Optional[str]:
    """Authorize a remote stop using persisted ROE and original call identity.

    A halt may already have transitioned the task to ``cancelled`` and the
    engagement to ``halted``. Such transitions must not prevent stopping work
    that was previously authorized. Target authorization and any original
    operator approval must still be independently verifiable.
    """
    memory = getattr(callback, "__self__", None)
    if not all(callable(getattr(memory, method, None)) for method in (
        "load_session_state", "load_task", "is_task_approved",
    )):
        return "scope_unavailable"
    if not all(isinstance(value, str) and value.strip() for value in (
        engagement_id, task_id,
    )):
        return "scope_context_missing"
    try:
        from ai_osop.memory.session_memory import SessionMemory
        from ai_osop.core.models import SessionState, Task
        from ai_osop.safety.scope import (
            ScopeEnforcer, action_requires_approval, validate_payload_targets,
        )

        task_reader = (
            memory.load_task_authoritative
            if isinstance(memory, SessionMemory)
            else memory.load_task
        )
        session, task = await asyncio.wait_for(
            asyncio.gather(
                memory.load_session_state(engagement_id), task_reader(task_id),
            ),
            timeout=_CHECK_TIMEOUT_SECONDS,
        )
        if (
            not isinstance(session, SessionState)
            or session.session_id != engagement_id
            or not isinstance(task, Task)
            or task.engagement_id != engagement_id
            or task.id != task_id
            or not session.scope.authorization_ref
            or not (session.scope.domains or session.scope.ips)
        ):
            return "scope_denied"
        if isinstance(memory, SessionMemory):
            # Redis scope/task snapshots and an old ROE reference cannot
            # authorize a provider command after signer revocation. Stopping
            # an old call is allowed after a time-window close, but still
            # requires the original task's current signed policy version.
            version = task.payload.get("_authorization_version")
            if type(version) is not int or version <= 0:
                return "scope_denied"
            await asyncio.wait_for(
                memory.assert_signed_authorization(
                    engagement_id, expected_version=version,
                ), timeout=_CHECK_TIMEOUT_SECONDS,
            )
        # A cancellation stops the *original* call. Validate its actual target,
        # not a caller-supplied replacement. Time-window checks are omitted
        # deliberately: stopping a scan after its window closes remains safe.
        active = any(marker in tool_name.lower() for marker in _ACTIVE_TOOL_MARKERS)
        validate_payload_targets(
            ScopeEnforcer(session.scope), _declared_targets(parameters),
            require_target=active,
        )
        qualified = f"{server_id}.{tool_name}"
        original_requires_approval = (
            requires_approval
            or task.approval_required
            or any(marker in tool_name.lower() for marker in _CONSEQUENTIAL_TOOL_MARKERS)
            or action_requires_approval(tool_name, session.scope)
            or action_requires_approval(qualified, session.scope)
        )
        if original_requires_approval:
            approval_id = task.payload.get("approval_id")
            if not isinstance(approval_id, str) or not approval_id:
                return "approval_required"
            approved = await asyncio.wait_for(
                memory.is_task_approved(task_id, engagement_id, approval_id),
                timeout=_CHECK_TIMEOUT_SECONDS,
            )
            if approved is not True:
                return "approval_required"
        return None
    except asyncio.CancelledError:
        raise
    except (OutOfScopeError, ScopeValidationError, ValueError):
        return "scope_denied"
    except Exception:
        return "scope_unavailable"


async def check_persisted_reconciliation_authorization(
    callback: Optional[BudgetCallback], claim: Dict[str, Any],
) -> Optional[str]:
    """Recheck current signed ownership before a persisted status-only lookup.

    Post-restart status probes use their committed claim's original identity;
    a caller-provided claim alone is not authority. This check never validates
    a new target or opens a scan's expired window because status-only queries
    have no target-side effect.
    """
    memory = getattr(callback, "__self__", None)
    from ai_osop.memory.session_memory import SessionMemory

    if not isinstance(memory, SessionMemory):
        # Legacy test/dedicated registries use the durable event-writer
        # contract; real production installations require authoritative PG.
        return None
    engagement_id = claim.get("engagement_id")
    task_id = claim.get("task_id")
    version = claim.get("authorization_version")
    if (
        not isinstance(engagement_id, str) or not engagement_id
        or not isinstance(task_id, str) or not task_id
        or type(version) is not int or version <= 0
    ):
        return "scope_denied"
    try:
        from ai_osop.core.models import Task

        task = await asyncio.wait_for(
            memory.load_task_authoritative(task_id),
            timeout=_CHECK_TIMEOUT_SECONDS,
        )
        if (
            not isinstance(task, Task)
            or task.id != task_id or task.engagement_id != engagement_id
            or type(task.payload.get("_authorization_version")) is not int
            or task.payload["_authorization_version"] != version
        ):
            return "scope_denied"
        await asyncio.wait_for(
            memory.assert_signed_authorization(
                engagement_id, expected_version=version,
            ), timeout=_CHECK_TIMEOUT_SECONDS,
        )
        return None
    except asyncio.CancelledError:
        raise
    except Exception:
        return "scope_unavailable"


async def check_tool_budget(
    callback: Optional[BudgetCallback],
    server_id: str,
    tool_name: str,
    context: Dict[str, str],
    request_id: Optional[str] = None,
) -> Optional[str]:
    """Return None to permit the HTTP call, otherwise a safe denial status.

    The callback is absent unless installed by the application. It is expected
    to treat engagements without an explicitly configured ROE budget as
    unlimited. Deliberately do not infer a session from tool parameters.
    Initialization/bootstrap and mocks without a callback remain unaffected.

    Callback tool names are qualified as `server_id.tool_name` to avoid
    collisions when different MCP servers advertise the same tool.
    """
    if callback is None:
        return None

    engagement_id = context.get("engagement_id")
    if engagement_id == _BOOTSTRAP_ENGAGEMENT:
        return None
    if not isinstance(engagement_id, str) or not engagement_id.strip():
        # No engagement means no way to look up the applicable ROE; do not
        # silently turn an attributed-budget policy into an unmetered call.
        return "quota_context_missing"

    agent = context.get("agent_id")
    agent_id = agent if isinstance(agent, str) and agent.strip() else "agent-unspecified"
    try:
        # The production Redis reservation understands the durable MCP
        # request identity. Retrying the SAME remote request on another
        # process must not charge quota twice before PostgreSQL denies its
        # duplicate dispatch claim. Custom budget callbacks retain their
        # historical three-argument contract rather than being bypassed.
        from ai_osop.memory.session_memory import SessionMemory

        canonical = getattr(callback, "__func__", None) is SessionMemory.consume_mcp_tool_budget
        reserve = (
            callback(engagement_id, f"{server_id}.{tool_name}", agent_id,
                     request_id=request_id)
            if canonical else
            callback(engagement_id, f"{server_id}.{tool_name}", agent_id)
        )
        authorized = await asyncio.wait_for(
            reserve,
            timeout=_CHECK_TIMEOUT_SECONDS,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        # Including TimeoutError/Redis errors. Never leak an exception message
        # or fall back to running an unaccounted tool.
        return "quota_unavailable"

    if authorized is True:
        return None
    if authorized is False:
        return "quota_exceeded"
    return "quota_unavailable"
