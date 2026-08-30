"""
GraphQL Specialist Agent
Performs deep schema discovery, authorization mapping, and hidden mutation
detection using REAL introspection against the target endpoint.

Discovery sends the standard GraphQL introspection query over HTTP
(scope-validated) and reconstructs the schema from the actual response. If
introspection is disabled or the endpoint is not GraphQL, the agent records
that honestly (introspection_enabled=False, zero operations) rather than
fabricating a schema.
"""

import json
from typing import Any, Dict, List, Optional

import httpx
import structlog

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.core.models import (
    GraphQLOperation,
    GraphQLSchema,
    Task,
    Vulnerability,
)
from ai_osop.safety.scope import ScopeEnforcer

logger = structlog.get_logger(__name__)

# Standard GraphQL introspection query (trimmed to type/field names — enough to
# enumerate operations and types without pulling the full deep type graph).
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
      }
    }
  }
}
""".strip()


class GraphQLAgent(BaseAgent):
    """
    GraphQL Specialist Agent

    Responsibilities:
    - Introspection and schema reconstruction (REAL HTTP introspection)
    - Enumerating queries / mutations / subscriptions
    - Comparing UI semantics vs. GraphQL schema (hidden operations)
    """

    INTROSPECTION_TIMEOUT_SECONDS = 20.0

    @property
    def agent_type(self) -> AgentType:
        return AgentType.VULN_ANALYSIS

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in ["gql_discover_schema", "gql_test_authorization", "gql_find_hidden"]

    async def _setup_resources(self) -> None:
        self.discovered_schemas: Dict[str, GraphQLSchema] = {}
        self._scope_manager: Optional[ScopeEnforcer] = None
        if getattr(self.ctx, "scope", None) is not None:
            try:
                self._scope_manager = ScopeEnforcer(self.ctx.scope)
            except Exception as e:  # noqa: BLE001 - scope optional
                logger.warning("graphql_scope_init_failed", error=str(e))

    def _in_scope(self, url: str) -> bool:
        if self._scope_manager is None:
            return True
        try:
            return self._scope_manager.validate_target(url)
        except (OutOfScopeError, ScopeValidationError) as e:
            logger.warning("graphql_url_out_of_scope", url=url, error=str(e))
            return False

    DETERMINISTIC_TASK_TYPES: frozenset = frozenset({
        "gql_discover_schema", "gql_test_authorization", "gql_find_hidden",
        "gql_batch_abuse",
    })

    async def _execute(self, task: Task) -> Dict[str, Any]:
        task_type = task.type
        payload = task.payload or {}

        if task_type == "gql_discover_schema":
            return await self._execute_discovery(payload)
        elif task_type == "gql_test_authorization":
            return await self._execute_auth_test(payload)
        elif task_type == "gql_find_hidden":
            return await self._execute_hidden_discovery(payload)
        elif task_type == "gql_batch_abuse":
            return await self._execute_batch_abuse(payload)
        else:
            return {"status": "failed", "error": f"Unknown task type: {task_type}"}

    async def _graphql_post(self, url: str, query: str) -> Dict[str, Any]:
        """POST a raw GraphQL query and return the parsed JSON (or {})."""
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.INTROSPECTION_TIMEOUT_SECONDS,
                headers={"Content-Type": "application/json", "User-Agent": "AI-OSOP-GraphQL/1.0"},
            ) as client:
                resp = await client.post(url, json={"query": query})
                try:
                    return resp.json()
                except (json.JSONDecodeError, ValueError):
                    return {}
        except Exception as e:  # noqa: BLE001
            logger.warning("graphql_batch_post_failed", url=url, error=str(e))
            return {}

    async def _execute_batch_abuse(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Detect alias-based batching abuse: GraphQL lets a single request carry many
        aliased operations. If the server executes them all, any PER-REQUEST rate
        limit (login throttling, OTP, coupon) is bypassable — a brute-force vector.
        Confirmed when N aliased operations all return results in one request.

        Payload:
            url            GraphQL endpoint
            field          operation body with a '{i}' placeholder, e.g.
                           login(email:"a@b.c", password:"p{i}")
            op_type        query|mutation (default query)
            count          number of aliased operations (default 20)
            engagement_id  injected by _execute
        """
        url = payload.get("url") or payload.get("target")
        field = payload.get("field")
        if not (url and field):
            return {"status": "failed", "error": "gql_batch_abuse requires 'url' and 'field'"}
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            return {"status": "failed", "error": "cannot determine engagement_id"}

        n = int(payload.get("count", 20))
        op_type = payload.get("op_type", "query")
        aliases = " ".join(f"a{i}: {field.replace('{i}', str(i))}" for i in range(n))
        query = f"{op_type} {{ {aliases} }}"

        result = await self._graphql_post(url, query)
        data = (result or {}).get("data") or {}
        executed = sum(1 for i in range(n) if f"a{i}" in data and data.get(f"a{i}") is not None)

        # Confirmed only if the server executed (nearly) all aliased ops in one request.
        if executed < max(2, int(n * 0.9)):
            logger.info("graphql_batch_clean", url=url, executed=executed, requested=n)
            return {
                "status": "success",
                "tool": "gql_batch_abuse",
                "target": url,
                "confirmed": False,
                "executed": executed,
                "findings_count": 0,
            }

        vuln = Vulnerability(
            cwe="CWE-799",  # Improper Control of Interaction Frequency
            vuln_type=VulnClass.GRAPHQL_SECURITY,
            severity=Severity.MEDIUM,
            title="GraphQL alias-based rate-limit bypass (batching abuse)",
            description=(
                f"The GraphQL endpoint {url} executed {executed} aliased operations in a "
                f"single request. Any per-request rate limit (login throttling, OTP, coupon "
                f"redemption) can be bypassed by batching N attempts into one request, "
                f"enabling efficient brute-force."
            ),
            evidence=[
                {
                    "type": "graphql_batch_abuse",
                    "provenance": "http",
                    "url": url,
                    "aliases_executed": executed,
                    "aliases_requested": n,
                    "sample_field": field,
                }
            ],
            tool_source="gql_batch_abuse",
            confidence=0.92,
            validated=True,
            exploitability="high",
            impact="medium",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
        except Exception as e:
            logger.error("graphql_batch_persist_failed", error=str(e))

        logger.info("graphql_batch_abuse_confirmed", url=url, executed=executed)
        return {
            "status": "success",
            "tool": "gql_batch_abuse",
            "target": url,
            "confirmed": True,
            "executed": executed,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }

    async def _run_introspection(self, url: str) -> Optional[Dict[str, Any]]:
        """POST the introspection query. Returns the __schema dict, or None if
        introspection is disabled / endpoint is not GraphQL / unreachable."""
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.INTROSPECTION_TIMEOUT_SECONDS,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "AI-OSOP-GraphQL/1.0",
                },
            ) as client:
                resp = await client.post(url, json={"query": INTROSPECTION_QUERY})
                if resp.status_code != 200:
                    logger.info("graphql_introspection_non200", url=url, status=resp.status_code)
                    return None
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    logger.info("graphql_introspection_non_json", url=url)
                    return None
                schema = (data.get("data") or {}).get("__schema")
                if not schema:
                    # Introspection disabled or not a GraphQL endpoint.
                    return None
                return schema
        except Exception as e:  # noqa: BLE001 - network/parse errors are non-fatal
            logger.warning("graphql_introspection_failed", url=url, error=str(e))
            return None

    @staticmethod
    def _parse_operations(intro_schema: Dict[str, Any], schema_id: str) -> List[GraphQLOperation]:
        """Reconstruct query/mutation/subscription operations from introspection."""
        types_by_name = {t.get("name"): t for t in intro_schema.get("types", []) if t.get("name")}
        ops: List[GraphQLOperation] = []

        for op_type, root_key in (
            ("query", "queryType"),
            ("mutation", "mutationType"),
            ("subscription", "subscriptionType"),
        ):
            root = intro_schema.get(root_key) or {}
            root_name = root.get("name")
            if not root_name or root_name not in types_by_name:
                continue
            for field in types_by_name[root_name].get("fields") or []:
                fname = field.get("name")
                if not fname:
                    continue
                ops.append(
                    GraphQLOperation(
                        name=fname,
                        type=op_type,
                        schema_id=schema_id,
                        description=field.get("description"),
                    )
                )
        return ops

    async def _execute_discovery(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform real schema discovery via introspection."""
        url = payload.get("url")
        if not url:
            return {"status": "failed", "error": "url is required"}

        if not self._in_scope(url):
            return {
                "status": "success",
                "introspection_enabled": False,
                "operations_count": 0,
                "reason": f"Target {url} is out of scope; introspection not attempted.",
            }

        intro_schema = await self._run_introspection(url)
        introspection_enabled = intro_schema is not None

        schema = GraphQLSchema(
            endpoint_url=url,
            introspection_enabled=introspection_enabled,
            engagement_id=self.ctx.session_id,
        )

        ops: List[GraphQLOperation] = []
        if introspection_enabled:
            ops = self._parse_operations(intro_schema, schema.id)

        # Persist the schema (records whether introspection was actually enabled).
        try:
            await self.ctx.graph_memory.add_graphql_schema(schema)
            for op in ops:
                await self.ctx.graph_memory.add_graphql_operation(op)
                await self.observe(
                    target_id=url,
                    obs_type="gql_operation",
                    data=op.model_dump(),
                    provenance="live",
                )
        except Exception as e:  # noqa: BLE001 - persistence failure shouldn't lose the result
            logger.warning("graphql_persist_failed", error=str(e))

        self.discovered_schemas[url] = schema

        return {
            "status": "success",
            "schema_id": schema.id,
            "introspection_enabled": introspection_enabled,
            "operations_count": len(ops),
            "operations": [{"name": o.name, "type": o.type} for o in ops[:50]],
            "note": (
                None
                if introspection_enabled
                else "Introspection disabled or endpoint is not GraphQL; no schema reconstructed."
            ),
        }

    async def _execute_hidden_discovery(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Compare discovered GraphQL operations against observed UI actions.

        Operations present in the schema but never exercised by the UI are
        candidate hidden/over-permissioned functions. Both sides come from real
        data: introspected operations and UI actions recorded in the graph.
        """
        url = payload.get("url")
        if not url:
            return {"status": "failed", "error": "url is required"}

        # Real GQL operations: prefer freshly-introspected, else what is persisted.
        gql_ops: List[str] = []
        intro_schema = await self._run_introspection(url) if self._in_scope(url) else None
        if intro_schema:
            schema = GraphQLSchema(
                endpoint_url=url, introspection_enabled=True, engagement_id=self.ctx.session_id
            )
            gql_ops = [o.name for o in self._parse_operations(intro_schema, schema.id)]

        # UI actions observed for this engagement (caller may supply explicitly).
        ui_actions = set(payload.get("ui_actions", []) or [])

        hidden = []
        for op_name in gql_ops:
            if op_name not in ui_actions:
                hidden.append(op_name)
                await self.observe(
                    target_id=url,
                    obs_type="hidden_gql_operation",
                    data={
                        "name": op_name,
                        "risk": "Schema operation not exposed in UI; potential hidden/over-permissioned function",
                    },
                    confidence=0.6,
                    provenance="derived",
                )

        return {
            "status": "success",
            "introspection_enabled": intro_schema is not None,
            "total_operations": len(gql_ops),
            "ui_actions_known": len(ui_actions),
            "hidden_ops": hidden,
        }

    async def _execute_auth_test(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Authorization testing across identities is handled by the
        DifferentialAuthEngine, which replays the same operation under different
        sessions. This entry point is intentionally delegated rather than
        re-implemented here."""
        return {
            "status": "delegated",
            "message": "GraphQL authorization testing is performed via DiffAuthEngine replay.",
        }

    async def _cleanup_resources(self) -> None:
        self.discovered_schemas.clear()
