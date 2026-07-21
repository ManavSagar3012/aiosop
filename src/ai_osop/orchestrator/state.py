from typing import Any, Dict, Optional

from ai_osop.core.models import Task


class SessionDict(dict):
    """A dict that allows lookups by either ``session.session_id`` (long form,
    e.g. ``eng-20260716-juice-e2e``) or by the canonical engagement id (short
    form, e.g. ``juice-e2e``).

    BLK-1 / MAJ-1 fix (2026-07-21): ``get()`` previously called ``key in self``
    which triggered ``__contains__`` -> ``get()`` -> infinite recursion.
    Use ``dict.__contains__`` for the fast path and ``canonical_engagement_id``
    for the fallback search.
    """

    def get(self, key, default=None):
        # Fast path: direct dict lookup (long form).
        # Use dict.__contains__ to avoid recursion through __contains__ -> get().
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        # Fallback: search by canonical_engagement_id (short form).
        for session in self.values():
            eid = getattr(session, "canonical_engagement_id", None)
            if eid == key:
                return session
            # Also check session.scope.engagement_id directly for robustness.
            if hasattr(session, "scope"):
                scope_eid = getattr(session.scope, "engagement_id", None)
                if scope_eid == key:
                    return session
        return default

    def __getitem__(self, key):
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key):
        return self.get(key) is not None


class OrchestrationState:
    def __init__(self):
        self.agents: Dict[str, Any] = {}  # agent_id -> agent instance
        self.tasks: Dict[str, Task] = {}  # task_id -> Task
        self.sessions: Dict[str, Any] = SessionDict()  # session_id -> SessionState
        self.approval_requests: Dict[str, Any] = {}
        self.auto_transition_failures: Dict[str, Dict[str, Any]] = {}

    def register_agent(self, agent: Any):
        self.agents[agent.ctx.agent_id] = agent

    def unregister_agent(self, agent_id: str):
        if agent_id in self.agents:
            del self.agents[agent_id]

    def get_agent(self, agent_id: str) -> Any:
        return self.agents.get(agent_id)

    def get_all_agents(self) -> Dict[str, Any]:
        return self.agents

    def add_task(self, task: Task):
        self.tasks[task.id] = task

    def get_task(self, task_id: str) -> Optional[Task]:
        return self.tasks.get(task_id)

    def get_all_tasks(self) -> Dict[str, Task]:
        return self.tasks
