from typing import Any, Dict, Optional
from ai_osop.core.models import Task

class OrchestrationState:
    def __init__(self):
        self.agents: Dict[str, Any] = {}  # agent_id -> agent instance
        self.tasks: Dict[str, Task] = {}  # task_id -> Task
        self.sessions: Dict[str, Any] = {}  # session_id -> SessionState
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
