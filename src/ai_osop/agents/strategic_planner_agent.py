"""
Strategic Planner Agent - Goal-Oriented Action Planning (GOAP)

This agent implements strategic autonomy, moving AI-OSOP from reactive 
event processing to proactive attack planning. It maintains a global 
goal tree and dynamically tasks specialized agents to fill intelligence gaps.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from .cognitive_swarm_agent import CognitiveSwarmAgent
from ..orchestrator.distributed_bus import CoordinationEvent

logger = logging.getLogger(__name__)


class GoalStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class GoalPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class StrategicGoal:
    """Represents a high-level offensive security goal."""

    id: str
    name: str
    description: str
    priority: GoalPriority
    status: GoalStatus = GoalStatus.PENDING
    sub_goals: List[str] = field(default_factory=list)
    required_findings: Set[str] = field(default_factory=set)
    completed_findings: Set[str] = field(default_factory=set)
    assigned_agents: List[str] = field(default_factory=list)

    def is_complete(self) -> bool:
        return self.required_findings.issubset(self.completed_findings)

    def get_missing_findings(self) -> Set[str]:
        return self.required_findings - self.completed_findings


@dataclass
class IntelligenceGap:
    """Represents missing information needed to achieve a goal."""

    goal_id: str
    gap_type: str  # e.g., "os_version", "service_banner", "credential"
    target: str
    description: str
    priority: GoalPriority


class StrategicPlannerAgent(CognitiveSwarmAgent):
    """
    Autonomous agent that plans attack strategies and tasks other agents.

    Unlike reactive agents, this agent:
    1. Maintains a global goal tree
    2. Identifies intelligence gaps
    3. Proactively publishes task requests (not just events)
    4. Dynamically reprioritizes based on new findings
    """

    def __init__(self, agent_id: str, redis_url: str):
        super().__init__(agent_id, redis_url)
        self.goals: Dict[str, StrategicGoal] = {}
        self.intelligence_gaps: List[IntelligenceGap] = []
        self.current_strategy: Optional[str] = None

        # Default attack goals for web applications
        self._initialize_default_goals()

    def _initialize_default_goals(self):
        """Initialize standard penetration testing goals."""
        default_goals = [
            StrategicGoal(
                id="goal_recon_complete",
                name="Complete Reconnaissance",
                description="Map entire attack surface including hidden endpoints",
                priority=GoalPriority.CRITICAL,
                required_findings={"all_endpoints", "all_technologies", "all_subdomains"},
            ),
            StrategicGoal(
                id="goal_auth_bypass",
                name="Achieve Authentication Bypass",
                description="Bypass authentication mechanisms",
                priority=GoalPriority.HIGH,
                required_findings={"auth_mechanism", "potential_vulnerability"},
            ),
            StrategicGoal(
                id="goal_rce",
                name="Achieve Remote Code Execution",
                description="Execute arbitrary code on target system",
                priority=GoalPriority.CRITICAL,
                required_findings={"vulnerable_service", "exploit_path", "payload_delivery"},
            ),
            StrategicGoal(
                id="goal_data_exfil",
                name="Data Exfiltration",
                description="Extract sensitive data from target",
                priority=GoalPriority.HIGH,
                required_findings={"sensitive_data_location", "exfiltration_channel"},
            ),
        ]

        for goal in default_goals:
            self.goals[goal.id] = goal

    async def start(self):
        """Start the strategic planner with autonomous goal management."""
        logger.info(f"🧠 {self.agent_id} starting strategic planning...")

        # Subscribe to all finding events
        await self.subscribe(
            ["recon.discovery", "vuln.detected", "exploit.success", "credential.found"]
        )

        # Start goal evaluation loop
        asyncio.create_task(self._goal_evaluation_loop())

        logger.info(f"🧠 {self.agent_id} active and planning attacks")

    async def handle_event(self, event: CoordinationEvent):
        """Process new findings and update strategic goals."""
        logger.debug(f"🧠 Processing event: {event.topic}")

        # Update goal progress based on finding type
        if event.topic == "recon.discovery":
            await self._process_recon_finding(event)
        elif event.topic == "vuln.detected":
            await self._process_vuln_finding(event)
        elif event.topic == "exploit.success":
            await self._process_exploit_success(event)

        # Re-evaluate goals and identify gaps
        await self._identify_intelligence_gaps()

    async def _process_recon_finding(self, event: CoordinationEvent):
        """Update reconnaissance goals based on new discovery."""
        finding_type = event.payload.get("finding_type", "")

        if "endpoint" in finding_type.lower():
            for goal in self.goals.values():
                if "all_endpoints" in goal.required_findings:
                    goal.completed_findings.add("all_endpoints")

        if "technology" in finding_type.lower():
            for goal in self.goals.values():
                if "all_technologies" in goal.required_findings:
                    goal.completed_findings.add("all_technologies")

    async def _process_vuln_finding(self, event: CoordinationEvent):
        """Update vulnerability/exploitation goals."""
        severity = event.payload.get("severity", "")
        vuln_type = event.payload.get("vuln_type", "")

        if severity in ["critical", "high"]:
            for goal in self.goals.values():
                if "potential_vulnerability" in goal.required_findings:
                    goal.completed_findings.add("potential_vulnerability")

                if "vulnerable_service" in goal.required_findings:
                    goal.completed_findings.add("vulnerable_service")

    async def _process_exploit_success(self, event: CoordinationEvent):
        """Handle successful exploitation."""
        logger.warning(f"🎯 Exploit successful: {event.payload.get('target')}")

        for goal in self.goals.values():
            if "exploit_path" in goal.required_findings:
                goal.completed_findings.add("exploit_path")

    async def _identify_intelligence_gaps(self):
        """Identify missing intelligence needed to achieve goals."""
        self.intelligence_gaps.clear()

        for goal in self.goals.values():
            if goal.status == GoalStatus.COMPLETED:
                continue

            missing = goal.get_missing_findings()

            for finding in missing:
                gap = IntelligenceGap(
                    goal_id=goal.id,
                    gap_type=self._map_finding_to_gap_type(finding),
                    target="target_environment",  # Could be more specific
                    description=f"Need {finding} to achieve: {goal.name}",
                    priority=goal.priority,
                )
                self.intelligence_gaps.append(gap)

        # Publish task requests for high-priority gaps
        await self._publish_task_requests()

    def _map_finding_to_gap_type(self, finding: str) -> str:
        """Map required finding to intelligence gap type."""
        mapping = {
            "all_endpoints": "endpoint_discovery",
            "all_technologies": "technology_stack",
            "all_subdomains": "subdomain_enumeration",
            "auth_mechanism": "authentication_analysis",
            "potential_vulnerability": "vulnerability_scanning",
            "vulnerable_service": "service_enumeration",
            "exploit_path": "exploit_development",
            "payload_delivery": "payload_delivery_method",
            "sensitive_data_location": "data_discovery",
            "exfiltration_channel": "network_mapping",
        }
        return mapping.get(finding, "general_recon")

    async def _publish_task_requests(self):
        """Publish task requests for intelligence gaps."""
        # Sort gaps by priority
        sorted_gaps = sorted(self.intelligence_gaps, key=lambda g: g.priority.value, reverse=True)

        for gap in sorted_gaps[:5]:  # Limit to top 5 gaps
            if gap.priority.value >= GoalPriority.HIGH.value:
                task_event = CoordinationEvent(
                    topic="strategic.task_request",
                    payload={
                        "task_type": gap.gap_type,
                        "priority": gap.priority.name,
                        "description": gap.description,
                        "goal_id": gap.goal_id,
                        "requester": self.agent_id,
                    },
                    source=self.agent_id,
                )

                await self.publish(task_event)
                logger.info(
                    f"📋 Published task request: {gap.gap_type} (Priority: {gap.priority.name})"
                )

    async def _goal_evaluation_loop(self):
        """Continuously evaluate and reprioritize goals."""
        while True:
            try:
                await asyncio.sleep(30)  # Evaluate every 30 seconds

                # Update goal statuses
                for goal in self.goals.values():
                    if goal.is_complete():
                        if goal.status != GoalStatus.COMPLETED:
                            goal.status = GoalStatus.COMPLETED
                            logger.info(f"✅ Goal completed: {goal.name}")

                            # Publish completion event
                            completion_event = CoordinationEvent(
                                topic="strategic.goal_completed",
                                payload={
                                    "goal_id": goal.id,
                                    "goal_name": goal.name,
                                    "completion_time": asyncio.get_event_loop().time(),
                                },
                                source=self.agent_id,
                            )
                            await self.publish(completion_event)

                    elif goal.status == GoalStatus.PENDING:
                        goal.status = GoalStatus.IN_PROGRESS

                # Log current strategy state
                active_goals = [
                    g for g in self.goals.values() if g.status == GoalStatus.IN_PROGRESS
                ]
                if active_goals:
                    logger.debug(f"📊 Active goals: {[g.name for g in active_goals]}")

            except Exception as e:
                logger.error(f"❌ Goal evaluation error: {e}")
                await asyncio.sleep(5)

    def get_goal_status(self) -> Dict:
        """Return current goal status for observability."""
        return {
            "total_goals": len(self.goals),
            "completed": sum(1 for g in self.goals.values() if g.status == GoalStatus.COMPLETED),
            "in_progress": sum(
                1 for g in self.goals.values() if g.status == GoalStatus.IN_PROGRESS
            ),
            "pending": sum(1 for g in self.goals.values() if g.status == GoalStatus.PENDING),
            "intelligence_gaps": len(self.intelligence_gaps),
            "goals": {
                k: {
                    "name": v.name,
                    "status": v.status.value,
                    "progress": f"{len(v.completed_findings)}/{len(v.required_findings)}",
                }
                for k, v in self.goals.items()
            },
        }


async def run_strategic_planner_demo():
    """Demo the strategic planner agent."""
    planner = StrategicPlannerAgent(agent_id="strategic_planner_01")

    await planner.start()

    # Simulate some findings
    await asyncio.sleep(5)

    print("\n=== Strategic Planner Status ===")
    print(json.dumps(planner.get_goal_status(), indent=2))

    await planner.stop()


if __name__ == "__main__":
    asyncio.run(run_strategic_planner_demo())
