"""
Cognitive Swarm Agent Base Class.

Provides the foundation for autonomous agents that communicate via the Distributed Coordination Bus.
Implements the "Hive Mind" pattern where agents publish discoveries and react to others' findings.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ai_osop.orchestrator.distributed_bus import (
    DistributedCoordinationBus, 
    CoordinationEvent, 
    initialize_bus,
    get_coordination_bus
)

logger = logging.getLogger(__name__)

class CognitiveSwarmAgent(ABC):
    """
    Base class for all AI-OSOP swarm agents.
    
    Lifecycle:
    1. Initialize connection to Redis Streams
    2. Subscribe to relevant topics (e.g., "recon.*", "vuln.*")
    3. Publish own discoveries
    4. React to incoming events from other agents
    """
    
    def __init__(
        self, 
        agent_id: str, 
        agent_type: str,
        redis_url: str = "redis://localhost:6379",
        engagement_id: str = "default"
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.redis_url = redis_url
        self.engagement_id = engagement_id
        self.bus: Optional[DistributedCoordinationBus] = None
        self._running = False
        self._tasks: List[asyncio.Task] = []
        
        # Define what topics this agent cares about
        self.subscription_topics = self._define_subscriptions()
        
    @abstractmethod
    def _define_subscriptions(self) -> List[str]:
        """Return list of topic patterns this agent subscribes to (e.g. ['recon.endpoint_found'])."""
        pass

    @abstractmethod
    async def handle_event(self, event: CoordinationEvent):
        """Process an incoming event from the swarm."""
        pass

    @abstractmethod
    async def start_autonomous_tasks(self):
        """Start any background tasks specific to this agent (e.g. periodic scanning)."""
        pass

    async def connect(self):
        """Initialize the coordination bus."""
        self.bus = await initialize_bus(self.redis_url, self.engagement_id)
        logger.info(f"Agent {self.agent_id} connected to swarm bus")

    async def disconnect(self):
        """Shutdown the agent and close connections."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self.bus:
            await self.bus.disconnect()
        logger.info(f"Agent {self.agent_id} disconnected")

    async def publish(self, topic: str, payload: Dict[str, Any], event_type: str = "discovery", confidence: float = 0.5):
        """Publish a discovery or status update to the swarm."""
        if not self.bus:
            logger.error("Bus not initialized. Call connect() first.")
            return
            
        event = CoordinationEvent(
            topic=topic,
            payload=payload,
            source_agent=self.agent_id,
            event_type=event_type,
            confidence=confidence,
            engagement_id=self.engagement_id
        )
        await self.bus.publish(event)
        logger.debug(f"[{self.agent_id}] Published to {topic}: {payload.get('summary', 'No summary')}")

    async def run(self):
        """Main entry point for the agent lifecycle."""
        self._running = True
        await self.connect()
        
        # Start subscription listener
        consumer_group = f"{self.agent_type}_group"
        self._tasks.append(asyncio.create_task(
            self.bus.subscribe(
                topics=self.subscription_topics,
                consumer_id=self.agent_id,
                group_name=consumer_group,
                callback=self.handle_event
            )
        ))
        
        # Start autonomous background tasks
        self._tasks.append(asyncio.create_task(self.start_autonomous_tasks()))
        
        logger.info(f"Agent {self.agent_id} started. Listening on {self.subscription_topics}")
        
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            logger.info(f"Agent {self.agent_id} shutting down...")
        finally:
            await self.disconnect()

# Example Implementation: Vulnerability Correlation Agent
class VulnerabilityCorrelationAgent(CognitiveSwarmAgent):
    """
    Listens for new endpoint discoveries and automatically triggers vulnerability scans.
    Demonstrates the 'Hive Mind' effect: Recon finds something -> Vuln Agent reacts immediately.
    """
    
    def __init__(self, engagement_id: str = "default"):
        super().__init__(
            agent_id="vuln_correlator_01",
            agent_type="vulnerability",
            engagement_id=engagement_id
        )
        
    def _define_subscriptions(self) -> List[str]:
        return ["recon.endpoint_found", "recon.service_detected"]

    async def handle_event(self, event: CoordinationEvent):
        """React to new recon data by launching targeted scans."""
        logger.info(f"[{self.agent_id}] Received event: {event.topic}")
        
        if event.topic == "recon.endpoint_found":
            endpoint = event.payload.get("endpoint")
            method = event.payload.get("method")
            
            # Auto-trigger scan on new endpoints
            await self.publish(
                topic="vuln.scan_requested",
                payload={
                    "target": endpoint,
                    "method": method,
                    "reason": f"Triggered by recon discovery from {event.source_agent}",
                    "priority": "high" if "admin" in endpoint else "normal"
                },
                event_type="request",
                confidence=0.9
            )
            
        elif event.topic == "recon.service_detected":
            service = event.payload.get("service")
            version = event.payload.get("version")
            
            # Check for known CVEs based on service/version
            await self.publish(
                topic="intel.cve_lookup",
                payload={
                    "service": service,
                    "version": version,
                    "source_endpoint": event.payload.get("endpoint")
                },
                event_type="request",
                confidence=0.8
            )

    async def start_autonomous_tasks(self):
        """No periodic tasks needed for this agent; it's purely reactive."""
        # Keep alive but do nothing
        while self._running:
            await asyncio.sleep(60)

# Example Implementation: Attack Chain Builder
class AttackChainAgent(CognitiveSwarmAgent):
    """
    Listens for vulnerability findings and attempts to chain them into multi-step attacks.
    """
    
    def __init__(self, engagement_id: str = "default"):
        super().__init__(
            agent_id="attack_chain_builder_01",
            agent_type="attack_chain",
            engagement_id=engagement_id
        )
        self.knowledge_base = []  # In-memory store of findings
        
    def _define_subscriptions(self) -> List[str]:
        return ["vuln.confirmed", "intel.cve_result"]

    async def handle_event(self, event: CoordinationEvent):
        """Accumulate findings and look for chains."""
        self.knowledge_base.append(event.payload)
        logger.info(f"[{self.agent_id}] Knowledge base size: {len(self.knowledge_base)}")
        
        # Simple heuristic: if we have > 3 findings, try to chain
        if len(self.knowledge_base) >= 3:
            chain = self._attempt_chain()
            if chain:
                await self.publish(
                    topic="attack.chain_identified",
                    payload={
                        "chain": chain,
                        "severity": "critical",
                        "steps": len(chain)
                    },
                    event_type="discovery",
                    confidence=0.7
                )

    def _attempt_chain(self) -> Optional[List[Dict]]:
        """Dummy logic to simulate attack chain detection."""
        # Real implementation would use graph algorithms on Neo4j
        sqli_findings = [k for k in self.knowledge_base if k.get("type") == "sqli"]
        auth_bypass = [k for k in self.knowledge_base if k.get("type") == "auth_bypass"]
        
        if sqli_findings and auth_bypass:
            return [
                {"step": 1, "action": "Bypass Auth", "detail": auth_bypass[0]},
                {"step": 2, "action": "Inject SQL", "detail": sqli_findings[0]},
                {"step": 3, "action": "Exfiltrate Data", "detail": "DB dump"}
            ]
        return None

    async def start_autonomous_tasks(self):
        """Periodically re-analyze knowledge base for new chains."""
        while self._running:
            await asyncio.sleep(30)
            # Re-check for chains with updated knowledge
            if len(self.knowledge_base) >= 3:
                chain = self._attempt_chain()
                if chain:
                    await self.publish(
                        topic="attack.chain_identified",
                        payload={"chain": chain, "periodic_check": True},
                        event_type="discovery",
                        confidence=0.6
                    )

async def run_swarm_demo(engagement_id: str = "demo-eng"):
    """
    Demonstration of the Cognitive Swarm in action.
    Spawns multiple agents that communicate autonomously.
    """
    print(f"🚀 Starting AI-OSOP Cognitive Swarm Demo for engagement: {engagement_id}")
    
    vuln_agent = VulnerabilityCorrelationAgent(engagement_id)
    chain_agent = AttackChainAgent(engagement_id)
    
    # Simulate a Recon Agent publishing events manually for demo
    async def simulate_recon():
        bus = get_coordination_bus(engagement_id)
        await asyncio.sleep(2)  # Wait for agents to connect
        
        print("🔍 Simulating Recon Agent discoveries...")
        
        # Publish fake recon findings to trigger the swarm
        await bus.publish(CoordinationEvent(
            topic="recon.endpoint_found",
            payload={"endpoint": "/api/admin/users", "method": "GET", "status": 200},
            source_agent="simulated_recon_01",
            event_type="discovery",
            confidence=0.95,
            engagement_id=engagement_id
        ))
        
        await asyncio.sleep(1)
        
        await bus.publish(CoordinationEvent(
            topic="recon.service_detected",
            payload={"service": "nginx", "version": "1.18.0", "endpoint": "/"},
            source_agent="simulated_recon_01",
            event_type="discovery",
            confidence=0.9,
            engagement_id=engagement_id
        ))
        
        await asyncio.sleep(1)
        
        # Simulate a vulnerability finding
        await bus.publish(CoordinationEvent(
            topic="vuln.confirmed",
            payload={"type": "sqli", "location": "/api/login", "param": "username"},
            source_agent="simulated_scanner_01",
            event_type="discovery",
            confidence=0.85,
            engagement_id=engagement_id
        ))
        
        print("✅ Recon simulation complete. Watch agents react.")

    # Run everything concurrently
    try:
        await asyncio.gather(
            vuln_agent.run(),
            chain_agent.run(),
            simulate_recon()
        )
    except KeyboardInterrupt:
        print("\n🛑 Stopping swarm...")

if __name__ == "__main__":
    asyncio.run(run_swarm_demo())
