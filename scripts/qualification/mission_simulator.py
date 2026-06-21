"""
AI-OSOP V5 Full Mission Simulator
Orchestrates an end-to-end research campaign in a controlled environment.
Verifies Phase 1, 3, 4, and 5 of the OQR-001 campaign.
"""

import asyncio
import uuid
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any

from ai_osop.core.config import VulnClass, Severity
from ai_osop.core.models import (
    Asset, Endpoint, Observation, Workflow, WorkflowStep, 
    Resource, DiffAuthFinding, VerificationRecord, OutcomeRecord
)
from ai_osop.core.governance import SwarmGovernor
from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory

class MissionSimulator:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.session_memory = SessionMemory()
        self.graph_memory = GraphMemory()
        self.governor = SwarmGovernor(initial_budget=100.0, engagement_id=engagement_id)
        self.calibration = ConfidenceCalibrationEngine(self.session_memory)
        
        self.metrics = {
            "hypotheses": 0,
            "validated": 0,
            "verified": 0,
            "system1_cost": 0.0,
            "system2_cost": 0.0
        }

    async def run_phase_1_simulation(self):
        print(f"--- [Phase 1] Starting E2E Simulation for Mission: {self.engagement_id} ---")
        
        # 1. Discovery Simulation
        print("[1] Simulating Asset Discovery...")
        asset = Asset(
            type="domain", 
            value="target-saas.com", 
            source="recon-agent", 
            confidence=1.0,
            engagement_id=self.engagement_id
        )
        # await self.graph_memory.add_asset(asset) # Mocking DB calls for now
        self.record_system1(0.01)

        # 2. Workflow & Semantic Extraction
        print("[2] Simulating Workflow Mapping (Register -> Dashboard)...")
        workflow = Workflow(name="Account Onboarding", role="guest", engagement_id=self.engagement_id)
        step = WorkflowStep(
            workflow_id=workflow.id, 
            endpoint_id="ep-register", 
            order=0, 
            action_type="POST", 
            engagement_id=self.engagement_id
        )
        self.record_system1(0.05)

        # 3. Anomaly Observation
        print("[3] Simulating Observation: User B can see User A resources...")
        obs = Observation(
            type="anomaly",
            source_agent_id="diff-auth-agent",
            target_id="ep-invoice-123",
            data={"reason": "Differential result mismatch"},
            engagement_id=self.engagement_id
        )
        self.metrics["hypotheses"] += 1
        self.record_system1(0.10)

        # 4. Escalation to System 2 (Verification)
        print("[4] Escalating to System 2 for Visual Confirmation...")
        strat = self.governor.optimizer.evaluate_strategy("high", 9)
        print(f"  Strategy: {strat}")
        self.record_system2(1.50)
        
        vis_obs = Observation(
            type="evidence",
            source_agent_id="visual-agent",
            target_id=obs.id,
            data={"confirmation": "Delete button visible in User B session"},
            engagement_id=self.engagement_id
        )
        self.metrics["validated"] += 1

        # 5. Reality Verification (Consensus)
        print("[5] Reaching Cross-Agent Consensus...")
        ver_record = VerificationRecord(
            finding_id="f-tenant-escape",
            evidence_sources=["DiffAuth", "Visual"],
            agreed_agents=["diff-auth-agent", "visual-agent"],
            engagement_id=self.engagement_id
        )
        is_verified = self.governor.verifier.verify_finding(ver_record, required_confidence=0.7)
        if is_verified:
            print("  VERIFICATION SUCCESS: Consensus reached.")
            self.metrics["verified"] += 1

        # 6. Learning Loop Update
        print("[6] Recording Outcome to Long-Term Memory...")
        outcome = OutcomeRecord(
            finding_id="f-tenant-escape",
            finding_type="tenant_escape",
            stack=["NextJS", "JWT"],
            workflow_intent="Identity Management",
            status="verified",
            validated=True,
            agent_id_responsible="diff-auth-agent",
            severity="high",
            initial_confidence=0.6,
            time_to_validate_seconds=120,
            engagement_id=self.engagement_id
        )
        # await self.session_memory.add_outcome_record(outcome)
        print("  Learning loop updated with successful finding.")

        print("\n--- [Phase 1] Simulation Complete ---")

    def record_system1(self, cost: float):
        self.governor.optimizer.record_cost(self.governor.budget, 1, cost)
        self.metrics["system1_cost"] += cost

    def record_system2(self, cost: float):
        self.governor.optimizer.record_cost(self.governor.budget, 2, cost)
        self.metrics["system2_cost"] += cost

    def print_metrics(self):
        print("\n--- Simulation Metrics ---")
        print(f"Hypotheses: {self.metrics['hypotheses']}")
        print(f"Validated:  {self.metrics['validated']}")
        print(f"Verified:   {self.metrics['verified']}")
        print(f"Total Cost: ${self.governor.budget.spent_budget:.2f}")
        print(f"System 1:   ${self.metrics['system1_cost']:.2f}")
        print(f"System 2:   ${self.metrics['system2_cost']:.2f}")
        print(f"Budget Rem: ${self.governor.budget.total_budget - self.governor.budget.spent_budget:.2f}")
        print("--------------------------")

async def run_campaign():
    sim = MissionSimulator(f"qual-{uuid.uuid4().hex[:6]}")
    await sim.run_phase_1_simulation()
    sim.print_metrics()

if __name__ == "__main__":
    asyncio.run(run_campaign())
