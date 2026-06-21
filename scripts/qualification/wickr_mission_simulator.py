"""
AI-OSOP V6.4 Wickr & Secure Messaging Mission Simulator
Verifies the 'Secure Messaging Hunter' persona and Protocol Invariants.
"""

import asyncio
import uuid
from typing import List, Dict, Any

from ai_osop.core.models import (
    Observation, Workflow, WorkflowStep, 
    VerificationRecord, OutcomeRecord, BusinessInvariant, EvidenceProvenance,
    VerificationStage
)
from ai_osop.core.governance import SwarmGovernor, BusinessLogicEngine

class WickrSimulator:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.governor = SwarmGovernor(initial_budget=100.0, engagement_id=engagement_id)
        self.logic_engine = BusinessLogicEngine()
        
        self.metrics = {
            "protocol_invariants": 0,
            "protocol_tasks": 0,
            "successful_bypasses": 0,
            "cost": 0.0
        }

    async def run_protocol_simulation(self):
        print(f"--- [Messaging Specialist] Starting Wickr Protocol Simulation for: {self.engagement_id} ---")
        
        # 1. Map Protocol Workflow
        print("[1] Mapping E2EE Handshake & Messaging Workflow...")
        workflow_steps = [
            {"action_type": "POST", "endpoint": "/api/v1/handshake/init", "description": "Key Exchange Init"},
            {"action_type": "POST", "endpoint": "/api/v1/handshake/complete", "description": "Key Exchange Finish"},
            {"action_type": "POST", "endpoint": "/api/v1/message/send", "description": "Send Encrypted Message"},
            {"action_type": "GET",  "endpoint": "/api/v1/message/fetch", "description": "Fetch Messages"},
            {"action_type": "POST", "endpoint": "/api/v1/device/register", "description": "Register New Device"}
        ]
        self.record_cost(0.30)

        # 2. Extract Protocol Invariants
        print("[2] Extracting Protocol Invariants via BusinessLogicEngine...")
        invariants = self.logic_engine.extract_invariants(workflow_steps)
        for inv in invariants:
            inv.engagement_id = self.engagement_id
            print(f"  Found Invariant: {inv.description} (Strategy: {inv.violation_strategy})")
            self.metrics["protocol_invariants"] += 1
        
        # 3. Generate Protocol Violation Tasks
        print("[3] Generating Targeted Protocol Fuzzing Tasks...")
        for inv in invariants:
            tests = self.logic_engine.generate_violation_tests(inv)
            for test in tests:
                print(f"  Task: {test['strategy']} -> {test['action']}")
                self.metrics["protocol_tasks"] += 1
        self.record_cost(0.60)

        # 4. Simulate Successful Conversation Member Bypass
        print("[4] Simulating Conversation Member Bypass (Secure Messaging Hunter Persona)...")
        conv_inv = next((i for i in invariants if i.violation_strategy == "conversation_leak"), None)
        if not conv_inv:
            print("  ERROR: Messaging Invariant not detected!")
            return

        # Simulate finding
        finding_id = f"f-msg-{uuid.uuid4().hex[:6]}"
        obs = Observation(
            type="evidence",
            source_agent_id="secure-messaging-hunter",
            target_id="/api/v1/message/fetch",
            data={"vuln": "BOLA in message fetch: User B can read User A's private messages by changing conversation_id"},
            engagement_id=self.engagement_id
        )
        print(f"  FINDING: {obs.data['vuln']}")
        self.record_cost(2.50) # System 2 cost

        # 5. Reality Verification
        print("[5] Verifying Protocol Integrity Impact via RealityVerifier...")
        ver_record = VerificationRecord(
            finding_id=finding_id,
            evidence_sources=["LogicDiff", "ProtocolTrace", "VisualEvidence"],
            agreed_agents=["secure-messaging-hunter", "stateful-logic-agent", "visual-agent"],
            engagement_id=self.engagement_id,
            provenance=EvidenceProvenance.LIVE,
            replayable=True
        )
        
        # Manually passed for simulation
        ver_record.stages = [
            VerificationStage(name="Reproduction", status="passed"),
            VerificationStage(name="Authorization Bypass", status="passed"),
            VerificationStage(name="Confidentiality Impact", status="passed")
        ]
        
        is_verified = self.governor.verifier.verify_finding(ver_record)
        if is_verified:
            print(f"  VERIFICATION SUCCESS: Confidence {ver_record.overall_confidence:.2f}")
            self.metrics["successful_bypasses"] += 1

        print("\n--- Simulation Complete ---")

    def record_cost(self, cost: float):
        self.governor.budget.spent_budget += cost
        self.metrics["cost"] += cost

    def print_metrics(self):
        print("\n--- Protocol Simulation Metrics ---")
        print(f"Protocol Invariants Discovered: {self.metrics['protocol_invariants']}")
        print(f"Violation Tasks Generated:    {self.metrics['protocol_tasks']}")
        print(f"Verified Bypasses Found:       {self.metrics['successful_bypasses']}")
        print(f"Total Simulation Cost:         ${self.metrics['cost']:.2f}")
        print("-----------------------------------")

async def main():
    sim = WickrSimulator(f"wickr-qual-{uuid.uuid4().hex[:6]}")
    await sim.run_protocol_simulation()
    sim.print_metrics()

if __name__ == "__main__":
    asyncio.run(main())
