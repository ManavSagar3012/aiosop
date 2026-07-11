"""
AI-OSOP V6.5 E-Commerce & Concurrency Mission Simulator
Verifies Race Condition detection and Multi-Role Marketplace logic.
"""

import asyncio
import uuid
from typing import Any, Dict, List

from ai_osop.core.governance import BusinessLogicEngine, SwarmGovernor
from ai_osop.core.models import (
    BusinessInvariant,
    EvidenceProvenance,
    Observation,
    OutcomeRecord,
    VerificationRecord,
    VerificationStage,
    Workflow,
    WorkflowStep,
)


class ConcurrencySimulator:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.governor = SwarmGovernor(initial_budget=100.0, engagement_id=engagement_id)
        self.logic_engine = BusinessLogicEngine()

        self.metrics = {
            "ecommerce_invariants": 0,
            "violation_tasks": 0,
            "successful_bypasses": 0,
            "cost": 0.0,
        }

    async def run_simulation(self):
        print(
            f"--- [Logic Specialist] Starting E-Commerce Simulation for: {self.engagement_id} ---"
        )

        # 1. Map E-Commerce Workflow
        print("[1] Mapping Checkout & Marketplace Workflow...")
        workflow_steps = [
            {"action_type": "POST", "endpoint": "/cart/add", "payload": "item_id=123"},
            {"action_type": "POST", "endpoint": "/cart/coupon/apply", "payload": "code=DISCOUNT50"},
            {"action_type": "POST", "endpoint": "/checkout/pay", "payload": "method=card"},
            {
                "action_type": "POST",
                "endpoint": "/booking/approve",
                "description": "Host approves booking",
            },
        ]
        self.record_cost(0.20)

        # 2. Extract Invariants
        print("[2] Extracting Concurrency & Marketplace Invariants...")
        invariants = self.logic_engine.extract_invariants(workflow_steps)
        for inv in invariants:
            inv.engagement_id = self.engagement_id
            print(f"  Found Invariant: {inv.description} (Strategy: {inv.violation_strategy})")
            self.metrics["ecommerce_invariants"] += 1

        # 3. Generate Violation Tasks
        print("[3] Generating Targeted Concurrency & Role Fuzzing Tasks...")
        for inv in invariants:
            tests = self.logic_engine.generate_violation_tests(inv)
            for test in tests:
                print(f"  Task: {test['strategy']} -> {test['action']}")
                self.metrics["violation_tasks"] += 1
        self.record_cost(0.40)

        # 4. Simulate Successful Race Condition
        print("[4] Simulating Race Condition Execution (Single Packet Attack)...")
        race_inv = next(
            (i for i in invariants if i.violation_strategy == "concurrent_execution"), None
        )
        if not race_inv:
            print("  ERROR: Concurrency Invariant not detected!")
            return

        # Simulate finding
        finding_id = f"f-race-{uuid.uuid4().hex[:6]}"
        obs = Observation(
            type="evidence",
            source_agent_id="stateful-logic-agent",
            target_id="/cart/coupon/apply",
            data={
                "vuln": "Race condition allows applying the same $50 coupon 10 times via parallel HTTP/2 single-packet attack"
            },
            engagement_id=self.engagement_id,
        )
        print(f"  FINDING: {obs.data['vuln']}")
        self.record_cost(2.50)  # System 2 cost

        # 5. Reality Verification
        print("[5] Verifying Financial Impact via RealityVerifier...")
        ver_record = VerificationRecord(
            finding_id=finding_id,
            evidence_sources=["ConcurrentRequestEngine", "SessionAnalysis"],
            agreed_agents=["stateful-logic-agent", "api-hunter"],
            engagement_id=self.engagement_id,
            provenance=EvidenceProvenance.LIVE,
            replayable=True,
        )

        # Manually passed for simulation
        ver_record.stages = [
            VerificationStage(name="Reproduction", status="passed"),
            VerificationStage(name="Integrity Impact", status="passed"),
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
        print("\n--- E-Commerce Simulation Metrics ---")
        print(f"Invariants Discovered:        {self.metrics['ecommerce_invariants']}")
        print(f"Violation Tasks Generated:    {self.metrics['violation_tasks']}")
        print(f"Verified Bypasses Found:      {self.metrics['successful_bypasses']}")
        print(f"Total Simulation Cost:        ${self.metrics['cost']:.2f}")
        print("-------------------------------------")


async def main():
    sim = ConcurrencySimulator(f"ecomm-qual-{uuid.uuid4().hex[:6]}")
    await sim.run_simulation()
    sim.print_metrics()


if __name__ == "__main__":
    asyncio.run(main())
