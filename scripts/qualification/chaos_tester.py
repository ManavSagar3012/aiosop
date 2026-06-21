"""
AI-OSOP V5 Swarm Chaos Tester
Intentionally triggers failure modes to verify recovery and resilience.
Verifies Phase 2 of the OQR-001 campaign.
"""

import asyncio
from ai_osop.core.governance import SwarmGovernor
from ai_osop.core.models import VerificationRecord
from ai_osop.core.exceptions import GraphQueryError

async def test_chaos():
    print("--- [Phase 2] Starting Swarm Chaos Testing ---")
    
    engagement_id = "chaos-test-001"
    governor = SwarmGovernor(initial_budget=5.0, engagement_id=engagement_id)
    
    # 1. Budget Exhaustion
    print("\n[1] Testing Budget Exhaustion...")
    expensive_task_cost = 10.0
    can_run = governor.can_execute(expensive_task_cost)
    if not can_run:
        print("  SUCCESS: Governor blocked execution due to insufficient budget.")
    else:
        print("  FAIL: Governor allowed over-spending.")

    # 2. Evidence Corruption (Missing data in verification)
    print("\n[2] Testing Verification with Corrupted Evidence...")
    ver_record = VerificationRecord(
        finding_id="f-broken",
        evidence_sources=[], # Missing evidence
        agreed_agents=["agent-1"], # Only 1 agent
        engagement_id=engagement_id
    )
    is_verified = governor.verifier.verify_finding(ver_record, required_sources=2)
    if not is_verified:
        print("  SUCCESS: Verifier rejected finding with insufficient evidence sources.")
    else:
        print("  FAIL: Verifier approved uncorroborated finding.")

    # 3. Model Integrity (Malformed payload logic)
    print("\n[3] Testing Malformed Decision Escalation...")
    # Simulate an invalid complexity string
    try:
        strat = governor.optimizer.evaluate_strategy("ultra-high-non-existent", 10)
        print(f"  Result: {strat} (Fallback triggered)")
    except Exception as e:
        print(f"  CRITICAL FAIL: Optimizer crashed on malformed input: {e}")

    print("\n--- [Phase 2] Chaos Testing Complete ---")

if __name__ == "__main__":
    asyncio.run(test_chaos())
