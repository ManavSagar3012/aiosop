"""
V5 Autonomous Security Research Runtime
Includes Swarm Governor, Reality Verifier, Uncertainty Engine, and Cost Optimizer.
"""

from typing import Any, Dict, List, Optional

from ai_osop.core.models import (
    BusinessInvariant,
    SwarmBudget,
    UncertaintyRecord,
    VerificationRecord,
)


class ResearchCostOptimizer:
    """Decides when to use System 1 (Cheap) vs System 2 (Expensive)."""

    def __init__(self):
        self.category_spend: Dict[str, float] = {
            "general": 0.0,
            "graphql": 0.0,
            "auth": 0.0,
            "workflow": 0.0,
            "cloud": 0.0,
            "recon": 0.0,
        }

    def evaluate_strategy(self, task_complexity: str, expected_impact: int) -> str:
        """
        Determines the analysis tier.
        Simple checks route to System 1. Complex reasoning routes to System 2.
        """
        if task_complexity == "low" or expected_impact < 5:
            return "system_1_regex_nuclei"
        elif task_complexity == "high" and expected_impact >= 8:
            return "system_2_llm_vision"
        return "system_1_first_then_escalate"

    def record_cost(
        self, budget: SwarmBudget, system: int, cost: float, category: str = "general"
    ) -> None:
        if system == 1:
            budget.system1_requests += 1
        elif system == 2:
            budget.system2_requests += 1
        budget.spent_budget += cost

        # Track category spend
        if category in self.category_spend:
            self.category_spend[category] += cost
        else:
            self.category_spend[category] = cost


class PayoutPredictionEngine:
    """V6: Optimizes for Bounty Value rather than just Vuln Count."""

    def __init__(self, session_memory: Any):
        self.session_memory = session_memory

    async def predict_yield(self, finding_type: str, severity: str, target_domain: str) -> float:
        """
        Calculates Expected Yield ($)
        Yield = Likelihood_of_Acceptance * Expected_Payout
        """
        # 1. Get historical acceptance rate for this type (from LearningEngine data)
        acceptance_rate = 0.85  # Default high for now

        # 2. Get expected payout from PortSwigger/HackerOne baselines
        payout_map = {"critical": 2500.0, "high": 1000.0, "medium": 400.0, "low": 100.0}
        base_payout = payout_map.get(severity.lower(), 50.0)

        # 3. Factor in duplicate probability (V6.3 Challenge)
        duplicate_prob = 0.1  # Real system would query session_memory.get_duplicate_rate()

        expected_yield = base_payout * acceptance_rate * (1.0 - duplicate_prob)
        return round(expected_yield, 2)


class BusinessLogicEngine:
    """V6: Manages Stateful Process Graphs and Invariant Violations."""

    def __init__(self):
        self.invariants: List[Any] = []
        self.state_machines: Dict[str, List[str]] = {}

    def extract_invariants(self, workflow_steps: List[Any]) -> List[BusinessInvariant]:
        """Convert observed workflow into machine-testable assumptions."""
        invariants = []

        # 1. Detect Sequential Dependencies (e.g. A must happen before B)
        # Combine action_type and endpoint for better semantic matching
        steps_text = " ".join(
            [f"{s.get('action_type', '')} {s.get('endpoint', '')}".lower() for s in workflow_steps]
        )

        if "pay" in steps_text and "ship" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Payment Required Before Shipping",
                    target_resource_type="Order",
                    required_state="PAID",
                    violation_strategy="jump_ahead",
                    engagement_id="",  # To be filled by agent
                )
            )

        if "delete" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Only Resource Owner Can Delete",
                    target_resource_type="GeneralResource",
                    actor_constraints=["OWNER"],
                    violation_strategy="cross_tenant",
                    engagement_id="",
                )
            )

        # 3. Identity & Authentication Invariants (Shopify ATO Campaign focus)
        if "mfa" in steps_text or "two_factor" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="MFA Change Requires Active Session + Re-auth",
                    target_resource_type="IdentitySettings",
                    required_state="RE_AUTHENTICATED",
                    violation_strategy="mfa_bypass",
                    engagement_id="",
                )
            )

        if "oauth" in steps_text or "auth_code" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="OAuth Auth Code is Single Use & Bound to Client",
                    target_resource_type="OAuthGrant",
                    violation_strategy="auth_code_reuse",
                    engagement_id="",
                )
            )

        if "recovery" in steps_text or "reset_password" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Account Recovery Requires Proof of Email Access",
                    target_resource_type="AccountRecovery",
                    violation_strategy="recovery_takeover",
                    engagement_id="",
                )
            )

        # 4. Secure Messaging & Protocol Invariants (Wickr focus)
        if "key_exchange" in steps_text or "handshake" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Key Exchange Requires Identity Verification",
                    target_resource_type="CryptographicSession",
                    violation_strategy="mitm_handshake",
                    engagement_id="",
                )
            )

        if "message" in steps_text and ("send" in steps_text or "receive" in steps_text):
            invariants.append(
                BusinessInvariant(
                    description="Message Access Restricted to Conversation Members",
                    target_resource_type="MessageContent",
                    actor_constraints=["MEMBER"],
                    violation_strategy="conversation_leak",
                    engagement_id="",
                )
            )

        if "device" in steps_text and "register" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Device Registration Requires Existing Trust Anchor",
                    target_resource_type="DeviceTrust",
                    violation_strategy="rogue_device_registration",
                    engagement_id="",
                )
            )

        # 5. E-Commerce & Concurrency Invariants (Newegg focus)
        if "coupon" in steps_text or "discount" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Coupon Can Only Be Applied Once Per Order",
                    target_resource_type="Cart",
                    violation_strategy="concurrent_execution",
                    engagement_id="",
                )
            )

        if "reward" in steps_text or "balance" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Reward Points Cannot Go Below Zero",
                    target_resource_type="Wallet",
                    violation_strategy="concurrent_execution",
                    engagement_id="",
                )
            )

        # 6. Multi-Role Marketplace Invariants (Airbnb focus)
        if "host" in steps_text or "guest" in steps_text or "booking" in steps_text:
            invariants.append(
                BusinessInvariant(
                    description="Strict Isolation Between Guest, Host, and Co-Host Actions",
                    target_resource_type="BookingWorkflow",
                    actor_constraints=["GUEST", "HOST", "CO_HOST"],
                    violation_strategy="multi_role_escalation",
                    engagement_id="",
                )
            )

        return invariants

    def generate_violation_tests(self, invariant: BusinessInvariant) -> List[Dict[str, Any]]:
        """Creates 'Impossible' tasks to attempt violating the business rule."""
        if invariant.violation_strategy == "jump_ahead":
            return [
                {
                    "strategy": "jump_ahead",
                    "action": "Trigger SHIPPED state via direct API call, omitting PAYMENT token",
                },
                {
                    "strategy": "race_condition",
                    "action": "Parallelize SHIP and PAY requests to find TOCTOU flaw",
                },
            ]
        elif invariant.violation_strategy == "cross_tenant":
            return [
                {
                    "strategy": "cross_tenant",
                    "action": "Attempt DELETE using User B's session on User A's resource ID",
                }
            ]
        elif invariant.violation_strategy == "mfa_bypass":
            return [
                {
                    "strategy": "mfa_bypass",
                    "action": "Attempt to disable MFA by omitting 'current_password' or 'mfa_token'",
                },
                {
                    "strategy": "parameter_pollution",
                    "action": "Inject duplicate MFA parameters to bypass validation",
                },
            ]
        elif invariant.violation_strategy == "auth_code_reuse":
            return [
                {
                    "strategy": "replay_attack",
                    "action": "Attempt to reuse a previously exchanged Auth Code",
                },
                {
                    "strategy": "client_confusion",
                    "action": "Exchange Auth Code using a different Client ID (Cross-client reuse)",
                },
            ]
        elif invariant.violation_strategy == "recovery_takeover":
            return [
                {
                    "strategy": "recovery_poisoning",
                    "action": "Attempt to change recovery email via Host Header Injection or Parameter Pollution",
                },
                {
                    "strategy": "token_leakage",
                    "action": "Check if recovery token is leaked in Referer headers or analytics calls",
                },
            ]
        elif invariant.violation_strategy == "mitm_handshake":
            return [
                {
                    "strategy": "key_replacement",
                    "action": "Attempt to inject attacker public key during handshake",
                },
                {
                    "strategy": "downgrade_attack",
                    "action": "Force protocol downgrade to weaker or unauthenticated version",
                },
            ]
        elif invariant.violation_strategy == "conversation_leak":
            return [
                {
                    "strategy": "member_bypass",
                    "action": "Attempt to fetch messages using ID of a conversation where user is NOT a member",
                },
                {
                    "strategy": "metadata_leakage",
                    "action": "Check if conversation metadata (members, timing) is visible to non-members",
                },
            ]
        elif invariant.violation_strategy == "rogue_device_registration":
            return [
                {
                    "strategy": "trust_bypass",
                    "action": "Register a new device for User A using a stolen session token but NO out-of-band verification",
                },
                {
                    "strategy": "session_fixation",
                    "action": "Check if device registration token is predictable or reusable",
                },
            ]
        elif invariant.violation_strategy == "concurrent_execution":
            return [
                {
                    "strategy": "single_packet_attack",
                    "action": "Execute 20 parallel requests in a single TCP packet to bypass usage limits/locks",
                },
                {
                    "strategy": "race_condition",
                    "action": "Attempt to redeem/apply the resource simultaneously from two different sessions",
                },
            ]
        elif invariant.violation_strategy == "multi_role_escalation":
            return [
                {
                    "strategy": "role_confusion",
                    "action": "Perform action as Guest, but include Host-only parameters (Mass Assignment)",
                },
                {
                    "strategy": "cross_role_idor",
                    "action": "Attempt to approve a booking using a Co-Host session from a different property",
                },
            ]
        return [
            {
                "strategy": "generic_logic_test",
                "action": "Attempt to bypass " + invariant.description,
            }
        ]


class RealityVerifier:
    """Ensures high-severity findings have multiple, independent evidence sources across 5 critical validation stages."""

    def __init__(self, skill_engine: Optional[Any] = None):
        self.skill_engine = skill_engine

    STAGE_WEIGHTS = {
        "Reproduction": 0.2,
        "Exploitation": 0.3,
        "Confidentiality Impact": 0.2,
        "Integrity Impact": 0.2,
        "Authorization Bypass": 0.1,
    }

    def verify_finding(self, record: VerificationRecord, required_confidence: float = 0.7) -> bool:
        """
        Calculates overall verification confidence and Evidence Chain Score.
        Strictly enforces Evidence Provenance: MOCK or SIMULATED evidence cannot be verified.
        """
        from ai_osop.core.models import EvidenceProvenance

        # 0. Provenance Gate (Phase 3 Requirement)
        if record.provenance in [EvidenceProvenance.MOCK, EvidenceProvenance.SIMULATED]:
            record.is_verified = False
            record.overall_confidence = 0.0
            record.evidence_chain_score = 0.0
            return False

        confidence = 0.0
        passed_stages = [s.name for s in record.stages if s.status == "passed"]

        for stage, weight in self.STAGE_WEIGHTS.items():
            if stage in passed_stages:
                confidence += weight

        # Factor in agent consensus as a secondary signal
        unique_agents = len(set(record.agreed_agents))
        if unique_agents >= 2:
            confidence += 0.1

        record.overall_confidence = min(1.0, confidence)

        # V6.1: Calculate Evidence Chain Score (0-100)
        # 50% from stages, 30% from agents, 20% from provenance quality
        stage_score = (len(passed_stages) / 5.0) * 50
        unique_agents = len(set(record.agreed_agents))
        agent_score = min(30.0, unique_agents * 10.0)
        prov_score = 20.0 if record.provenance == EvidenceProvenance.LIVE else 10.0

        record.evidence_chain_score = stage_score + agent_score + prov_score

        # V6.2: Calculate Replayability Score (0-100)
        replay_score = 0.0
        if record.replayable:
            replay_score += 40.0  # Base flag
        if record.provenance == EvidenceProvenance.LIVE:
            replay_score += 20.0  # Authentic telemetry
        if "Reproduction" in passed_stages:
            replay_score += 40.0  # Empirically verified reproduction

        record.replayability_score = replay_score

        # V6.3: Calculate Acceptance Probability (0-100)
        # Shift focus from 'Discovery' to 'Payout'
        # Acceptance depends heavily on Chain Strength + Replayability
        acceptance_prob = (record.evidence_chain_score * 0.6) + (record.replayability_score * 0.4)
        record.overall_confidence = min(1.0, acceptance_prob / 100.0)

        if record.overall_confidence >= required_confidence:
            record.is_verified = True

            # V6: Record Verification Success into SkillEngine if skill was used
            if self.skill_engine:
                # Find the skill ID from finding metadata if possible (simplified here)
                for agent_id in record.agreed_agents:
                    self.skill_engine.record_execution(
                        "unknown_skill",
                        agent_id,
                        "Finding verified",
                        stage="verification",
                        finding_id=record.finding_id,
                    )

            return True

        # Legacy fallback for basic consensus if stages are empty
        if not record.stages:
            unique_sources = set(record.evidence_sources)
            if len(unique_sources) >= 2 and unique_agents >= 2:
                record.is_verified = True
                record.overall_confidence = 0.8
                return True

        return False


class UncertaintyEngine:
    """Tracks what the system doesn't know to prioritize unblocking tasks."""

    def __init__(self):
        self.records: Dict[str, UncertaintyRecord] = {}

    def log_uncertainty(
        self, target_id: str, knowns: List[str], unknowns: List[str], engagement_id: str
    ) -> UncertaintyRecord:
        record = UncertaintyRecord(
            target_id=target_id, knowns=knowns, unknowns=unknowns, engagement_id=engagement_id
        )
        self.records[record.id] = record
        return record


class SwarmGovernor:
    """Manages the overall swarm budget, priorities, and conflict resolution."""

    def __init__(self, initial_budget: float, engagement_id: str):
        self.budget = SwarmBudget(total_budget=initial_budget, engagement_id=engagement_id)
        self.optimizer = ResearchCostOptimizer()
        self.verifier = RealityVerifier()
        self.uncertainty = UncertaintyEngine()

    def can_execute(self, estimated_cost: float) -> bool:
        return (self.budget.spent_budget + estimated_cost) <= self.budget.total_budget
