"""
V4.6 Confidence Calibration Engine
Adjusts Expected Value (EV) and Priority based on historical success rates.
"""

import asyncio
from typing import Any, Dict, List, Optional

from ai_osop.memory.session_memory import SessionMemory


class ConfidenceCalibrationEngine:
    """
    Applies empirical learning to adjust hypothesis confidence.
    """

    def __init__(self, session_memory: SessionMemory, skill_engine: Optional[Any] = None):
        self.session_memory = session_memory
        self.skill_engine = skill_engine

    async def calibrate_confidence(
        self,
        base_confidence: float,
        finding_type: str,
        workflow_intent: Optional[str] = None,
        used_skill_id: Optional[str] = None,
    ) -> float:
        """
        Adjust raw heuristic confidence using historical outcome data and skill effectiveness.
        """
        # 1. Fetch historical success rate from PostgreSQL (Semantic Memory)
        historical_rate = await self.session_memory.get_historical_success_rate(
            finding_type, workflow_intent
        )
        # 2. Apply the empirical + skill weighting to the fetched rate.
        return self.calibrate_from_rate(base_confidence, historical_rate, used_skill_id)

    def calibrate_from_rate(
        self,
        base_confidence: float,
        historical_rate: float,
        used_skill_id: Optional[str] = None,
    ) -> float:
        """Apply the empirical + skill weighting to an already-fetched success rate.

        Split out from ``calibrate_confidence`` so callers that already hold the
        historical rate (e.g. the hypothesis engine, which fetches it once and caches
        per category) can recalibrate without a second DB round-trip — and without a
        time-of-check/time-of-use gap between two independent reads of the same rate.
        """
        # Factor in skill effectiveness.
        skill_bonus = 0.0
        if used_skill_id and self.skill_engine:
            effectiveness = self.skill_engine.get_skill_effectiveness(used_skill_id)
            # If skill effectiveness > 50%, provide a significant boost
            if effectiveness > 0.5:
                skill_bonus = (effectiveness - 0.5) * 0.5  # Up to +0.25 bonus

        # Bayesian-style update (simplified for V5). 0.5 is the neutral "no signal"
        # sentinel, so leave base confidence untouched (plus any skill bonus).
        if historical_rate == 0.5:
            calibrated = base_confidence + skill_bonus
        else:
            weight_history = 0.6
            weight_base = 0.4
            calibrated = (
                (historical_rate * weight_history) + (base_confidence * weight_base) + skill_bonus
            )

        # Clamp between 0.1 and 0.99
        return max(0.1, min(0.99, calibrated))

    async def calculate_ev(
        self,
        impact_score: int,
        base_confidence: float,
        finding_type: str,
        workflow_intent: str,
        used_skill_id: Optional[str] = None,
        estimated_cost_seconds: int = 10,
    ) -> float:
        """
        Calculate Expected Value using calibrated confidence.
        EV = (Impact * Calibrated_Confidence * Stealth) / Cost
        """
        calibrated_confidence = await self.calibrate_confidence(
            base_confidence, finding_type, workflow_intent, used_skill_id
        )

        stealth_factor = 0.9  # Hardcoded for MVP

        # Avoid div by zero
        cost = max(1, estimated_cost_seconds)

        # Normalize Impact (1-10) to (0.1 - 1.0)
        norm_impact = impact_score / 10.0

        ev = (norm_impact * calibrated_confidence * stealth_factor) / cost
        return ev
