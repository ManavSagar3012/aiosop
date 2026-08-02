"""
V4.6 Confidence Calibration Engine
Adjusts Expected Value (EV) and Priority based on historical success rates.

Feedback loop (P2b, closed on REAL outcomes)
--------------------------------------------
1. RECORD: ``record_outcome(finding, outcome)`` durably persists a real
   submission verdict (accepted / rejected / duplicate / informative / ...)
   into the same Postgres ``finding_corpus`` the rest of the engine reads
   from. This is the ground truth the brain learns from — there is no
   simulated or fabricated signal.
2. LEARN: ``calibrate_with_evidence(...)`` turns the observed accept counts
   for a vuln-class/technique into an adjusted confidence using a
   Beta-Binomial (conjugate) posterior mean. A class with ZERO recorded
   outcomes is returned unchanged; a class with lots of consistent outcomes
   is pulled strongly toward its observed accept-rate. The prior's
   equivalent-sample-size (``prior_strength``) governs how much evidence is
   needed before the raw model confidence is meaningfully moved, so a single
   lucky accept cannot yank a class to certainty.
"""

from typing import Any, Dict, Optional

from ai_osop.memory.session_memory import SessionMemory

# Confidence is always reported in this closed interval (matches the legacy
# clamp so downstream EV maths never sees a 0 or a 1.0).
_CONF_FLOOR = 0.1
_CONF_CEIL = 0.99

# Equivalent sample size of the prior for Beta-Binomial shrinkage. Interpreted
# as "the raw model confidence is worth this many pseudo-observations": with the
# default 5.0, a class needs on the order of ~5+ real decided outcomes before
# the observed accept-rate dominates the model's own belief. Tuned to be
# conservative — a cold or thin class is nudged, never whipsawed.
DEFAULT_PRIOR_STRENGTH = 5.0

# HackerOne/Bugcrowd outcome vocabulary. Kept in lock-step with
# ``SessionMemory.get_historical_success_rate`` so a recorded outcome is scored
# the same way on the way in and on the way out.
POSITIVE_OUTCOMES = frozenset({"accepted", "paid", "triaged", "duplicate"})
NEGATIVE_OUTCOMES = frozenset({"rejected", "na", "informative"})
VALID_OUTCOMES = POSITIVE_OUTCOMES | NEGATIVE_OUTCOMES


class ConfidenceCalibrationEngine:
    """
    Applies empirical learning to adjust hypothesis confidence.
    """

    def __init__(self, session_memory: SessionMemory, skill_engine: Optional[Any] = None):
        self.session_memory = session_memory
        self.skill_engine = skill_engine

    # ------------------------------------------------------------------ #
    # RECORD side of the loop                                            #
    # ------------------------------------------------------------------ #
    async def record_outcome(
        self,
        finding_data: Dict[str, Any],
        outcome: str = "accepted",
    ) -> str:
        """Durably record a REAL submission outcome for a finding.

        This is the single public entry point external callers (e.g. the
        H1/Bugcrowd outcome-sync job) should use to feed ground truth into the
        calibration brain. It persists through the engine's existing store
        (``SessionMemory`` -> Postgres ``finding_corpus``); no new datastore is
        introduced. Upsert semantics mean a later verdict revision (an initial
        ``triaged`` that is later ``rejected``) corrects the ground truth rather
        than double-counting it.

        Args:
            finding_data: the finding payload. Must carry at least ``id`` (used
                as the upsert key) and ``category`` (the vuln-class the
                calibration lookup is keyed on).
            outcome: the real verdict, from the HackerOne/Bugcrowd vocabulary
                (see ``VALID_OUTCOMES``). Case-insensitive.

        Returns:
            The normalized (lower-cased) outcome that was persisted.

        Raises:
            ValueError: if ``outcome`` is not a recognized verdict — we refuse
                to record a signal the reader cannot classify, since it would
                silently vanish from every accept-rate aggregate.
        """
        normalized = (outcome or "").strip().lower()
        if normalized not in VALID_OUTCOMES:
            raise ValueError(
                f"Unknown submission outcome {outcome!r}; expected one of "
                f"{sorted(VALID_OUTCOMES)}"
            )
        await self.session_memory.upsert_corpus_finding(finding_data, outcome=normalized)
        return normalized

    # ------------------------------------------------------------------ #
    # LEARN side of the loop                                             #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _clamp(value: float) -> float:
        return max(_CONF_FLOOR, min(_CONF_CEIL, value))

    def calibrate_with_evidence(
        self,
        base_confidence: float,
        n_valid: int,
        n_total: int,
        *,
        prior_strength: float = DEFAULT_PRIOR_STRENGTH,
        prior_mean: Optional[float] = None,
    ) -> float:
        """Calibrate confidence from REAL outcome counts via Beta-Binomial shrinkage.

        Models the probability that a finding of this class is genuinely valid
        as ``p ~ Beta(a0, b0)`` with the raw model confidence as the prior mean,
        then updates it with the observed Bernoulli evidence (``n_valid`` valid
        out of ``n_total`` decided). The reported confidence is the posterior
        mean::

            prior_mean m  = base_confidence (unless overridden)
            a0 = k * m,  b0 = k * (1 - m)          # k = prior_strength
            calibrated = (n_valid + a0) / (n_total + a0 + b0)
                       = (n_valid + k*m) / (n_total + k)

        Properties (all relied on by the tests):
          * Deterministic — pure arithmetic, no clock/RNG/DB.
          * No data (``n_total == 0``) -> returns ``base_confidence`` unchanged.
            A cold class is never fabricated a boost.
          * Correct direction — an observed accept-rate above the prior raises
            confidence, below it lowers confidence.
          * Monotonic — more accepts (higher ``n_valid``) strictly raises the
            result; more rejects strictly lowers it.
          * Sample-size aware — the prior's equivalent sample size ``k`` means a
            thin class barely moves while a well-evidenced class converges to
            its true accept-rate.

        Args:
            base_confidence: raw model confidence in [0, 1]; also the prior mean.
            n_valid: count of positive (valid) real outcomes for the class.
            n_total: count of decided real outcomes (valid + invalid).
            prior_strength: equivalent sample size of the prior (k >= 0).
            prior_mean: override the prior centre; defaults to ``base_confidence``
                so that with no evidence the input is returned verbatim.

        Returns:
            Calibrated confidence, clamped to ``[_CONF_FLOOR, _CONF_CEIL]``.
        """
        if n_total < 0 or n_valid < 0 or n_valid > n_total:
            raise ValueError(f"invalid outcome counts: n_valid={n_valid}, n_total={n_total}")
        if prior_strength < 0:
            raise ValueError(f"prior_strength must be >= 0, got {prior_strength}")

        # No real evidence -> return the model's own belief untouched (only
        # clamped). This is what makes cold-start honest: no data, no movement.
        if n_total == 0:
            return self._clamp(base_confidence)

        m = base_confidence if prior_mean is None else prior_mean
        posterior_mean = (n_valid + prior_strength * m) / (n_total + prior_strength)
        return self._clamp(posterior_mean)

    async def calibrate_for_class(
        self,
        base_confidence: float,
        finding_type: str,
        workflow_intent: Optional[str] = None,
        *,
        prior_strength: float = DEFAULT_PRIOR_STRENGTH,
    ) -> float:
        """Fetch a class's real outcomes and calibrate — the count-aware live path.

        Prefers true outcome COUNTS (so Beta-Binomial shrinkage can weigh the
        evidence by sample size). If the store only exposes the collapsed
        success *rate* (the current ``SessionMemory`` API), it degrades to the
        legacy rate blend rather than fabricating a sample size.

        Wiring this in production is a one-liner at the scoring site; see the
        module docstring. The only enhancement needed for full count-aware
        calibration in the live path is a ``get_historical_outcome_counts``
        reader on ``SessionMemory`` returning ``(n_valid, n_total)``.
        """
        counts_fn = getattr(self.session_memory, "get_historical_outcome_counts", None)
        if counts_fn is not None:
            n_valid, n_total = await counts_fn(finding_type, workflow_intent)
            return self.calibrate_with_evidence(
                base_confidence, n_valid, n_total, prior_strength=prior_strength
            )
        # Fallback: only a rate is available — cannot shrink by sample size, so
        # reuse the established rate blend (which treats 0.5 as "no signal").
        rate = await self.session_memory.get_historical_success_rate(finding_type, workflow_intent)
        return self.calibrate_from_rate(base_confidence, rate)

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
