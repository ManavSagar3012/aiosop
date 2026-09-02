"""LLM model routing decisions for task categories.

Pure decision module: maps a TaskCategory + complexity hint to the best model
name from an in-process registry. No LLM SDK imports here -- actual completion
calls happen elsewhere (llm_client). Tracks per-model latency and consecutive
failures so routing degrades gracefully down a fallback chain.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Deque, Dict, List, Tuple


class TaskCategory(Enum):
    CLASSIFICATION = "classification"
    EXTRACTION = "extraction"
    REASONING = "reasoning"
    CODE_ANALYSIS = "code_analysis"
    VISUAL_ANALYSIS = "visual_analysis"
    REPORT_GENERATION = "report_generation"


@dataclass
class ModelCapability:
    name: str
    speed_tier: int  # 1=fastest .. 5=slowest
    quality_tier: int  # 1=lowest .. 5=highest
    context_window: int
    cost_per_1k_tokens: float


# Category -> (speed_weight, quality_weight, context_weight).
_WEIGHTS: Dict[TaskCategory, Tuple[float, float, float]] = {
    TaskCategory.CLASSIFICATION: (1.0, 0.15, 0.0),
    TaskCategory.EXTRACTION: (0.55, 0.55, 0.05),
    TaskCategory.REASONING: (0.10, 1.00, 0.05),
    TaskCategory.CODE_ANALYSIS: (0.25, 0.70, 0.40),
    TaskCategory.VISUAL_ANALYSIS: (0.15, 1.00, 0.0),
    TaskCategory.REPORT_GENERATION: (0.15, 0.90, 0.10),
}

_CODE_HINTS = ("qwen", "gpt-4o")  # families known to handle source well
_VISION_PREFIXES = ("gpt-4o",)  # only these entries accept image inputs


class ModelRouter:
    """Routes task categories to model names; tracks health for fallback."""

    FAILURE_THRESHOLD = 3

    def __init__(self) -> None:
        caps = [
            ModelCapability("ollama/phi3:latest", 1, 2, 4096, 0.0),
            ModelCapability("ollama/qwen3:8b", 3, 3, 32768, 0.0),
            ModelCapability("gpt-4o-mini", 2, 4, 128000, 0.00015),
            ModelCapability("gpt-4o", 4, 5, 128000, 0.005),
        ]
        self._registry: Dict[str, ModelCapability] = {m.name: m for m in caps}
        self._latency: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self._failures: Dict[str, int] = defaultdict(int)

    def _chain(self, category: TaskCategory, hint: str) -> List[ModelCapability]:
        pool = list(self._registry.values())
        if category is TaskCategory.VISUAL_ANALYSIS:
            pool = [m for m in pool if m.name.startswith(_VISION_PREFIXES)]
        w_speed, w_quality, w_context = _WEIGHTS[category]
        if hint == "fast":
            fast_pool = [m for m in pool if m.speed_tier <= 2]
            pool = fast_pool or pool
        elif hint == "deep":
            deep_pool = [m for m in pool if m.quality_tier >= 4]
            pool = deep_pool or pool

        def score(m: ModelCapability) -> float:
            s = w_speed * (6 - m.speed_tier) / 5.0
            q = w_quality * m.quality_tier / 5.0
            ctx = w_context * min(m.context_window / 128000.0, 1.0)
            code_bonus = (
                0.05
                if category is TaskCategory.CODE_ANALYSIS
                and any(h in m.name.lower() for h in _CODE_HINTS)
                else 0.0
            )
            return s + q + ctx + code_bonus - m.cost_per_1k_tokens * 0.01

        return sorted(pool, key=score, reverse=True)

    def route(self, task_category: TaskCategory, complexity_hint: str = "auto") -> str:
        """Return best model name; skip tripped models, last resort otherwise."""
        for cap in self._chain(task_category, complexity_hint):
            if self._failures[cap.name] < self.FAILURE_THRESHOLD:
                return cap.name
        return self._chain(task_category, complexity_hint)[0].name

    def record_failure(self, model: str) -> None:
        self._failures[model] += 1

    def record_success(self, model: str) -> None:
        self._failures[model] = 0

    def record_latency(self, model: str, seconds: float) -> None:
        self._latency[model].append(seconds)

    def get_health_report(self) -> Dict[str, Any]:
        models: Dict[str, Dict[str, Any]] = {}
        for name in self._registry:
            samples = self._latency.get(name, ())
            fails = self._failures[name]
            models[name] = {
                "avg_latency_s": round(sum(samples) / len(samples), 6) if samples else None,
                "max_latency_s": max(samples) if samples else None,
                "samples": len(samples),
                "consecutive_failures": fails,
                "healthy": fails < self.FAILURE_THRESHOLD,
            }
        return {"models": models, "healthy_count": sum(1 for m in models.values() if m["healthy"])}
