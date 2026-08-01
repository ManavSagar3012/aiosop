"""Anchored reasoning loop for autonomous agents.

Actions are chosen by reference to the actual observations from the *last*
successful iteration, not by a fresh start. Prevents drift/rational leaps.

Contract: given persistent state (goal + observations list + optional prior
step references), reason_step returns a new ReasoningOutput that is *anchored*
(contains the original content, "anchors": [prior_step_id, ...]) so eval can
quantify tie continuity across steps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence


@dataclass
class ReasoningOutput:
    think: str
    action: Dict[str, Any]
    anchors: List[str] = field(default_factory=list)
    step_id: str = ""


class AnchoredReasoner:
    def __init__(
        self,
        llm: Any,
        anchor_tool: Optional[Callable[[List[Dict[str, Any]]], Any]] = None,
        max_window: int = 8,
    ) -> None:
        self.llm = llm
        self.anchor_tool = anchor_tool
        self.max_window = max_window

    async def reason_step(
        self, state: Dict[str, Any], step_id: Optional[str] = None
    ) -> ReasoningOutput:
        observations = list(state.get("observations") or [])
        if len(observations) > self.max_window:
            observations = observations[-self.max_window :]
        state["observations"] = observations
        # Tool result to route to reasoner: retain only what matters
        prompt = self._serialize(state, step_id)
        raw = await self.llm.complete(prompt)
        out = self._parse(raw)
        out.step_id = step_id or ""
        out.anchors = list(observations)
        if self.anchor_tool is not None and out.anchors:
            await self.anchor_tool(observations[-1:])
        return out

    def _serialize(self, state: Dict[str, Any], step_id: Optional[str]) -> List[Dict[str, Any]]:
        user_msg = {
            "role": "user",
            "content": json.dumps(
                {
                    "goal": state.get("goal", ""),
                    "step_id": step_id,
                    "observations": state.get("observations"),
                    "allowed_actions_hint": ["choose one action", "stop"],
                }
            ),
        }
        sys_msg = {
            "role": "system",
            "content": "You must anchor on the listed observations. Use only as context. Return JSON with reasoning and single action.",
        }
        return [sys_msg, user_msg]

    def _parse(self, raw: Any) -> ReasoningOutput:
        if isinstance(raw, ReasoningOutput):
            return raw
        if isinstance(raw, str):
            try:
                obj = json.loads(raw.replace("\n", " "))
                return ReasoningOutput(
                    think=str(obj.get("think", "") or obj.get("think", "")),
                    action=dict(obj.get("action", {})),
                )
            except json.JSONDecodeError:
                pass
        raise RuntimeError(f"LLM returned malformed reasoning: {raw!r}")
