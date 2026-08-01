"""Core decision loop that turns LLM advisory text into agentic behaviour.

The existing ``BaseAgent.think`` generates a natural-language recommendation that is
never used to *do* anything. ``ActionLoop`` closes that gap. It repeatedly asks the
LLM to pick one structured action from an allow-list, executes it through an
injected tool facade, and feeds the observation back into the prompt so the next
decision is grounded in reality.

Scope assumptions:
- The injected ``tools`` facade enforces target scope and safety; the loop itself
  only enforces the action allow-list and JSON contract so it stays transport-
  agnostic and testable.
- LLM responses must be JSON with ``{"action": str, "reasoning": str, ...}``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from ai_osop.core import metrics_a2


@dataclass
class Action:
    name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class ActionResult:
    action: Action
    observation: Dict[str, Any]
    error: Optional[Dict[str, Any]] = None


@dataclass
class LoopState:
    target: str
    goal: str
    allowed_tools: Set[str]
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LoopResult:
    steps_taken: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    completed: bool = False
    aborted: bool = False
    error: Optional[str] = None
    depends_on_history: bool = True  # whether prompt included all observations


class _ParseError(ValueError):
    """Failed to extract a JSON action object from the LLM text."""


class _DisallowedAction(ValueError):
    """JSON was valid but the chosen action is not in the allow-list."""


class _MissingAction(ValueError):
    """JSON lacked an 'action' key."""


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = (text or "").strip()
    if not cleaned:
        raise _ParseError("LLM returned empty response")
    block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if block_match:
        cleaned = block_match.group(1)
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end <= start:
            raise _ParseError("LLM output is not valid JSON")
        try:
            obj = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            raise _ParseError("LLM output is not valid JSON")
    if not isinstance(obj, dict):
        raise _ParseError("LLM JSON must be an object")
    return obj


def parse_action(text: str, allowed_tools: Set[str]) -> Action:
    obj = _extract_json_object(text)
    action_name = str(obj.get("action") or obj.get("tool") or "").strip()
    if not action_name:
        raise _MissingAction("JSON is missing the 'action' key")
    if action_name not in allowed_tools:
        raise _DisallowedAction(f"Action '{action_name}' is not allowed")
    reasoning = str(obj.get("reasoning") or obj.get("thought") or "")
    parameters = {
        k: v for k, v in obj.items() if k not in {"action", "tool", "reasoning", "thought"}
    }
    return Action(name=action_name, parameters=parameters, reasoning=reasoning)


class ActionLoop:
    """Prompt -> parse -> execute -> observe loop with safety limits."""

    def __init__(self, llm: Any, tools: Any, trace_recorder: Any = None):
        self.llm = llm
        self.tools = tools
        # Step D trace-capture hook: caller passes a TraceRecorder to enable
        # JSONL emission per engagement; defaults to None so no I/O happens
        # on test/dev paths unless explicitly enabled.
        self.trace_recorder = trace_recorder

    async def _complete(self, messages: List[Dict[str, Any]]) -> str:
        resp = await self.llm.complete(messages)
        if isinstance(resp, str):
            return resp
        # litellm-style object with .choices
        try:
            choices = getattr(resp, "choices", None) or []
            if choices:
                content = getattr(choices[0], "message", None)
                if content is not None:
                    content = getattr(content, "content", None)
                    if isinstance(content, str):
                        return content
        except (AttributeError, IndexError, KeyError):
            pass
        if isinstance(resp, dict):
            choices = resp.get("choices") or []
            if choices:
                msg = choices[0].get("message") or {}
                content = msg.get("content")
                if isinstance(content, str):
                    return content
        return ""

    def _build_prompt(
        self, state: LoopState, history: Sequence[ActionResult]
    ) -> List[Dict[str, Any]]:
        tool_hints = []
        for name in sorted(state.allowed_tools):
            tool = getattr(self.tools, name, None)
            doc_lines = []
            if tool is not None:
                doc = getattr(tool, "__doc__", None) or ""
                doc_lines = [line.strip() for line in doc.strip().splitlines() if line.strip()]
            tool_hints.append(f"- {name}: {doc_lines[0] if doc_lines else ''}")
        tools_block = "\n".join(tool_hints)
        system = (
            "You are the decision-making core of an autonomous security assessment agent. "
            "Each turn you must output a JSON object with keys:\n"
            "  action (string, one of the allowed tools)\n"
            "  reasoning (string, why this step)\n"
            "  plus any parameters the tool expects.\n"
            "Only use tools from this allow-list:\n" + tools_block + "\n\n"
            f"Target scope: {state.target}\nGoal: {state.goal}\n"
            "Do not guess targets outside scope. Cite prior observations when possible."
        )
        messages = [{"role": "system", "content": system}]
        for step in history:
            messages.append(
                {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "action": step.action.name,
                            "reasoning": step.action.reasoning,
                            **step.action.parameters,
                        }
                    ),
                }
            )
            obs = step.observation if step.error is None else {"error": step.error}
            # Explicit replan hint: a failed step carries a one-line self-critique so
            # the next LLM decision sees both the failing action and the concrete
            # observation and can change strategy rather than repeat the same call.
            hint = ""
            if step.error is not None or step.observation.get("found") is False:
                hint = " (prior step was unproductive; plan a different tool/param now)"
            messages.append(
                {
                    "role": "user",
                    "content": "Observation: " + json.dumps(obs) + hint,
                }
            )
        messages.append({"role": "user", "content": "Pick the next action now."})
        return messages

    async def run(self, state: LoopState, max_steps: int = 10) -> LoopResult:
        history: List[ActionResult] = []
        findings: List[Dict[str, Any]] = []
        error_msg: Optional[str] = None
        completed = False
        tokens_start = getattr(self.llm, "tokens_consumed", None)

        for _ in range(max_steps):
            messages = self._build_prompt(state, history)
            raw = await self._complete(messages)
            try:
                action = parse_action(raw, state.allowed_tools)
            except _DisallowedAction as exc:
                observation = {
                    "error": str(exc),
                    "raw": raw,
                    "status": "rejected_by_policy",
                }
                history.append(
                    ActionResult(
                        Action(name="__disallowed__", reasoning=raw),
                        observation,
                        error={"type": "policy", "message": str(exc)},
                    )
                )
                continue
            except _ParseError as exc:
                observation = {
                    "error": f"invalid LLM action: {exc}",
                    "raw": raw,
                    "status": "rejected",
                }
                history.append(
                    ActionResult(
                        Action(name="__invalid__", reasoning=raw),
                        observation,
                        error={"type": "parse", "message": str(exc)},
                    )
                )
                continue

            tool_fn = getattr(self.tools, action.name, None)
            if tool_fn is None:
                observation = {"error": f"tool '{action.name}' not available", "status": "rejected"}
                history.append(
                    ActionResult(
                        action,
                        observation,
                        error={"type": "missing_tool", "message": observation["error"]},
                    )
                )
                continue

            try:
                observation = await tool_fn(**action.parameters)
                if not isinstance(observation, dict):
                    observation = {"result": observation}
            except TypeError as exc:
                observation = {
                    "error": f"invalid parameters for {action.name}: {exc}",
                    "status": "rejected",
                }
                history.append(
                    ActionResult(
                        action, observation, error={"type": "parameters", "message": str(exc)}
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                observation = {"error": f"{action.name} failed: {exc}", "status": "failed"}
                history.append(
                    ActionResult(
                        action, observation, error={"type": "execution", "message": str(exc)}
                    )
                )
            else:
                history.append(ActionResult(action, observation))
                if observation.get("found"):
                    findings.append(observation.copy())

            if action.name == "done":
                completed = True
                break

        if error_msg is None and history:
            for step in reversed(history):
                if step.error and step.error.get("type") == "parse":
                    error_msg = step.error.get("message")
                    break

        # Per-finding token receipts: attribute cumulative LLM tokens consumed
        # during this loop to its vuln_class so dashboards can cost findings.
        tokens_end = getattr(self.llm, "tokens_consumed", None)
        if isinstance(tokens_start, int) and isinstance(tokens_end, int):
            delta = tokens_end - tokens_start
            if delta > 0:
                try:
                    vuln_class = str(state.context.get("vuln_class", "unknown"))
                    model = getattr(self.llm, "primary_model", None) or "unknown"
                    metrics_a2.finding_llm_tokens(delta, model=str(model), vuln_class=vuln_class)
                except Exception:  # noqa: BLE001 - metrics must never break the loop
                    pass

        # Step D trace-capture (opt-in): one ActionTrace per executed step so
        # weeks of real runs produce the labeled dataset a future fine-tune learns
        # from. No-ops unless a TraceRecorder is attached.
        if self.trace_recorder is not None:
            try:
                import uuid as _uuid
                from datetime import datetime as _dt

                from ai_osop.core.trace_capture import ActionTrace

                target = str(getattr(state, "target", "") or "")
                goal = str(getattr(state, "goal", "") or "")
                vuln_class = str(state.context.get("vuln_class", "unknown"))
                engagement_id = str(state.context.get("engagement_id", "unknown"))
                caller_model = getattr(self.llm, "primary_model", None) or "unknown"
                for idx, r in enumerate(history):
                    obs = r.observation if isinstance(r.observation, dict) else {}
                    obs_status = (
                        "rejected"
                        if r.error and r.error.get("type") in {"policy", "parse"}
                        else ("failed" if r.error else "ok")
                    )
                    summary_src = json.dumps(obs, sort_keys=True, default=str)[:500]
                    self.trace_recorder.record(
                        ActionTrace(
                            trace_id=f"{_uuid.uuid4().hex[:8]}",
                            engagement_id=engagement_id,
                            goal=goal,
                            vuln_class=vuln_class,
                            step_idx=idx,
                            thought=str(getattr(r.action, "reasoning", "") or "")[:500],
                            action_name=str(getattr(r.action, "name", "") or ""),
                            action_params=dict(getattr(r.action, "parameters", {}) or {}),
                            observation_status=obs_status,
                            observation_summary=summary_src,
                            target=target,
                            caller_model=str(caller_model),
                            timestamp=_dt.utcnow().isoformat() + "Z",
                        )
                    )
            except Exception:  # noqa: BLE001 - tracing must never break the loop
                pass

        return LoopResult(
            steps_taken=len(history),
            findings=findings,
            completed=completed,
            aborted=(len(history) >= max_steps and not completed),
            error=error_msg,
        )
