import heapq
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GoalAction(BaseModel):
    """
    Represents a possible technique or step in an attack chain.
    """

    name: str
    preconditions: Dict[str, Any] = Field(default_factory=dict)
    effects: Dict[str, Any] = Field(default_factory=dict)
    cost: float = Field(1.0, ge=0.0)


class GoalState(BaseModel):
    """
    Represents the state of an engagement (or agent) at a point in time.
    """

    properties: Dict[str, Any] = Field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)


class PlannerNode:
    """
    Internal node class for A* search.
    """

    def __init__(
        self,
        state: GoalState,
        g_score: float,
        h_score: float,
        parent: Optional["PlannerNode"] = None,
        action: Optional[GoalAction] = None,
    ):
        self.state = state
        self.g_score = g_score
        self.h_score = h_score
        self.f_score = g_score + h_score
        self.parent = parent
        self.action = action

    def __lt__(self, other: "PlannerNode") -> bool:
        return self.f_score < other.f_score


class GoalPlanner:
    """
    GOAP Planner using A* search to find paths from initial_state to goal_state.
    """

    def plan(
        self,
        initial_state: GoalState,
        goal_state: GoalState,
        actions: List[GoalAction],
    ) -> Optional[List[GoalAction]]:
        """
        Find a sequence of actions that transition initial_state to goal_state.
        Returns None if no path is found.
        """
        # Ties are broken by the order nodes are added (a simple counter)
        open_list: List[Tuple[float, int, PlannerNode]] = []
        counter = 0

        initial_h = self._heuristic(initial_state, goal_state)
        start_node = PlannerNode(state=initial_state, g_score=0.0, h_score=initial_h)
        heapq.heappush(open_list, (start_node.f_score, counter, start_node))
        counter += 1

        closed_set: Set[Tuple[Tuple[str, Any], ...]] = set()

        while open_list:
            _, _, current_node = heapq.heappop(open_list)
            current_state = current_node.state

            # If we reached the goal state
            if self._is_goal_reached(current_state, goal_state):
                return self._reconstruct_path(current_node)

            hashable_state = self._to_hashable(current_state)
            if hashable_state in closed_set:
                continue
            closed_set.add(hashable_state)

            # Try applying all available actions
            for action in actions:
                if self._satisfies_preconditions(current_state, action):
                    next_state = self._apply_effects(current_state, action)
                    next_hashable = self._to_hashable(next_state)

                    if next_hashable in closed_set:
                        continue

                    tentative_g = current_node.g_score + action.cost
                    h_score = self._heuristic(next_state, goal_state)

                    next_node = PlannerNode(
                        state=next_state,
                        g_score=tentative_g,
                        h_score=h_score,
                        parent=current_node,
                        action=action,
                    )

                    heapq.heappush(open_list, (next_node.f_score, counter, next_node))
                    counter += 1

        return None

    def _heuristic(self, state: GoalState, goal: GoalState) -> float:
        """
        Estimate distance to the goal by counting the number of mismatched target properties.
        """
        mismatches = 0
        for k, v in goal.properties.items():
            if k not in state.properties:
                mismatches += 1
                continue
            state_val = state.properties[k]
            if isinstance(state_val, (list, set)):
                if isinstance(v, (list, set)):
                    mismatches += len(set(v) - set(state_val))
                else:
                    if v not in state_val:
                        mismatches += 1
            elif state_val != v:
                mismatches += 1
        return float(mismatches)

    def _is_goal_reached(self, state: GoalState, goal: GoalState) -> bool:
        """
        Check if state satisfies all properties in goal.
        """
        for k, v in goal.properties.items():
            if k not in state.properties:
                return False
            state_val = state.properties[k]
            if isinstance(state_val, (list, set)):
                if isinstance(v, (list, set)):
                    if not set(v).issubset(set(state_val)):
                        return False
                else:
                    if v not in state_val:
                        return False
            elif state_val != v:
                return False
        return True

    def _satisfies_preconditions(self, state: GoalState, action: GoalAction) -> bool:
        """
        Check if state meets all of the action's preconditions.
        """
        for k, v in action.preconditions.items():
            if k not in state.properties:
                return False
            state_val = state.properties[k]
            if isinstance(state_val, (list, set)):
                if isinstance(v, (list, set)):
                    if not set(v).issubset(set(state_val)):
                        return False
                else:
                    if v not in state_val:
                        return False
            elif state_val != v:
                return False
        return True

    def _apply_effects(self, state: GoalState, action: GoalAction) -> GoalState:
        """
        Generate a new state by applying the action's effects.
        """
        new_properties = dict(state.properties)
        for k, v in action.effects.items():
            current_val = new_properties.get(k)
            if isinstance(current_val, list):
                if isinstance(v, list):
                    # Merge and deduplicate preserving order
                    combined = list(current_val)
                    for item in v:
                        if item not in combined:
                            combined.append(item)
                    new_properties[k] = combined
                else:
                    if v not in current_val:
                        new_properties[k] = current_val + [v]
            elif isinstance(current_val, set):
                if isinstance(v, (list, set)):
                    new_properties[k] = current_val | set(v)
                else:
                    new_properties[k] = current_val | {v}
            else:
                new_properties[k] = v
        return GoalState(properties=new_properties)

    def _reconstruct_path(self, node: PlannerNode) -> List[GoalAction]:
        """
        Trace back from goal node to initial node to reconstruct the action sequence.
        """
        path = []
        current: Optional[PlannerNode] = node
        while current and current.action:
            path.append(current.action)
            current = current.parent
        return list(reversed(path))

    def _to_hashable(self, state: GoalState) -> Tuple[Tuple[str, Any], ...]:
        """
        Convert GoalState properties into a sorted hashable representation.
        """
        items = []
        for k, v in sorted(state.properties.items()):
            if isinstance(v, list):
                items.append((k, tuple(sorted(v))))
            elif isinstance(v, set):
                items.append((k, tuple(sorted(list(v)))))
            elif isinstance(v, dict):
                items.append(
                    (
                        k,
                        tuple(
                            sorted(
                                (dk, tuple(dv) if isinstance(dv, list) else dv)
                                for dk, dv in v.items()
                            )
                        ),
                    )
                )
            else:
                items.append((k, v))
        return tuple(items)
