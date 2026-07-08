from datetime import datetime

from ai_osop.core.config import EngagementPhase
from ai_osop.core.engagement_state import EngagementState
from ai_osop.orchestrator.state_machine import EngagementStateMachine


def test_state_machine():
    state = EngagementState(id="eng-1", phase=EngagementPhase.INITIALIZED)
    sm = EngagementStateMachine(session_memory=None)

    print(f"Initial state: {state.phase}")

    # Valid transition
    success = sm.apply_transition(state, EngagementPhase.RECONNAISSANCE)
    print(
        f"Transition to RECONNAISSANCE: {success}, New state: {state.phase}, Version: {state.version}"
    )
    assert success
    assert state.phase == EngagementPhase.RECONNAISSANCE
    assert state.version == 1

    # Invalid transition
    success = sm.apply_transition(state, EngagementPhase.INITIALIZED)
    print(
        f"Transition to INITIALIZED: {success}, New state: {state.phase}, Version: {state.version}"
    )
    assert not success
    assert state.phase == EngagementPhase.RECONNAISSANCE
    assert state.version == 1


if __name__ == "__main__":
    test_state_machine()
    print("Test passed!")
