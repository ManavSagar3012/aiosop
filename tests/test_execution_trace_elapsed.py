"""elapsed_seconds must freeze at completion, not keep counting wall-clock.

Regression: a completed 37s task reported ~950s when read minutes later because
elapsed used time.monotonic() - start instead of last_stage - start.
"""

import time

from ai_osop.core.execution_trace import (
    ExecutionStage,
    StageRecord,
    TaskExecutionTrace,
)


def test_completed_trace_freezes_elapsed():
    t = TaskExecutionTrace("task-x", "eng-x")
    t._start_time = 1000.0
    t._stages = [
        StageRecord("task_created", timestamp=1000.2),
        StageRecord(ExecutionStage.TASK_COMPLETED.value, timestamp=1037.6),
    ]
    assert t.is_complete
    # Duration is fixed at last-stage - start, regardless of "now".
    assert round(t.elapsed_seconds, 1) == 37.6
    time.sleep(0.05)
    assert round(t.elapsed_seconds, 1) == 37.6  # does not drift


def test_running_trace_uses_now():
    t = TaskExecutionTrace("task-y", "eng-y")
    t._stages = [StageRecord("task_created", timestamp=t._start_time + 0.01)]
    assert not t.is_complete
    e1 = t.elapsed_seconds
    time.sleep(0.05)
    e2 = t.elapsed_seconds
    assert e2 >= e1  # still counting while in-flight


if __name__ == "__main__":
    test_completed_trace_freezes_elapsed()
    test_running_trace_uses_now()
    print("execution-trace elapsed tests OK")
