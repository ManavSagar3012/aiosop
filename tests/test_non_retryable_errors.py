"""Non-retryable error classification: deterministic contract errors skip the
retry loop and go straight to the DLQ.

Regression for the live-audit retry storm (66 retries across 12 tasks on
"Tool run_sqlmap not available on server security-bridge").
"""

from ai_osop.orchestrator.task_scheduler import TaskScheduler


def test_deterministic_errors_are_non_retryable():
    for err in (
        "Tool run_sqlmap not available on server security-bridge",
        "tool 'x' not registered",
        "Unknown tool: foo",
        "invalid argument: url",
    ):
        assert TaskScheduler._is_non_retryable({"error": err}), err


def test_transient_errors_still_retry():
    for err in (
        "ConnectionRefusedError: [Errno 111]",
        "Read timed out after 180s",
        "HTTP 503 Service Unavailable",
        "neo4j.exceptions.ServiceUnavailable",
        "",
    ):
        assert not TaskScheduler._is_non_retryable({"error": err}), err


if __name__ == "__main__":
    test_deterministic_errors_are_non_retryable()
    test_transient_errors_still_retry()
    print("non-retryable classifier tests OK")
