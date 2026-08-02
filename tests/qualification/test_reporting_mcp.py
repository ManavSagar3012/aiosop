"""
Reporting MCP reality gate.
Proves reporting-mcp compiles real HTML/Markdown reports using ReportExporter.
"""

import pytest
import time
from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def test_reporting_flow():
    base = require_server("reporting")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "compile_findings" in tools

    idemp_key = f"idemp-key-{int(time.time())}"

    # Trigger report compilation
    # It enqueues the job and returns a job_id with status "pending" or "running"
    res = mcp_execute(
        base,
        "compile_findings",
        {
            "engagement_id": "test-eng-reporting-mcp",
            "format": "html",
            "idempotency_key": idemp_key
        }
    )
    assert res.get("job_id") is not None
    assert res.get("status") in ("pending", "running", "completed")

    # Poll using the idempotency key for completion
    for _ in range(15):
        time.sleep(1)
        poll_res = mcp_execute(
            base,
            "compile_findings",
            {
                "engagement_id": "test-eng-reporting-mcp",
                "format": "html",
                "idempotency_key": idemp_key
            }
        )
        if poll_res.get("status") == "completed":
            assert poll_res.get("download_url") is not None
            assert "reports/download/" in poll_res.get("download_url")
            break
        elif poll_res.get("status") == "failed":
            pytest.fail(f"Report job failed: {poll_res.get('error')}")
    else:
        pytest.fail("Report job did not complete within timeout")
