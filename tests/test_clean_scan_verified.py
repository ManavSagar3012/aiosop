"""Regression: clean (0-finding) scans must be honestly terminalizable.

Guards AIOSOP-XSS-CLEAN-VERIFIED-2026-07-26. The honesty guard
(BaseAgent._validate_output) downgrades any status=="success" result that
carries no proof-of-execution — this stops a no-op/stub scanner from reporting
a false "all clear". But a scanner that GENUINELY ran its probe and found
nothing is a legitimate clean result and must survive.

The fix: clean scan returns carry ``execution_verified`` set to whether the
probe actually ran (real browser navigate+eval / real HTTP). This test pins
the two halves of that contract:

1. A verified-clean result (execution_verified=True) survives the guard.
2. A blind-clean result (execution_verified=False, e.g. stub/launch-failure)
   is still rejected — the guard's whole point.

Run: .venv/Scripts/python.exe tests/test_clean_scan_verified.py
"""
import asyncio
import sys

sys.path.insert(0, "src")

from ai_osop.agents.base import BaseAgent


# _validate_output only reads the result dict — it never touches ``self`` — so we
# invoke the unbound coroutine with self=None, avoiding BaseAgent's abstract-method
# / AgentContext construction requirements.
def _validate(result):
    return asyncio.run(BaseAgent._validate_output(None, result))


def test_verified_clean_survives():
    # xss_scan clean return shape WITH a real browser probe having run.
    clean = {
        "status": "success",
        "tool": "xss_scan",
        "target": "http://t/rest/products/search?q=1",
        "confirmed": False,
        "findings_count": 0,
        "execution_verified": True,
    }
    out = _validate(clean)
    assert out["status"] == "success", f"verified-clean was wrongly downgraded: {out}"


def test_blind_clean_rejected():
    # Same clean shape but the probe never ran (stub / chromium launch failure).
    blind = {
        "status": "success",
        "tool": "xss_scan",
        "target": "http://t/rest/products/search?q=1",
        "confirmed": False,
        "findings_count": 0,
        "execution_verified": False,
    }
    out = _validate(blind)
    assert out["status"] == "error", f"blind-clean should be rejected by honesty guard: {out}"


def test_missing_flag_still_rejected():
    # A clean success with NO execution_verified key (the old bug) must not pass.
    legacy = {
        "status": "success",
        "tool": "xss_scan",
        "confirmed": False,
        "findings_count": 0,
    }
    out = _validate(legacy)
    assert out["status"] == "error", f"un-evidenced clean must be rejected: {out}"


if __name__ == "__main__":
    test_verified_clean_survives()
    test_blind_clean_rejected()
    test_missing_flag_still_rejected()
    print("clean-scan honesty contract OK: verified-clean survives, blind-clean rejected")
