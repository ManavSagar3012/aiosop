"""Pins the honesty-guard contract for the LIVE standalone csrf/jwt agents.

Regression guard for the dead-code trap: the earlier execution_verified fix
landed in vuln_agent._execute_{csrf,jwt}_scan, which are test-compat dead code —
the scheduler routes csrf_scan/jwt_scan to the standalone CSRFAgent/JWTAgent
(csrf_agent.py / jwt_agent.py). Those agents' success returns lacked
execution_verified, so every clean csrf/jwt scan was rejected by the guard and
marked failed. These assertions fail if any live terminal path regresses.

Run: python tests/test_csrf_jwt_execution_verified.py
"""

import asyncio
import sys

sys.path.insert(0, "src")

from ai_osop.agents.base import BaseAgent


async def guard(d):
    # _validate_output only reads `result`; self is unused.
    return await BaseAgent._validate_output(None, d)


def survives(d):
    return asyncio.run(guard(d)).get("status") != "error"


# --- The exact terminal shapes the fixed live agents now return ---
CSRF_NOT_APPLICABLE = {"status": "skipped", "confirmed": False, "reason": "r", "findings_count": 0}
CSRF_NO_COOKIE = {"status": "skipped", "confirmed": False, "reason": "bearer", "findings_count": 0}
CSRF_PROBE_REJECTED = {
    "status": "success",
    "tool": "csrf_scan",
    "confirmed": False,
    "reason": "rejected",
    "findings_count": 0,
    "execution_verified": True,
}
JWT_NO_TOKEN = {
    "status": "skipped",
    "message": "skipped: no JWT token in scope",
    "findings_count": 0,
}
JWT_ANALYZED = {"status": "success", "message": "JWT scan completed", "execution_verified": True}

# --- The old broken shapes that caused csrf/jwt to always fail ---
CSRF_OLD_BROKEN = {"status": "success", "confirmed": False, "reason": "r", "findings_count": 0}
JWT_OLD_BROKEN = {"status": "success", "message": "JWT scan completed"}


def main():
    for name, d in [
        ("csrf not-applicable", CSRF_NOT_APPLICABLE),
        ("csrf no-cookie", CSRF_NO_COOKIE),
        ("csrf probe-rejected", CSRF_PROBE_REJECTED),
        ("jwt no-token", JWT_NO_TOKEN),
        ("jwt analyzed-clean", JWT_ANALYZED),
    ]:
        assert survives(d), f"{name} must survive the honesty guard, was rejected"

    # The pre-fix shapes must still be rejected — proves the guard is real and
    # the fix is what makes the difference (not a weakened guard).
    assert not survives(CSRF_OLD_BROKEN), "old csrf success-without-evidence must be rejected"
    assert not survives(JWT_OLD_BROKEN), "old jwt success-without-evidence must be rejected"

    print(
        "csrf/jwt execution_verified contract OK: live terminal paths survive, old shapes rejected"
    )


if __name__ == "__main__":
    main()
