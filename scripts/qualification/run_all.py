#!/usr/bin/env python3
"""Master runner for all qualification suites.

Usage:
    python scripts/qualification/run_all.py
"""

import asyncio
import subprocess
import sys
from pathlib import Path

SUITES = [
    "scripts/qualification/test_security.py",
    "scripts/qualification/test_reliability.py",
    "scripts/qualification/test_ownership.py",
    "scripts/qualification/test_scale.py",
]


async def main():
    print("=" * 60)
    print("AI-OSOP QUALIFICATION SUITE - MASTER RUNNER")
    print("=" * 60)

    all_passed = True
    for suite in SUITES:
        if not Path(suite).exists():
            print(f"\nWARNING: {suite} not found, skipping")
            continue
        print(f"\n--- Running {suite} ---")
        proc = await asyncio.create_subprocess_exec(
            sys.executable, suite,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        print(stdout.decode("utf-8", errors="replace"))
        if proc.returncode != 0:
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("ALL QUALIFICATION SUITES PASSED")
    else:
        print("SOME QUALIFICATION SUITES FAILED")
    print("=" * 60)

    # Generate report
    print("\nGenerating report...")
    report_proc = await asyncio.create_subprocess_exec(
        sys.executable, "scripts/qualification/generate_report.py",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stdout, _ = await report_proc.communicate()
    print(stdout.decode("utf-8", errors="replace"))

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
