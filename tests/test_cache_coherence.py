"""Test: Cache coherence spike test (runs all 12 scenarios).

This is the pytest CI wrapper for
scripts/qualification/test_cache_coherence.py.
"""

from __future__ import annotations

import subprocess
import sys


class TestCacheCoherence:

    def test_all_scenarios(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/qualification/test_cache_coherence.py"],
            capture_output=True,
            timeout=120,
        )
        stdout = result.stdout.decode()
        stderr = result.stderr.decode()
        if result.returncode != 0:
            print(stdout)
            print(stderr)
        assert result.returncode == 0, (
            f'Cache coherence spike returned exit {result.returncode}. '
            f'Stdout: {stdout[:500]}'
        )
