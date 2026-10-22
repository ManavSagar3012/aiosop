"""Real Linux DAC witness: a readonly bind is not a permission grant.

This test creates ONLY temporary fixtures, never uses production SourceMap
files or Docker. Run as a root-owned isolated *test runner* to exercise the
actual kernel's different-UID access denial; otherwise skip rather than
claiming an unobserved cross-UID result. Native workers remain nonroot.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux kernel DAC evidence only")


def _unprivileged_open(path: Path, *, write: bool) -> subprocess.CompletedProcess[str]:
    """Invoke a bounded Python child as uid/gid 65534, not a native worker."""

    def drop_to_nobody() -> None:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

    code = "import pathlib,sys; " "p=pathlib.Path(sys.argv[1]); " + (
        "p.write_bytes(b'changed')" if write else "p.read_bytes()"
    )
    return subprocess.run(
        [sys.executable, "-c", code, str(path)],
        check=False,
        text=True,
        capture_output=True,
        cwd="/tmp",
        timeout=5,
        preexec_fn=drop_to_nobody,
    )


def test_private_original_is_not_readable_or_writable_by_distinct_native_uid() -> None:
    if os.geteuid() != 0:
        pytest.skip("Different native UID requires isolated root-owned test fixture")
    with tempfile.TemporaryDirectory(prefix="osop-dac-", dir="/tmp") as base:
        # The test parent is traversable so an unsuccessful open actually
        # depends on the staged directory/file protection, not /tmp ancestry.
        os.chmod(base, 0o711)
        root = Path(base) / "sourcemap-originals"
        root.mkdir(mode=0o700)
        staged = root / ("e" * 64 + ".map")
        staged.write_bytes(b'{"version":3}')
        os.chmod(staged, 0o400)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(staged.stat().st_mode) == 0o400
        assert root.stat().st_uid == 0
        assert staged.stat().st_uid == 0
        assert staged.read_bytes() == b'{"version":3}'

        read = _unprivileged_open(staged, write=False)
        write = _unprivileged_open(staged, write=True)
        assert read.returncode != 0
        assert write.returncode != 0
        assert b"changed" not in staged.read_bytes()
        assert staged.read_bytes() == b'{"version":3}'
