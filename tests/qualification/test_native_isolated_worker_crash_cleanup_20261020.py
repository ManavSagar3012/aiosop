"""Controlled hard-kill of OWNED isolated Go worker with stranded tmpfs bytes.

This exercises Docker daemon cleanup of a private worker mount after forced
process/container death, not execution of a scanner or actual 0032 staging.
The deliberately inserted test-only file is NOT an app artifact or a target.
"""

from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

from tests.qualification.native_linux_isolated_go_helper_20261020 import (
    isolated_linux_go_worker,
)

_OPT_IN = "OSOP_NATIVE_ISOLATED_KILL_QUAL"
_OWNER_LABEL = "osop.native.linux.qualification"


@pytest.mark.asyncio
async def test_owned_worker_hard_kill_erases_stranded_private_tmpfs() -> None:
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip("Explicitly opt in to isolated disposable worker hard-kill")

    import docker

    client = docker.from_env(timeout=8)
    worker_id = ""
    network_id = ""
    try:
        async with isolated_linux_go_worker(native_env={}) as worker:
            worker_id = worker.container_id
            network_id = worker.network_id
            owned = client.containers.get(worker_id)
            assert owned.labels.get(_OWNER_LABEL, "").startswith("osop-native-linux-")
            assert await worker.stage_root_empty() is True

            # Simulate a process crash AFTER writing a read-only original file
            # but BEFORE its Go cleanup defer; the test does not forge or
            # issue a grant or contact a target. Only our own container UID
            # writes under its dedicated noexec/nohostmount private tmpfs.
            script = (
                "import os; p='/run/osop-native-stage/stage-crash-fixture'; "
                "f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600); "
                "os.write(f,b'controlled-inert-original'); os.fsync(f); "
                "os.fchmod(f,0o400); os.close(f)"
            )
            await asyncio.to_thread(
                subprocess.run,
                ["docker", "exec", "--user", "65534:65534", owned.name, "python3", "-c", script],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
            assert await worker.stage_root_empty() is False
            owned.kill(signal="SIGKILL")
            owned.reload()
            assert owned.status != "running"

        # The independent context manager tears down the owned container and
        # its entire tmpfs mount despite no native Go graceful cleanup.
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(worker_id)
        with pytest.raises(docker.errors.NotFound):
            client.networks.get(network_id)
    finally:
        client.close()
