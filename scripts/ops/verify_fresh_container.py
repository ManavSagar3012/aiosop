"""Verify packaged startup against disposable databases owned by this run.

This proves migrations and backing-store connectivity, not scanner execution.
No host database, existing container, external target, or provider is modified.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def _docker(*arguments: str) -> str:
    result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=120)
    if result.returncode:
        # Command arguments can contain temporary credentials.
        raise RuntimeError("Disposable container operation failed")
    return result.stdout.strip()


def main() -> None:
    identity = "osop-startup-" + secrets.token_hex(5)
    password = secrets.token_hex(24)
    owned: list[str] = []
    runtime = Path(".runtime/fresh-container")
    runtime.mkdir(parents=True, exist_ok=True)
    _docker("network", "create", identity)
    try:
        for suffix, image, environment in (
            (
                "pg",
                "pgvector/pgvector:pg16",
                ["POSTGRES_USER=osop", "POSTGRES_DB=osop", f"POSTGRES_PASSWORD={password}"],
            ),
            ("redis", "redis:7-alpine", []),
            (
                "graph",
                "neo4j:5.18-community",
                [
                    f"NEO4J_AUTH=neo4j/{password}",
                    "NEO4J_server_memory_heap_initial__size=128m",
                    "NEO4J_server_memory_heap_max__size=256m",
                    "NEO4J_server_memory_pagecache_size=64m",
                ],
            ),
        ):
            name = identity + "-" + suffix
            arguments = ["run", "-d", "--name", name, "--network", identity]
            for variable in environment:
                arguments.extend(["-e", variable])
            container = _docker(*arguments, image)
            owned.append(container)
        api_name = identity + "-api"
        arguments = [
            "run",
            "-d",
            "--name",
            api_name,
            "--network",
            identity,
            "-p",
            "127.0.0.1::8200",
        ]
        for variable in (
            "OSOP_ENV=development",
            "OSOP_ATTESTED_REPORT_ROOT=/app/reports",
            f"OSOP_POSTGRES_URI=postgresql+asyncpg://osop:{password}@{identity}-pg:5432/osop",
            f"OSOP_REDIS_URI=redis://{identity}-redis:6379/0",
            f"OSOP_NEO4J_URI=bolt://{identity}-graph:7687",
            f"OSOP_NEO4J_PASSWORD={password}",
            f"OSOP_JWT_SECRET={secrets.token_hex(32)}",
        ):
            arguments.extend(["-e", variable])
        container = _docker(*arguments, "ai-osop:repair-20261022")
        owned.append(container)
        port = json.loads(_docker("inspect", container))[0]["NetworkSettings"]["Ports"]["8200/tcp"][
            0
        ]["HostPort"]
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/ready", timeout=3
                ) as response:
                    ready = json.load(response)
                if all(
                    ready["checks"][name]["status"] == "healthy"
                    for name in ("postgres", "redis", "neo4j")
                ):
                    migration = _docker("exec", container, "alembic", "current")
                    (runtime / "result.json").write_text(
                        json.dumps(
                            {
                                "ready": ready,
                                "migration": migration,
                                "claim": "fresh development startup only",
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    print(
                        "PASS: fresh packaged startup, migrations and three databases; provider execution unverified"
                    )
                    return
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(2)
        logs = _docker("logs", container).replace(password, "[REDACTED]")
        (runtime / "api.log").write_text(logs, encoding="utf-8")
        raise RuntimeError("Fresh startup failed; inspect .runtime/fresh-container/api.log")
    finally:
        for container in reversed(owned):
            _docker("rm", "-f", "-v", container)
        _docker("network", "rm", identity)


if __name__ == "__main__":
    main()
