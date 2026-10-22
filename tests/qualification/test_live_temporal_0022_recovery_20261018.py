"""Opt-in isolated launcher for the unchanged real Temporal/PG recovery suite.

Owns only two uniquely named disposable containers. Never attaches to an
existing application service or uses default host ports. Worker hard-kill is
performed by the historical qualification test on its own spawned subprocess.
"""

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest


@pytest.mark.timeout(240)
def test_disposable_temporal_pg_recovery_0022():
    if os.environ.get("OSOP_DISPOSABLE_TEMPORAL_0022") != "1":
        pytest.skip("Set OSOP_DISPOSABLE_TEMPORAL_0022=1 for fresh isolated Docker services")

    import docker
    import psycopg

    docker_client = docker.from_env()
    for image in ("pgvector/pgvector:pg16", "temporalio/temporal:latest"):
        docker_client.images.get(image)  # Existing local images only; no pulls.

    run_id = uuid.uuid4().hex[:14]
    db_name = "temporal_qualification_" + run_id
    names = ["osop-disposable-temporal-pg-" + run_id, "osop-disposable-temporal-server-" + run_id]
    for name in names:
        if docker_client.containers.list(all=True, filters={"name": name}):
            pytest.fail("Unique qualification container name collision")
    created = []
    try:
        postgres = docker_client.containers.run(
            "pgvector/pgvector:pg16", detach=True, name=names[0], remove=False,
            environment={"POSTGRES_USER": "postgres", "POSTGRES_PASSWORD": "temporal-qual-local",
                         "POSTGRES_DB": db_name},
            ports={"5432/tcp": ("127.0.0.1", None)}, volumes={},
            labels={"osop.disposable.qualification": "temporal-0022"},
        )
        created.append(postgres)
        postgres.reload()
        db_binding = postgres.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert len(db_binding) == 1 and db_binding[0]["HostIp"] == "127.0.0.1"
        db_port = int(db_binding[0]["HostPort"])
        assert db_port not in {5432, 5433}

        temporal = docker_client.containers.run(
            "temporalio/temporal:latest", detach=True, name=names[1], remove=False,
            command=["server", "start-dev", "--ip", "0.0.0.0", "--port", "7233"],
            ports={"7233/tcp": ("127.0.0.1", None)}, volumes={},
            labels={"osop.disposable.qualification": "temporal-0022"},
        )
        created.append(temporal)
        temporal.reload()
        temporal_binding = temporal.attrs["NetworkSettings"]["Ports"]["7233/tcp"]
        assert len(temporal_binding) == 1 and temporal_binding[0]["HostIp"] == "127.0.0.1"
        temporal_port = int(temporal_binding[0]["HostPort"])
        assert temporal_port not in {7233, 7234}

        for _ in range(60):
            try:
                with psycopg.connect(host="127.0.0.1", port=db_port, user="postgres",
                                     password="temporal-qual-local", dbname=db_name,
                                     connect_timeout=1) as connection:
                    connection.execute("SELECT 1")
                break
            except psycopg.OperationalError:
                time.sleep(.2)
        else:
            pytest.fail("Disposable PostgreSQL not ready")

        # The historical tests themselves perform real Temporal connection,
        # Alembic head migration and signed PG admission checks.
        env = dict(os.environ)
        env.pop("OSOP_DISPOSABLE_TEMPORAL_0022", None)
        env["OSOP_TEMPORAL_QUAL_ADDRESS"] = f"127.0.0.1:{temporal_port}"
        env["OSOP_TEMPORAL_QUAL_POSTGRES_URL"] = (
            f"postgresql+asyncpg://postgres:temporal-qual-local@127.0.0.1:{db_port}/{db_name}"
        )
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
             "tests/qualification/test_live_temporal_admission_recovery.py"],
            cwd=root, env=env, capture_output=True, text=True, timeout=180,
        )
        print(result.stdout[-6000:])
        if result.returncode:
            print(result.stderr[-4000:])
        assert result.returncode == 0, "Unchanged live Temporal/PG recovery suite failed"
        assert "passed" in result.stdout and "failed" not in result.stdout
    finally:
        for container in reversed(created):
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
