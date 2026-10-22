"""Opt-in disposable PostgreSQL migration 0024 immutable evidence checks.

Uses ONLY fresh uniquely owned loopback Docker container and private test DB;
never accesses application Postgres or calls a target. These synthetic records
are NOT valid independent target verification or senior report approval.
"""

import asyncio
import os
import uuid
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_disposable_0024_write_once_evidence_digest_and_fk():
    if os.environ.get("OSOP_DISPOSABLE_EVIDENCE_0024_PG") != "1":
        pytest.skip("Explicit isolated PostgreSQL 0024 opt-in required")

    import docker
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    client = docker.from_env()
    client.images.get("pgvector/pgvector:pg16")  # Never pull a new image.
    name = "osop-disposable-evidence-0024-" + uuid.uuid4().hex[:12]
    assert not client.containers.list(all=True, filters={"name": name})
    owned = None
    engine = None
    try:
        owned = client.containers.run(
            "pgvector/pgvector:pg16",
            name=name,
            detach=True,
            remove=False,
            environment={
                "POSTGRES_USER": "postgres",
                "POSTGRES_PASSWORD": "disposable-local-evidence-0024",
                "POSTGRES_DB": "isolated_evidence_0024",
            },
            ports={"5432/tcp": ("127.0.0.1", None)},
            labels={"osop.disposable.qualification": "evidence-0024"},
            volumes={},
        )
        owned.reload()
        binding = owned.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert binding and binding[0]["HostIp"] in {"127.0.0.1", "::1"}
        port = int(binding[0]["HostPort"])
        dsn = (
            "postgresql+asyncpg://postgres:disposable-local-evidence-0024"
            f"@127.0.0.1:{port}/isolated_evidence_0024"
        )
        engine = create_async_engine(dsn, connect_args={"timeout": 3})
        for _ in range(45):
            try:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            pytest.fail("Unique disposable PostgreSQL did not start")

        project = Path(__file__).resolve().parents[2]

        def migrated_upgrade():
            config = Config(str(project / "alembic.ini"))
            config.set_main_option("script_location", str(project / "migrations"))
            config.set_main_option("sqlalchemy.url", dsn)
            command.upgrade(config, "0024")

        await asyncio.to_thread(migrated_upgrade)
        async with engine.connect() as conn:
            assert (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one() == "0024"
            triggers = (
                (
                    await conn.execute(
                        text(
                            "SELECT tgname FROM pg_trigger WHERE tgrelid='evidence_artifacts'::regclass "
                            "AND NOT tgisinternal"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert "trg_evidence_artifacts_immutable" in triggers

        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO session_states (session_id) VALUES (:id)"),
                {"id": "eng-disposable-evidence-0024"},
            )

        valid = {
            "id": "ev-" + uuid.uuid4().hex[:12],
            "engagement_id": "eng-disposable-evidence-0024",
            "finding_id": "finding-disposable",
            "source_tool": "isolated-test-only",
            "target_url": "https://not-contacted.invalid/resource",
            "request_headers_sha256": "a" * 64,
            "request_body_sha256": "b" * 64,
            "response_status": 200,
            "response_headers_sha256": "c" * 64,
            "response_body_sha256": "d" * 64,
            "merkle_leaf_hash": "e" * 64,
        }
        insert = text(
            "INSERT INTO evidence_artifacts "
            "(id,engagement_id,finding_id,source_tool,target_url,"
            "request_headers_sha256,request_body_sha256,response_status,"
            "response_headers_sha256,response_body_sha256,merkle_leaf_hash,replay_recipe) "
            "VALUES (:id,:engagement_id,:finding_id,:source_tool,:target_url,"
            ":request_headers_sha256,:request_body_sha256,:response_status,"
            ":response_headers_sha256,:response_body_sha256,:merkle_leaf_hash,CAST('{}' AS JSON))"
        )
        async with engine.begin() as conn:
            await conn.execute(insert, valid)
        for statement, args in (
            (
                "UPDATE evidence_artifacts SET source_tool='tampered' WHERE id=:id",
                {"id": valid["id"]},
            ),
            ("DELETE FROM evidence_artifacts WHERE id=:id", {"id": valid["id"]}),
        ):
            async with engine.connect() as conn:
                with pytest.raises(Exception):
                    await conn.execute(text(statement), args)
                await conn.rollback()
        async with engine.connect() as conn:
            with pytest.raises(Exception):
                await conn.execute(
                    insert, {**valid, "id": "ev-bad-digest", "merkle_leaf_hash": "BAD"}
                )
            await conn.rollback()
        async with engine.connect() as conn:
            assert (
                await conn.execute(
                    text("SELECT count(*) FROM evidence_artifacts WHERE id=:id"),
                    {"id": valid["id"]},
                )
            ).scalar_one() == 1
    finally:
        if engine is not None:
            await engine.dispose()
        if owned is not None:
            try:
                owned.remove(force=True, v=True)
            except Exception:
                # Do not touch other containers; report failure if owned cleanup fails.
                raise
