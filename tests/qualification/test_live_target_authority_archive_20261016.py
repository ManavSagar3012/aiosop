"""Real disposable PG16 migration 0016→0018 immutable signed-source qualification.

Runs ONLY against a separately named temporary loopback PostgreSQL container.
Never uses application DATABASE_URL and never opens a non-disposable database.
"""

import importlib.util
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

_ROOT = Path(__file__).resolve().parents[2]
_VERSIONS = (
    "0016_target_authority_nonce_receipts",
    "0017_target_audit_corroboration_digest",
    "0018_target_authority_signed_sources",
)


def _create_disposable_schema_and_apply_migrations(conn):
    conn.execute(text("CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)"))
    conn.execute(text("CREATE TABLE execution_flows (id varchar(64) PRIMARY KEY)"))
    conn.execute(text("CREATE TABLE tasks (id varchar(64) PRIMARY KEY)"))
    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        for name in _VERSIONS:
            location = _ROOT / "migrations" / "versions" / (name + ".py")
            spec = importlib.util.spec_from_file_location(name, location)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.upgrade()


@pytest.mark.asyncio
async def test_live_disposable_postgres_signed_source_archive_and_immutability():
    raw = os.environ.get("OSOP_DISPOSABLE_TARGET_ARCHIVE_DB", "")
    if not raw:
        pytest.skip("Explicit dedicated disposable PostgreSQL URL required")
    url = urlsplit(raw)
    if (
        url.scheme != "postgresql+asyncpg"
        or url.username != "postgres"
        or url.hostname != "127.0.0.1"
        or url.port != 65489
        or url.path != "/postgres"
    ):
        pytest.fail("Refusing database outside the exclusively named disposable PG container")
    engine = create_async_engine(raw, pool_size=2, max_overflow=0)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(_create_disposable_schema_and_apply_migrations)
            await conn.execute(
                text("INSERT INTO session_states(session_id) VALUES ('eng-archive')")
            )
            await conn.execute(text("INSERT INTO execution_flows(id) VALUES ('flow-archive')"))
            for task_id in ("task-original", "task-source", "task-target"):
                await conn.execute(text("INSERT INTO tasks(id) VALUES (:id)"), {"id": task_id})

            args = {
                "id": "tproof-" + "a" * 32,
                "eng": "eng-archive",
                "flow": "flow-archive",
                "original": "task-original",
                "source": "task-source",
                "target": "task-target",
                "key": "independent-service-key",
                "version": 5,
                "revision": 7,
                "proof": "a" * 64,
                "audit": "b" * 64,
                "claims": b'{"schema":"target-owned-attestation"}',
                "sig": "A" * 86,
                "ownership": b'{"role":"ownership"}',
                "ownership_sig": "B" * 86,
                "access": b'{"role":"access"}',
                "access_sig": "C" * 86,
            }
            await conn.execute(
                text(
                    "INSERT INTO target_authority_assertions "
                    "(id,engagement_id,flow_id,original_source_task_id,source_task_id,"
                    "target_task_id,key_id,authorization_version,flow_revision,proof_sha256,"
                    "audit_corroboration_sha256,target_claims_json,target_signature_b64url,"
                    "ownership_audit_json,ownership_audit_signature,access_audit_json,"
                    "access_audit_signature,proof_received_at_epoch) VALUES "
                    "(:id,:eng,:flow,:original,:source,:target,:key,:version,:revision,:proof,"
                    ":audit,:claims,:sig,:ownership,:ownership_sig,:access,:access_sig,"
                    "CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT))"
                ),
                args,
            )
            stored = (
                (
                    await conn.execute(
                        text(
                            "SELECT target_claims_json,ownership_audit_json,access_audit_json,"
                            "audit_corroboration_sha256,proof_received_at_epoch "
                            "FROM target_authority_assertions WHERE id=:id"
                        ),
                        {"id": args["id"]},
                    )
                )
                .mappings()
                .one()
            )
            assert bytes(stored["target_claims_json"]) == args["claims"]
            assert bytes(stored["ownership_audit_json"]) == args["ownership"]
            assert bytes(stored["access_audit_json"]) == args["access"]
            assert stored["audit_corroboration_sha256"] == args["audit"]
            assert type(stored["proof_received_at_epoch"]) is int

            # A complete old source-only entry remains structurally representable
            # but has no signed bytes or admission time and is not promotable.
            await conn.execute(
                text(
                    "INSERT INTO target_authority_assertions "
                    "(id,engagement_id,flow_id,original_source_task_id,source_task_id,"
                    "target_task_id,key_id,authorization_version,flow_revision,proof_sha256) "
                    "VALUES ('tproof-legacy',:eng,:flow,:original,:source,:target,:key,5,7,:proof)"
                ),
                {**args, "proof": "c" * 64},
            )

        async with engine.begin() as conn:
            with pytest.raises(DBAPIError):
                async with conn.begin_nested():
                    await conn.execute(
                        text(
                            "UPDATE target_authority_assertions SET proof_sha256=:sha WHERE id=:id"
                        ),
                        {"id": args["id"], "sha": "e" * 64},
                    )
            with pytest.raises(DBAPIError):
                async with conn.begin_nested():
                    await conn.execute(
                        text("DELETE FROM target_authority_assertions WHERE id=:id"),
                        {"id": args["id"]},
                    )
            with pytest.raises(DBAPIError):
                async with conn.begin_nested():
                    await conn.execute(
                        text(
                            "INSERT INTO target_authority_assertions "
                            "(id,engagement_id,flow_id,original_source_task_id,source_task_id,"
                            "target_task_id,key_id,authorization_version,flow_revision,proof_sha256,"
                            "audit_corroboration_sha256,ownership_audit_json) "
                            "VALUES ('tproof-partial',:eng,:flow,:original,:source,:target,"
                            ":key,5,7,:proof,:audit,:ownership)"
                        ),
                        {**args, "proof": "d" * 64},
                    )
    finally:
        await engine.dispose()
