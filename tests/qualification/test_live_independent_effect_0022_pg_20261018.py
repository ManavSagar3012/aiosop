"""Opt-in fresh disposable PostgreSQL qualification for actual Alembic 0022.

Starts only a uniquely named local-image container, binds a random loopback
port, and always removes solely that container. No application DB is used.
"""

import asyncio
import os
import uuid
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_disposable_pg0022_immutable_nonce_and_concurrent_cas():
    if os.environ.get("OSOP_DISPOSABLE_EFFECT_0022_PG") != "1":
        pytest.skip("Explicit disposable PG0022 opt-in required")
    import docker
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    project = Path(__file__).resolve().parents[2]
    client = docker.from_env()
    client.images.get("pgvector/pgvector:pg16")  # Never pull an image.
    name = "osop-disposable-effect-0022-" + uuid.uuid4().hex[:12]
    assert not client.containers.list(all=True, filters={"name": name})
    container = None
    engine = None
    try:
        container = client.containers.run(
            "pgvector/pgvector:pg16", detach=True, name=name, remove=False,
            environment={"POSTGRES_USER": "postgres", "POSTGRES_PASSWORD": "disposable-local-test",
                         "POSTGRES_DB": "isolated_effect_0022"},
            ports={"5432/tcp": ("127.0.0.1", None)},
            volumes={}, network_mode="bridge", labels={"osop.disposable.qualification": "0022"},
        )
        container.reload()
        binding = container.attrs["NetworkSettings"]["Ports"]["5432/tcp"]
        assert binding and binding[0]["HostIp"] in {"127.0.0.1", "::1"}
        port = int(binding[0]["HostPort"])
        url = f"postgresql+asyncpg://postgres:disposable-local-test@127.0.0.1:{port}/isolated_effect_0022"
        engine = create_async_engine(url, pool_pre_ping=True, connect_args={"timeout": 3})
        for _ in range(35):
            try:
                async with engine.connect() as connection:
                    await connection.execute(text("SELECT 1"))
                break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            pytest.fail("Fresh disposable PostgreSQL did not start")

        def upgrade():
            cfg = Config(str(project / "alembic.ini"))
            cfg.set_main_option("script_location", str(project / "migrations"))
            cfg.set_main_option("sqlalchemy.url", url)
            command.upgrade(cfg, "0022")

        await asyncio.to_thread(upgrade)
        async with engine.connect() as connection:
            head = (await connection.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
            assert head == "0022"
            triggers = (await connection.execute(text(
                "SELECT tgname FROM pg_trigger WHERE tgrelid IN "
                "('independent_target_effect_challenges'::regclass, "
                "'independent_target_effect_verifications'::regclass) AND NOT tgisinternal"
            ))).scalars().all()
            assert {"trg_independent_target_effect_challenges_immutable",
                    "trg_independent_target_effect_verifications_immutable"} <= set(triggers)

        nonce = uuid.uuid4().hex * 2
        challenge_id = "challenge-" + uuid.uuid4().hex
        # Seed solely in the disposable lab. Replica mode temporarily bypasses
        # unrelated parent FKs; tests below run with normal trigger checks.
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL session_replication_role = replica"))
            await connection.execute(text(
                "INSERT INTO independent_target_effect_challenges "
                "(id,engagement_id,flow_id,finding_id,qualification_id,qualification_sha256,"
                "nonce_sha256,issued_at,expires_at) VALUES "
                "(:id,'eng-lab','flow-lab','finding-lab','qual-lab',:digest,:nonce,100,130)"
            ), {"id": challenge_id, "digest": "a" * 64, "nonce": nonce})

        async with engine.connect() as connection:
            with pytest.raises(Exception):
                await connection.execute(text(
                    "UPDATE independent_target_effect_challenges SET expires_at=120 WHERE id=:id"
                ), {"id": challenge_id})
            await connection.rollback()
            with pytest.raises(Exception):
                await connection.execute(text(
                    "DELETE FROM independent_target_effect_challenges WHERE id=:id"
                ), {"id": challenge_id})
            await connection.rollback()

        async def claim(identifier: str):
            async with engine.begin() as connection:
                return await connection.execute(text(
                    "INSERT INTO independent_target_effect_challenges "
                    "(id,engagement_id,flow_id,finding_id,qualification_id,qualification_sha256,"
                    "nonce_sha256,issued_at,expires_at) VALUES "
                    "(:id,'eng-lab','flow-lab','finding-lab','qual-lab',:digest,:nonce,101,121) "
                    "ON CONFLICT (nonce_sha256) DO NOTHING RETURNING id"
                ), {"id": identifier, "digest": "a" * 64, "nonce": nonce})

        # Challenge is already consumed by the seed: concurrent retry attempts
        # cannot claim it again. Actual production CAS requires signed admission.
        outcomes = await asyncio.gather(claim("retry-1"), claim("retry-2"))
        assert all(result.scalar_one_or_none() is None for result in outcomes)
        async with engine.connect() as connection:
            count = (await connection.execute(text(
                "SELECT count(*) FROM independent_target_effect_challenges WHERE nonce_sha256=:nonce"
            ), {"nonce": nonce})).scalar_one()
            assert count == 1

        # Actual two-connection race on a previously unused nonce. FK bypass
        # applies only to synthetic lab parents; PG uniqueness still applies.
        fresh_nonce = uuid.uuid4().hex * 2
        async def first_claim(identifier):
            async with engine.begin() as connection:
                await connection.execute(text("SET LOCAL session_replication_role = replica"))
                result = await connection.execute(text(
                    "INSERT INTO independent_target_effect_challenges "
                    "(id,engagement_id,flow_id,finding_id,qualification_id,qualification_sha256,"
                    "nonce_sha256,issued_at,expires_at) VALUES "
                    "(:id,'eng-lab','flow-lab','finding-lab','qual-lab',:digest,:nonce,200,230) "
                    "ON CONFLICT (nonce_sha256) DO NOTHING RETURNING id"
                ), {"id": identifier, "digest": "a" * 64, "nonce": fresh_nonce})
                return result.scalar_one_or_none()
        winners = await asyncio.gather(first_claim("claim-one"), first_claim("claim-two"))
        assert len([winner for winner in winners if winner is not None]) == 1

        # Populate a verified row using synthetic parents within the isolated
        # lab. Constraints remain enabled and reject malformed verification.
        row = dict(
            id="itefv-" + uuid.uuid4().hex, engagement_id="eng-lab", flow_id="flow-lab",
            finding_id="finding-verified", review_decision_id="decision-lab",
            review_decision_sha256="a" * 64, review_revision=1,
            qualification_id="qual-verification", qualification_sha256="b" * 64,
            qualification_revision=1, challenge_id=challenge_id,
            original_source_task_id="task-original", source_task_id="task-source",
            target_task_id="task-target", proof_sha256="c" * 64,
            audit_corroboration_sha256="d" * 64, observation_binding_sha256="e" * 64,
            report_source_evidence_sha256="f" * 64, authorization_id="auth-lab",
            authorization_version=1, authorization_sha256="a" * 64,
            flow_revision=1, senior_reviewer_sub="reviewer-lab", resource_id="resource-lab",
            resource_owner_identity_sha256="b" * 64, resource_visibility="private",
            source_http_status=200, target_http_status=200, anonymous_http_status=403,
            private_content_sha256="c" * 64, verifier_key_id="key-lab",
            verifier_origin="https://observer.example.invalid", verifier_public_key_sha256="d" * 64,
            verifier_registry_sha256="e" * 64, verifier_nonce_sha256="f" * 64,
            verdict_sha256="1" * 64, signed_verdict_json=b"synthetic-lab-verdict",
            verdict_signature_b64url="A" * 86, verdict_issued_at=100,
            verdict_expires_at=130, status="VERIFIED", independent_effect_verified=True,
            finding_verified=True, report_release_approved=False,
        )
        columns = ",".join(row)
        params = ",".join(":" + key for key in row)
        insert = text(f"INSERT INTO independent_target_effect_verifications ({columns}) VALUES ({params})")
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL session_replication_role = replica"))
            await connection.execute(insert, row)

        async with engine.connect() as connection:
            with pytest.raises(Exception):
                await connection.execute(text(
                    "UPDATE independent_target_effect_verifications SET status='UNKNOWN' WHERE id=:id"
                ), {"id": row["id"]})
            await connection.rollback()
            with pytest.raises(Exception):
                await connection.execute(text(
                    "DELETE FROM independent_target_effect_verifications WHERE id=:id"
                ), {"id": row["id"]})
            await connection.rollback()

        # Two concurrent attempts to promote the same immutable challenge:
        # unique challenge, qualification and nonce keys reject duplication.
        async def duplicate_verification(identifier):
            duplicate = {**row, "id": identifier, "finding_id": "different-" + identifier,
                         "verdict_sha256": uuid.uuid4().hex * 2}
            try:
                async with engine.begin() as connection:
                    await connection.execute(text("SET LOCAL session_replication_role = replica"))
                    await connection.execute(insert, duplicate)
                return True
            except Exception:
                return False
        attempts = await asyncio.gather(
            duplicate_verification("itefv-" + "2" * 32),
            duplicate_verification("itefv-" + "3" * 32),
        )
        assert attempts == [False, False]

        # Corrupted candidate cannot promote and a failed transaction must
        # leave the prior verified row byte-for-byte unchanged.
        corrupt = {**row, "id": "itefv-" + "4" * 32,
                   "qualification_id": "qual-corrupt", "challenge_id": "challenge-corrupt",
                   "finding_id": "finding-corrupt", "verifier_nonce_sha256": "2" * 64,
                   "verdict_sha256": "3" * 64, "anonymous_http_status": 200}
        async with engine.connect() as connection:
            with pytest.raises(Exception):
                await connection.execute(text("SET LOCAL session_replication_role = replica"))
                await connection.execute(insert, corrupt)
                await connection.commit()
            await connection.rollback()
            observed = (await connection.execute(text(
                "SELECT count(*), bool_and(report_release_approved = false) "
                "FROM independent_target_effect_verifications"
            ))).one()
            assert observed == (1, True)
    finally:
        if engine is not None:
            await engine.dispose()
        if container is not None:
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
