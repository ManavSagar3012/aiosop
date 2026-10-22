"""Real separate-process PostgreSQL one-use proof admission qualification.

The only permitted URL is the explicitly named disposable loopback container
`osop-proof-pg-20261016` on port 65488. No application database is opened.
"""

import asyncio
import os
from urllib.parse import urlsplit

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from ai_osop.memory.target_authority_receipts import TargetAuthorityReplayGuard


@pytest.mark.asyncio
async def test_live_disposable_postgres_atomic_nonce_claim_and_rollback() -> None:
    url = os.environ.get("OSOP_DISPOSABLE_NONCE_DB", "")
    uri = urlsplit(url)
    if not url:
        pytest.skip("Explicit disposable database URL is required")
    if (
        uri.scheme != "postgresql+asyncpg"
        or uri.hostname != "127.0.0.1"
        or uri.port != 65488
        or uri.path != "/postgres"
        or uri.username != "postgres"
    ):
        pytest.fail("Refusing a database outside the dedicated disposable container")
    engine = create_async_engine(url, pool_size=3, max_overflow=0)
    try:
        async with engine.begin() as db:
            await db.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS target_authority_nonce_receipts (
                    id varchar(64) PRIMARY KEY,
                    engagement_id varchar(64) NOT NULL,
                    flow_id varchar(64) NOT NULL,
                    key_id varchar(64) NOT NULL,
                    nonce_sha256 varchar(64) NOT NULL,
                    proof_sha256 varchar(64) NOT NULL,
                    UNIQUE (engagement_id,flow_id,key_id,nonce_sha256)
                )
            """
                )
            )

        async def attempt(nonce: str) -> bool:
            async with engine.begin() as db:
                return await TargetAuthorityReplayGuard(db).claim_once(
                    engagement_id="eng-disposable",
                    flow_id="flow-disposable",
                    key_id="independent-target",
                    nonce=nonce,
                    proof_sha256="f" * 64,
                )

        # Independent physical PG connections contend for the same immutable
        # nonce identity; only one process/connection can admit it.
        first, second = await asyncio.gather(
            attempt("1234567890abcdef1234567890abcdef"),
            attempt("1234567890abcdef1234567890abcdef"),
        )
        assert sorted((first, second)) == [False, True]

        # A failed higher-level authorization must roll back the reservation.
        async with engine.connect() as db:
            tx = await db.begin()
            assert await TargetAuthorityReplayGuard(db).claim_once(
                engagement_id="eng-disposable",
                flow_id="flow-disposable",
                key_id="independent-target",
                nonce="fedcba0987654321fedcba0987654321",
                proof_sha256="f" * 64,
            )
            await tx.rollback()
        assert await attempt("fedcba0987654321fedcba0987654321") is True
    finally:
        await engine.dispose()
