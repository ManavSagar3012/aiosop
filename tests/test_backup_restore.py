"""Tests verifying backup and restore engine capabilities (F-04 and F-15 remediation)."""

from __future__ import annotations

import gzip
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from scripts.ops.restore_database import DatabaseRestoreEngine


class TestDatabaseRestoreEngine:
    @pytest.fixture
    def engine(self) -> DatabaseRestoreEngine:
        return DatabaseRestoreEngine(dry_run=True)

    async def test_restore_postgres_validates_gzip(self, engine: DatabaseRestoreEngine, tmp_path: Path) -> None:
        """Validates that valid gzip SQL archive is accepted and checksum computed."""
        sql_file = tmp_path / "valid_backup.sql.gz"
        content = "CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(100));\n"
        with gzip.open(sql_file, "wt") as gz:
            gz.write(content)

        result = await engine.restore_postgres(sql_file)
        assert result["status"] == "validated"
        assert result["target"] == "postgres"
        assert len(result["checksum"]) == 64
        assert result["size_bytes"] > 0

    async def test_restore_postgres_rejects_empty(self, engine: DatabaseRestoreEngine, tmp_path: Path) -> None:
        """Empty archive is rejected."""
        empty_file = tmp_path / "empty.sql.gz"
        empty_file.write_bytes(b"")
        with pytest.raises(ValueError, match="empty or corrupted"):
            await engine.restore_postgres(empty_file)

    async def test_restore_redis_validates_rdb(self, engine: DatabaseRestoreEngine, tmp_path: Path) -> None:
        """Validates that valid Redis RDB format with REDIS magic header is accepted."""
        rdb_file = tmp_path / "dump.rdb"
        # Redis RDB starts with 'REDIS' followed by 4-digit version
        rdb_content = b"REDIS0009\xfa\x09redis-ver\x057.0.0\xff\x00\x00\x00\x00\x00\x00\x00\x00"
        rdb_file.write_bytes(rdb_content)

        result = await engine.restore_redis(rdb_file)
        assert result["status"] == "validated"
        assert result["target"] == "redis"
        assert len(result["checksum"]) == 64

    async def test_restore_redis_rejects_corrupted_magic(self, engine: DatabaseRestoreEngine, tmp_path: Path) -> None:
        """Corrupted Redis RDB file without REDIS magic header is rejected."""
        corrupt_file = tmp_path / "corrupt.rdb"
        corrupt_file.write_bytes(b"NOT_REDIS_SNAPSHOT_DATA_CORRUPT")
        with pytest.raises(ValueError, match="Invalid Redis RDB magic header"):
            await engine.restore_redis(corrupt_file)

    async def test_restore_neo4j_validates_dump(self, engine: DatabaseRestoreEngine, tmp_path: Path) -> None:
        """Validates Neo4j archive checksum and size."""
        dump_file = tmp_path / "neo4j.dump"
        dump_file.write_bytes(b"NEO4J_DUMP_FORMAT_DATA_RECORD_BLOCK" * 10)

        result = await engine.restore_neo4j(dump_file)
        assert result["status"] == "validated"
        assert result["target"] == "neo4j"
        assert len(result["checksum"]) == 64

    async def test_restore_postgres_live_execution(self, tmp_path: Path) -> None:
        """Non-dry-run restore executes connectivity check via sqlalchemy text()."""
        engine = DatabaseRestoreEngine(dry_run=False)
        sql_file = tmp_path / "prod_backup.sql.gz"
        with gzip.open(sql_file, "wt") as gz:
            gz.write("SELECT 1;\n")

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=MagicMock(scalar_one=lambda: 1))
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_engine.dispose = AsyncMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=mock_engine):
            result = await engine.restore_postgres(sql_file, target_uri="postgresql+asyncpg://osop:osop@localhost/osop")
            assert result["status"] == "restored"
            mock_conn.execute.assert_awaited_once()
