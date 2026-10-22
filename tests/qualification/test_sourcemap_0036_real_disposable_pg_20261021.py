"""Opt-in *real disposable PostgreSQL* validation of SourceMap 0036 CHECK.

Exercises the literal migration SQL predicate and PostgreSQL locking/check
behavior on an ephemeral, unprivileged UNIX-SOCKET-ONLY PG 16 server. This is
NOT the full Alembic migration, application DB, 0029 issuer, 0033 supervisor,
or any provider effect. Run explicitly with OSOP_DISPOSABLE_0036_PG=1.
"""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[2]
_MIGRATION = _ROOT / "migrations/versions/0036_sourcemap_native_grant_pair.py"
_BIN = Path("/usr/lib/postgresql/16/bin")


def _constant(name: str) -> str:
    tree = ast.parse(_MIGRATION.read_text(encoding="utf-8"))
    matches = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id == name
    ]
    assert len(matches) == 1
    value = ast.literal_eval(matches[0])
    assert isinstance(value, str) and len(value) <= 2000
    assert re.fullmatch(r"[A-Za-z0-9_,()' =.-]+", value)
    return value


def _command(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True, timeout=35, **kwargs)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux disposable PG only")
def test_literal_0036_pair_check_and_one_use_constraints_in_real_postgresql() -> None:
    if os.getenv("OSOP_DISPOSABLE_0036_PG") != "1":
        pytest.skip("Explicit opt-in OSOP_DISPOSABLE_0036_PG=1 required")
    if os.geteuid() == 0:
        pytest.skip("Do not run disposable PostgreSQL as root")
    if any(not (_BIN / name).is_file() for name in ("initdb", "pg_ctl", "psql")):
        pytest.skip("Standalone PostgreSQL 16 server binaries unavailable")

    original = _constant("_ORIGINAL")
    paired = _constant("_PAIRWISE")
    assert "source-map-mcp" in paired and "inspect_local_original_sourcemap" in paired
    with tempfile.TemporaryDirectory(prefix="osop-disposable-0036-", dir="/tmp") as temp:
        root = Path(temp)
        data = root / "data"
        log = root / "postgres.log"
        # Isolation: private directory, *no TCP listener*, no application DB,
        # and a newly initialized cluster torn down before tempdir removal.
        os.chmod(root, 0o700)
        init = _command(
            [
                str(_BIN / "initdb"),
                "-D",
                str(data),
                "-A",
                "trust",
                "-U",
                "osop_disposable",
                "--no-instructions",
            ]
        )
        assert init.returncode == 0, init.stderr[-600:]
        started = False
        try:
            startup = _command(
                [
                    str(_BIN / "pg_ctl"),
                    "-D",
                    str(data),
                    "-l",
                    str(log),
                    "-o",
                    (
                        "-c listen_addresses='' "
                        f"-c unix_socket_directories={root} "
                        "-c unix_socket_permissions=0700 "
                        "-c port=55436 -c fsync=on -c synchronous_commit=on"
                    ),
                    "-w",
                    "-t",
                    "20",
                    "start",
                ]
            )
            assert startup.returncode == 0, startup.stderr[-600:]
            started = True

            def psql(sql: str, *, success: bool = True) -> str:
                result = _command(
                    [
                        str(_BIN / "psql"),
                        "-X",
                        "-A",
                        "-t",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-h",
                        str(root),
                        "-p",
                        "55436",
                        "-U",
                        "osop_disposable",
                        "-d",
                        "postgres",
                        "-c",
                        sql,
                    ]
                )
                if success:
                    assert result.returncode == 0, result.stderr[-700:]
                else:
                    assert result.returncode != 0
                return result.stdout.strip()

            assert psql("SHOW listen_addresses") == ""
            assert (root / ".s.PGSQL.55436").is_socket()
            psql(
                "CREATE TABLE native_mcp_execution_grants ("
                "server_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
                "side_effect_class TEXT NOT NULL, action_id TEXT UNIQUE NOT NULL, "
                "request_id TEXT UNIQUE NOT NULL, "
                f"CONSTRAINT ck_native_mcp_grant_inert_tool CHECK ({original}))"
            )
            psql(
                "INSERT INTO native_mcp_execution_grants VALUES "
                "('recon-mcp','authority_status','READ_ONLY','act-go','req-go')"
            )
            # Original SQL admits unrelated inert identities, so 0036 must
            # refuse to mutate until a current-table precheck has cleared.
            psql(
                "INSERT INTO native_mcp_execution_grants VALUES "
                "('unknown-mcp','authority_status','READ_ONLY','act-foreign','req-foreign')"
            )
            assert (
                psql(
                    "SELECT EXISTS (SELECT 1 FROM native_mcp_execution_grants "
                    f"WHERE NOT ({paired}))"
                )
                == "t"
            )
            psql("DELETE FROM native_mcp_execution_grants WHERE action_id='act-foreign'")
            assert (
                psql(
                    "SELECT EXISTS (SELECT 1 FROM native_mcp_execution_grants "
                    f"WHERE NOT ({paired}))"
                )
                == "f"
            )

            # Apply the literal same paired predicate in a REAL PostgreSQL
            # transactional DDL critical section as the additive migration.
            psql(
                "BEGIN; SET LOCAL lock_timeout='5s'; "
                "LOCK TABLE native_mcp_execution_grants IN ACCESS EXCLUSIVE MODE; "
                "ALTER TABLE native_mcp_execution_grants "
                "DROP CONSTRAINT ck_native_mcp_grant_inert_tool; "
                "ALTER TABLE native_mcp_execution_grants ADD CONSTRAINT "
                f"ck_native_mcp_grant_inert_tool CHECK ({paired}); COMMIT"
            )
            constraint = psql(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname='ck_native_mcp_grant_inert_tool'"
            )
            assert "source-map-mcp" in constraint
            psql(
                "INSERT INTO native_mcp_execution_grants VALUES "
                "('source-map-mcp','inspect_local_original_sourcemap',"
                "'READ_ONLY','act-source','req-source')"
            )

            # Two actual independent psql client processes racing for the
            # same original Action get exactly one database winner. This is
            # scoped to the disposable grant-table uniqueness, NOT a full
            # production 0027/0029 issue/redemption or cross-replica test.
            def race_one(number: int) -> subprocess.CompletedProcess[str]:
                return _command(
                    [
                        str(_BIN / "psql"),
                        "-X",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-h",
                        str(root),
                        "-p",
                        "55436",
                        "-U",
                        "osop_disposable",
                        "-d",
                        "postgres",
                        "-c",
                        "INSERT INTO native_mcp_execution_grants VALUES "
                        "('source-map-mcp','inspect_local_original_sourcemap',"
                        f"'READ_ONLY','act-race','req-race-{number}')",
                    ]
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(race_one, (1, 2)))
            assert sum(item.returncode == 0 for item in outcomes) == 1
            assert (
                psql(
                    "SELECT count(*) FROM native_mcp_execution_grants " "WHERE action_id='act-race'"
                )
                == "1"
            )
            for server, tool, klass in (
                ("source-map-mcp", "authority_status", "READ_ONLY"),
                ("recon-mcp", "inspect_local_original_sourcemap", "READ_ONLY"),
                ("source-map-mcp", "inspect_local_original_sourcemap", "RECON_ACTIVE"),
                ("unknown-mcp", "authority_status", "READ_ONLY"),
            ):
                psql(
                    "INSERT INTO native_mcp_execution_grants VALUES "
                    f"('{server}','{tool}','{klass}','act-bad','req-bad')",
                    success=False,
                )
            # Original uniqueness survives constraint replacement and still
            # fences the exact same Action / request under real PostgreSQL.
            psql(
                "INSERT INTO native_mcp_execution_grants VALUES "
                "('recon-mcp','authority_status','READ_ONLY','act-source','req-other')",
                success=False,
            )
            psql(
                "INSERT INTO native_mcp_execution_grants VALUES "
                "('recon-mcp','authority_status','READ_ONLY','act-other','req-source')",
                success=False,
            )
            # Downgrade must not discard existing SourceMap rows.
            assert (
                psql(
                    "SELECT EXISTS (SELECT 1 FROM native_mcp_execution_grants "
                    "WHERE server_id='source-map-mcp')"
                )
                == "t"
            )
            # Remove both fixture-only SourceMap rows (the original and the
            # independent-process race winner) before restoring the old CHECK.
            psql("DELETE FROM native_mcp_execution_grants WHERE server_id='source-map-mcp'")
            psql(
                "BEGIN; LOCK TABLE native_mcp_execution_grants IN ACCESS EXCLUSIVE MODE; "
                "ALTER TABLE native_mcp_execution_grants DROP CONSTRAINT "
                "ck_native_mcp_grant_inert_tool; "
                "ALTER TABLE native_mcp_execution_grants ADD CONSTRAINT "
                f"ck_native_mcp_grant_inert_tool CHECK ({original}); COMMIT"
            )
            psql(
                "INSERT INTO native_mcp_execution_grants VALUES "
                "('source-map-mcp','inspect_local_original_sourcemap',"
                "'READ_ONLY','act-rejected','req-rejected')",
                success=False,
            )
        finally:
            if started:
                shutdown = _command(
                    [str(_BIN / "pg_ctl"), "-D", str(data), "-w", "-m", "fast", "stop"]
                )
                assert shutdown.returncode == 0, shutdown.stderr[-600:]
