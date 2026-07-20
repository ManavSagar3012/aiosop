# Operational Runbook: Applying migration 0004 to an existing database

## Background

Commit `9c41df9` added ORM columns that the application now queries at runtime:

- `outbox.attempt_count`, `outbox.dlq` (DLQ retry path, issue #12)
- `audit_logs.archived`, `audit_logs.archived_at` (soft-delete retention, issue #15)

The application creates schema via `Base.metadata.create_all`, which creates
**missing tables** but never adds **columns to tables that already exist**. Any
database provisioned before `9c41df9` therefore has `outbox` / `audit_logs`
**without** these columns, and the new code raises `UndefinedColumn` in the
outbox processor and retention service.

Migration `0004` (`migrations/versions/0004_add_dlq_and_soft_delete_columns.py`)
adds the columns + indexes and backfills existing rows (`dlq=false`,
`archived=false`, `attempt_count=0`) so they satisfy the hot-path predicates
`dlq == false` / `archived == false`.

## Who is affected

Any environment where the tables exist but the columns are missing. Detect it:

```bash
# missing columns? (expects: attempt_count, dlq / archived, archived_at)
docker exec ai-osop-postgres psql -U "$OSOP_POSTGRES_USER" -d "$OSOP_POSTGRES_DB" -tAc \
  "SELECT column_name FROM information_schema.columns
   WHERE table_name IN ('outbox','audit_logs')
     AND column_name IN ('attempt_count','dlq','archived','archived_at') ORDER BY 1;"

# has alembic ever stamped this DB? NULL => built by create_all, never migrated
docker exec ai-osop-postgres psql -U "$OSOP_POSTGRES_USER" -d "$OSOP_POSTGRES_DB" -tAc \
  "SELECT to_regclass('public.alembic_version');"
```

If the four columns are absent, this DB needs the procedure below.

## Procedure

The DB host URI must be reachable from wherever alembic runs. On dev hosts the
container port is remapped to `15432` (see `docker-compose.yml`), so use
`127.0.0.1:15432`; inside the docker network use `postgres:5432`.

```bash
export OSOP_POSTGRES_URI="postgresql+asyncpg://<user>:<pass>@127.0.0.1:15432/<db>"
```

### Case A — `alembic_version` is NULL (DB built entirely by create_all)

The schema already matches the `1e010edbfecb` baseline (all tables +
`session_states.created_by` + `session_states.last_accessed` + `dlq_entries`),
so **stamp** that baseline, then upgrade — this runs only `0004`.

```bash
# 1) confirm the baseline schema really is present before stamping
docker exec ai-osop-postgres psql -U "$OSOP_POSTGRES_USER" -d "$OSOP_POSTGRES_DB" -tAc \
  "SELECT to_regclass('public.dlq_entries'),
          (SELECT 1 FROM information_schema.columns
            WHERE table_name='session_states' AND column_name='last_accessed');"
# expect: dlq_entries|1

# 2) stamp baseline (records version only, no DDL)
python -m alembic -c alembic.ini stamp 1e010edbfecb

# 3) upgrade (runs 0004 only)
python -m alembic -c alembic.ini upgrade head
```

### Case B — `alembic_version` exists and is behind `0004`

Normal migrated DB. Just upgrade:

```bash
python -m alembic -c alembic.ini upgrade head
```

## Verification

```bash
python -m alembic -c alembic.ini current   # -> 0004 (head)

docker exec ai-osop-postgres psql -U "$OSOP_POSTGRES_USER" -d "$OSOP_POSTGRES_DB" -tAc \
  "SELECT count(*) FROM outbox WHERE dlq IS NULL;"          # -> 0
docker exec ai-osop-postgres psql -U "$OSOP_POSTGRES_USER" -d "$OSOP_POSTGRES_DB" -tAc \
  "SELECT count(*) FROM audit_logs WHERE archived IS NULL;" # -> 0
```

Non-zero NULL counts mean the backfill did not apply — investigate before
relying on the outbox/retention paths.

## Rollback

`0004` is additive and reversible:

```bash
python -m alembic -c alembic.ini downgrade 1e010edbfecb
```

This drops the four columns + their indexes. Note the running application code
expects the columns, so only downgrade after reverting to a pre-`9c41df9` build.

## Notes

- The migration is guarded (each add is inspected against live schema) and
  idempotent, so re-running `upgrade head` is safe.
- It is portable across PostgreSQL and SQLite; the automated coverage in
  `tests/test_migration_0004.py` exercises upgrade/backfill/downgrade and both
  guard paths against throwaway SQLite DBs.
