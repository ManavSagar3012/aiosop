# AI-OSOP Database Migrations

This directory contains Alembic migrations for the PostgreSQL schema.

## Setup

```bash
poetry add alembic
```

## Create a new migration

```bash
alembic revision -m "description"
```

## Run migrations

```bash
# Upgrade to latest
alembic upgrade head

# Upgrade by one revision
alembic upgrade +1

# Downgrade
alembic downgrade -1

# Current revision
alembic current

# History
alembic history
```

## Migration validation (CI gate)

```bash
# Verify no migration drift
alembic check
```

## Existing deployments

If your database was created before `created_by` was added:

```bash
alembic upgrade 0002
```

New deployments should run:

```bash
alembic upgrade head
```

## Schema tables

| Table | Purpose |
|-------|---------|
| `session_states` | Engagement sessions (warm storage) |
| `tasks` | Task queue persistence |
| `approval_requests` | Approval workflow state |
| `audit_logs` | Tamper-evident audit trail |
| `user_sessions` | Captured browser sessions |
