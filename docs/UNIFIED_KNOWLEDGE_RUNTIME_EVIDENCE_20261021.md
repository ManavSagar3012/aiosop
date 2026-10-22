# Unified operator knowledge: bounded qualification evidence

Date: **2026-10-21**. This document records qualification of the read-only
`GET /operator/search/knowledge` introduced in
`src/ai_osop/api/routers/unified_knowledge_search.py`. It does **not** certify
production deployment, signed identity enforcement across a real request, or
atomic consistency across knowledge sources.

## Actual implementation traced

The mounted router calls two existing and distinct stores:

| Provenance | Store / migration | Authority used in production |
|---|---|---|
| `user_global_0039` | `OperatorGlobalLibrary.search`; 0039 `operator_global_library_documents` and `operator_global_library_versions` | Issuer plus SHA-256-derived signed principal namespace, current-version join, permanent tombstone filter |
| `flow_local_0019_0038` | `OperatorKnowledgeStore.search`; 0019 `operator_knowledge_documents`, 0038 exact tenant FK/content SHA enforcement | `FlowArtifactStore._fence` owner/session, signed ROE via `guard_sql`, exact Flow revision and current authorization version/SHA, tenant/owner-qualified SQL |

The public result has source labels, SHA-256 and version/revision metadata,
no content or owner identifiers, and explicit `false` flags for agent-context
approval, execution, target-effect verification, reportability, and
`atomic_cross_source_snapshot`. Global search executes first. If an
explicitly requested Flow is denied afterward, the endpoint returns an error,
not a partial global success. The two store reads have separate database
transactions, so **no cross-source atomic snapshot is claimed**.

## New qualification and observed results

Only these two files were added by worker-36:

- `tests/qualification/test_unified_operator_knowledge_real_pg_20261021.py`
- `docs/UNIFIED_KNOWLEDGE_RUNTIME_EVIDENCE_20261021.md`

### Default in-process API/store tests — **synthetic database and Flow fence**

**Observed:** 5 passed, 1 opt-in skipped (final default run); the actual
`OperatorGlobalLibrary.search` and `OperatorKnowledgeStore.search` methods
execute through the actual FastAPI route over a recording, data-filtering
synthetic SQL adapter. The `_operator` dependency and
`OperatorKnowledgeStore._fence` are deliberately simulated, **not
cryptographic proof or production PostgreSQL authorization**.

The final combined offline regression run covering the existing
`tests/test_unified_knowledge_search_20261021.py` plus this new suite
returned **13 passed, 1 opt-in skipped**. This does not add real database
or signed-Flow coverage to the existing router tests.

They verify:

1. Both sources return **only** permitted metadata, original/current SHA,
   global revision 2 and Flow revision lineage; inert source labels and all
   negative effect/agent approval flags are preserved.
2. Owner-global search succeeds without a Flow, omits a tombstoned global
   entry, and uses the separately SHA-derived principal namespace.
3. Another principal's explicit Flow request is denied, with **no partial
   global result**; this is synthetic owner/Flow denial, not a real signed ROE.
4. A corrupt global current SHA is rejected before Flow search, and
   provenance errors are not returned as successful metadata.
5. The **real** `FlowArtifactStore._fence` checks the durable owner row
   before the signed-policy guard is called, checks the exact Flow revision,
   and passes the expected authorization version to `guard_sql`. This
   additional test uses **synthetic SQL rows and an AsyncMock for
   `guard_sql`**, not a real cryptographic signature.
6. Static migration lineage and 0038 composite foreign key are grounded in
   actual local migration source.

### Opt-in independent **real PostgreSQL 16** schema qualification

**Observed:** **1 passed** with explicit opt-in
`OSOP_DISPOSABLE_UNIFIED_KNOWLEDGE_PG=1`, while five in-process cases were
excluded by the targeted `-k` selection. The test initializes its *own*
nonroot PostgreSQL 16 data directory under a private temporary folder,
with `listen_addresses=''`, Unix socket permissions `0700`,
`fsync=on`, `synchronous_commit=on`, and mandatory shutdown in `finally`.
No application database, Docker, external provider, or target is accessed.

The test invokes the **actual online Alembic `upgrade()` functions** for
`0019_operator_knowledge_documents.py`,
`0038_operator_knowledge_integrity.py` and
`0039_operator_global_library.py`, in dependency order. Minimal
`session_states` and `execution_flows` parents are isolated test fixtures,
**not** the full application schema.

The real PG check inserted legitimate UTF-8 Flow and global documents;
verified source metadata, exact stored content SHA/length and own-principal
qualification; enforced 0038 cross-tenant FK `23503` and digest `23514`,
0039 immutable-version digest/trigger `23514`; advanced the global
document to a new immutable current revision; tombstoned it; and verified
the old versions remained but active search excluded the tombstone.
The opt-in subprocess printed `RESULT_UNIFIED_PG16_OK`; the pytest assertion
verified this marker and exited successfully.

**Scope limitation:** real PG tests exercise actual migration DDL and
parameterized SQL statements against those tables. They do **not** run the
production unified FastAPI route or the production signed
`FlowArtifactStore._fence` and `guard_sql` against that disposable cluster.
The default suite calls the real application store search methods, but with
synthetic SQL and authorization. Therefore the combination is evidence of
separate correct boundaries, **not** a joined production signed request.

## Exact commands and safeguards

From the original worktree:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts= -q -rs --tb=short tests/qualification/test_unified_operator_knowledge_real_pg_20261021.py

$env:OSOP_DISPOSABLE_UNIFIED_KNOWLEDGE_PG='1'
try {
  .\.venv\Scripts\python.exe -m pytest -o addopts= -q -rs --tb=short tests/qualification/test_unified_operator_knowledge_real_pg_20261021.py -k opt_in_real_private_nonroot_pg16
} finally {
  Remove-Item Env:OSOP_DISPOSABLE_UNIFIED_KNOWLEDGE_PG -ErrorAction SilentlyContinue
}
```

Default execution is offline and does not start PostgreSQL. The opt-in mode
requires PostgreSQL 16 binaries in Ubuntu WSL or Linux and imports the actual
local Alembic migrations. It creates a fresh private cluster, **never**
uses configured `DATABASE_URL` or connects to an existing service. If these
prerequisites are missing, the opt-in test is an error/failed qualification,
not an invented pass.

Black formatting, Ruff checking, and Python compilation passed on the new
test file. Existing application code, migrations, protected reports and
other tests were not modified.

## Outstanding evidence and integration gaps

- Real signed JWT/OIDC `_operator` checks, durable token revocation and
  real `guard_sql` signed-Flow fencing need a separate isolated full-schema
  test with an independently valid signed ROE. The supplemental
  `FlowArtifactStore._fence` in-process test validates its call ordering and
  version contract with a **mocked** signed guard only.
- The two independent stores do not provide an atomic cross-source snapshot.
  Do not infer simultaneous revocation or single-transaction consistency.
- This is **metadata discovery only**, not RAG, agent prompt ingestion,
  independently reviewed knowledge, vulnerability corroboration or target
  effects.
- The opt-in cluster is a **minimal parent-schema** harness and does not
  establish migration compatibility of the whole application or
  production multi-replica behavior.
