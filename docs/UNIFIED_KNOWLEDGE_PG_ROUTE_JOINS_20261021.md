# Mounted unified operator knowledge — joined PostgreSQL runtime evidence

**Date:** 2026-10-21  
**Worker:** 36, disjoint qualification  
**Release disposition:** **Not production certified.**

## Owned changes

Only these **new** files belong to this assignment:

- `tests/qualification/test_unified_knowledge_mounted_pg_integration_20261021.py`
- `docs/UNIFIED_KNOWLEDGE_PG_ROUTE_JOINS_20261021.md`

No production code, existing migrations, existing tests, other workers'
reports, application database, Docker configuration, providers, scan targets,
or Git state were modified.

## Evidence scope: actual mounted FastAPI + actual PostgreSQL 16

The opt-in test imports the **actual** `ai_osop.api.main.app`, confirming
exactly one mounted `GET /operator/search/knowledge`. It invokes that
same application with Starlette `TestClient` **without starting the
application lifespan**; no Redis/Neo4j/MCP/LLM/agent dependencies are
started. Request handling runs the production route, its
`flow_artifacts._operator` bearer dependency, `deps.verify_token`,
`OperatorGlobalLibrary.search`, `OperatorKnowledgeStore.search`,
`FlowArtifactStore._fence`, and `authorization_store.guard_sql`.

**Real signing:** Each run generates a temporary in-process Ed25519 private
key solely for its synthetic, non-target `example.test` policy and enrolls
only its public key through the existing `OSOP_ROE_TRUSTED_KEYS_JSON`
contract. Its canonical policy/signature is validated using the production
`verify_signed_roe` verifier, then stored in a real
`signed_authorizations` row. `guard_sql` independently re-verifies the
*current* signature, policy scope/ROE, owner, validity window, approval
version, current status, and durable owner state during the Flow store's
read transaction. A separate fixture HMAC JWT secret signs local operator
JWTs; production `verify_token` genuinely verifies them, without overriding
the route's authentication dependency. Both signer secrets exist **only**
inside the opt-in test process; these are synthetic identities, **not**
real external identity-provider credentials or production approval.

**Actual migrations and persistence:** A separate nonroot Ubuntu WSL
PostgreSQL **16** server is initialized in a randomly named `0700`
temporary directory, with `listen_addresses=''` (no TCP), a private
`0700` Unix socket, `fsync=on`, and `synchronous_commit=on`.
Actual online Alembic `upgrade()` functions for revisions **0009,
0014, 0019, 0038, and 0039** run against minimum PostgreSQL parent tables
`session_states` and `execution_flows`. These minimal parent tables are
**not** a migration of the application's complete production schema.

Windows has the project's working FastAPI/Pydantic dependency wheels,
whereas WSL Python cannot import `pydantic_core._pydantic_core` from the
Windows wheel. Rather than inventing a Linux FastAPI installation, the
test implements a small controlled stdio adapter between the Windows-mounted
ASGI process and a persistent psycopg connection inside the newly started
WSL PostgreSQL instance. Real application SQLAlchemy statement objects are
compiled with PostgreSQL named placeholders and executed as parameterized
SQL in the same DB transaction across each store's fence/query sequence.
This is **real PostgreSQL, real store code and real mounted API logic**, but
it is **not** the deployed SQLAlchemy async-driver/runtime, a full
application-lifespan deployment, or multi-replica qualification.

## Observed assertions

1. Actual application route registration and unauthenticated `401`.
2. Signed operator-A JWT + live, independently signed Ed25519
   current `0009` ROE + matching SQL Flow owner, revision 4, authorization
   version 7: HTTP **200**, one `user_global_0039` and one
   `flow_local_0019_0038` item with exact current SHA-256, provenance,
   revision/version metadata and no content, owner/engagement identifiers,
   target proof or agent-context authority.
3. Different, cryptographically valid operator-B JWT attempting operator-A
   Flow: **403**, with no partial global success. Operator-A global-only
   query: **200**; operator-B own global query has **no** A documents.
4. Stale expected Flow revision: **409**. Incorrect current signed
   authorization version: **403**.
5. Forged HMAC JWT: **401**. Removal of the currently enrolled Ed25519
   public trust root while the signature remains in PG: Flow **403**;
   independently owned global-only search still **200**. Re-enrollment of
   the legitimate test root restores Flow access.
6. Real 0038 content digest CHECK rejects wrong SHA with PostgreSQL
   SQLSTATE **23514**. With a different, *existing* engagement parent,
   the composite Flow/engagement foreign key rejects cross-tenant knowledge
   reassignment with **23503**.
7. Real 0039 immutable versions: append revision 2, advance `current_revision`
   through the database, verify unified search returns only the new SHA,
   then tombstone the document and verify global search becomes empty while
   Flow-local material still remains visible.
8. Persisted token-digest revocation returns **401** for the exact JWT.
   A distinct valid JWT remains accepted until a durable
   `operator_subject_controls.disabled=true` record is committed, then
   returns **401**. Re-enabling the subject restores this distinct token.
   Finally, changing current signed ROE status to `revoked` causes a fresh
   signed JWT Flow request to return **403** while global-only lookup
   remains **200**.

All two-source results have
`atomic_cross_source_snapshot=false`, `synthesis_performed=false`,
`approved_for_agent_context=false`, `independent_target_effect_verified=false`,
`safe_for_execution=false`, and `reportable=false`.
**No atomic cross-source snapshot** is guaranteed: global and Flow stores
run separate database transactions, even though this test uses one database.
They are separate trust domains; a successful global lookup does not confer
Flow authorization or approval to use a document in agent prompts.

## Actual commands, outcomes and earlier failure

Commands from original repository root, Windows virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts= -q -rs --tb=short tests/qualification/test_unified_knowledge_mounted_pg_integration_20261021.py
```

**Default result:** 1 passed, 1 skipped (isolated PG requires opt-in).

Additional offline regression command:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts= -q -rs --tb=short tests/test_unified_knowledge_search_20261021.py tests/qualification/test_unified_operator_knowledge_real_pg_20261021.py tests/qualification/test_unified_knowledge_mounted_pg_integration_20261021.py
```

**Observed:** **15 passed, 2 skipped** (the two independent PostgreSQL
opt-in suites remained deliberately disabled for the offline run).

```powershell
$env:OSOP_PRIVATE_UNIFIED_MOUNTED_PG16='1'
try {
    .\.venv\Scripts\python.exe -m pytest -o addopts= -q -rs --tb=short tests/qualification/test_unified_knowledge_mounted_pg_integration_20261021.py
} finally {
    Remove-Item Env:OSOP_PRIVATE_UNIFIED_MOUNTED_PG16 -ErrorAction SilentlyContinue
}
```

**Final opt-in result:** **2 passed in 30.64 seconds** against an actually
initialized and stopped private PG16 cluster.

`black --check`, `ruff check`, and `compileall -q` on the new test
file also all passed.

An earlier opt-in attempt **failed**, because initial test fixture inserts
put the 0039 document and referenced version into *separate* transactions,
and PostgreSQL correctly rejected that with the deferrable current-revision
FK. The test fixture was fixed to insert both in the **same** transaction;
the subsequent opt-in tests passed. This was a genuine fixture error, not
proof of an application defect, and the failed run is **not** counted as a
passing qualification.

## Important limits and outstanding work

- JWT and Ed25519 signatures are **real cryptographic operations with
  ephemeral test keys**, not a production identity-provider enrollment or
  externally authorized ROE. The test never authorizes or contacts a target.
- The PostgreSQL cluster and app are coupled by a bounded stdio SQL adapter,
  **not** a deployed Linux FastAPI runtime or the production async DB driver.
- Minimal parent tables mean this does **not** certify full application
  migration compatibility, lifespan orchestration, replica fencing,
  background executors, or deployment wiring.
- The two queries are **not** one atomic transaction or consistent snapshot;
  source metadata can change between the sequential reads.
- This is inert operator text retrieval, **not** RAG ingestion, reviewed
  trusted context, verified exploitation, independent target-effect evidence,
  or a production release certificate.
