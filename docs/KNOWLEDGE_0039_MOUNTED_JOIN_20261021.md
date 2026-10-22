# 0039 original user library + Flow-local knowledge: mounted operator join qualification

**Date:** 2026-10-21  
**Status:** **Qualified only with synthetic read-only data; NOT a deployed
PostgreSQL / signed-ROE / production release certification.**

## Actual surface inspected

The existing `src/ai_osop/api/main.py` registers these real routers:

- `operator_global_library.router`: `/operator/library/documents` user-global
  guide/answer/code CRUD, current immutable revision, explicit owner-only GET,
  tombstone and CAS under migration 0039.
- `operator_knowledge.router`: `/flows/{flow_id}/operator-knowledge` per-Flow
  owner, current Flow revision and authorization version; owner-only content
  GET, mutation, search/list under 0019 with 0038 integrity constraints.
- `unified_knowledge_search.router`: `/operator/search/knowledge` joins
  **read-only metadata** results, never merges authorizations or underlying
  storage transactions. It defaults to 0039 only; to add Flow-local it
  requires exact Flow ID, expected Flow revision and authorization version.
  Denied Flow retrieval prevents returning a partial global result.

The UI has `UserLibrary.tsx` with an actual mounted
`OperatorGlobalLibraryPanel` metadata-only unified search; `FlowOperations.tsx`
mounts `OperatorKnowledgePanel`, `FlowResourceAliasesPanel` and
`FlowResourceFoldersPanel` against a selected Flow and pinned revision.
This is **not** a secure join between raw global documents and executable Flow
resources. The library and Flow panels expose distinct workflows; no automatic
copy, signed promotion, agent ingestion, original source-citation review, or
external finding verification is established by these UI mount points.

## New, disjoint qualification

`tests/qualification/test_0039_actual_mounted_operator_join_20261021.py`
tests **the registered `main.app` itself**, not a freshly copied test router
or mocked whole store methods. Its signed local HS256 JWTs are checked by the
production FastAPI dependency. It executes the **actual**:

- `OperatorGlobalLibrary.search/get` SQL construction and SHA-256 projection.
- `OperatorKnowledgeStore.search/list/get`, exact authorization-lineage
  row check and `FlowArtifactStore._fence` owner/tenant/revision checks.
- `unified_knowledge_search._safe_items` metadata-only provenance filtering.

**Deliberate test substitution:** `session_memory._async_session` points to
a strict synthetic `OfflineReadOnly` SQL interpreter that answers only
recognized `SELECT` queries and rejects all writes. Its rows represent
fictional user `operator-owned-0039`, Flow `flow-isolated-0039` and engagement
`eng-isolated-0039`. The real `guard_sql` **was replaced** for this
qualification by a *fake authorization/version check*; it does not verify
Ed25519 signed ROE, a real PostgreSQL row lock, revocation race, production
tenant ownership, or deployment enrollment. The operator revocation ledger is
likewise a fake with a controllable revoked subject. Real OIDC/JWKS, real
database migrations/constraints and runtime provider connections were never
accessed. No actual deployment authenticity is inferred from synthetic JWT
signatures.

### Observations

| Scenario | Observed result and limit |
|---|---|
| Authenticated owner queries both sources | HTTP 200 with distinct `user_global_0039` and `flow_local_0019_0038` source labels, immutable revision and SHA citation metadata; actual 0039 joined-version and Flow knowledge scoped SQL executed, no SQL writes. |
| Global owner and issuer swapped | 0039 SQL filters issuer+hashed principal; foreign user/issuer sees an empty global page. Global search alone executes no Flow document SELECT and does not create Flow authority. |
| Revoked Flow authorization, foreign Flow owner, stale Flow revision, version mismatch | HTTP 403/409 and **no partial global source list** despite global original search having executed. |
| Synthetic Flow tenant changed but owner retained | HTTP 200 with empty Flow items, not a scope error: SQL filters by tenant, so no foreign document leaks. This is not proof that a moved real tenant would have a valid ROE. |
| Flow document owner, tenant or authorization SHA inconsistent with filtered SQL | Flow metadata page empty, no foreign citation returned. An inconsistent row returned **despite** filters is rejected by `OperatorKnowledgeStore._assert_row` with HTTP 409; unified search emits no partial global result. |
| Global original content SHA substituted while underlying bytes unchanged | `OperatorGlobalLibrary._projection` rejects with HTTP 503 and no Flow result. Genuine original SHA is recomputed for global search. |
| Foreign explicit global and Flow document GET | Global returns 404, Flow returns 403, neither contains private text. Owner GET alone exposes inert `content` or `untrusted_content`; unified metadata search never exposes either. |
| Bad, expired or revoked local JWT; viewer role | HTTP 401/403 before any SQL. Signature validation was real local HMAC with a test-only key; revocation was simulated. |
| Untrusted instruction-like content | Neither original body enters unified search results nor is it promoted as target evidence, executable resource, agent context or report. All returned source citations have explicit negative approval/effect flags. |

### Important unresolved integrity observation

An adversarial **synthetic DB result** carrying a syntactically valid but
**incorrect Flow-local SHA-256** and `source_flow_revision=900` while the
requested Flow revision was 4 was accepted as **metadata-only** by the Flow
search and unified allowlist (without any content bytes). The 0039 global
search rejected an equivalent mismatching digest by recomputing original
bytes. For Flow-local search, `_metadata` and `_safe_items` check metadata
shape and owner/authorization lineage but do **not** recompute content digest
or compare `source_flow_revision <= current_flow_revision`.

This is a **source-citation validation gap at the SQL-result trust boundary**,
not a demonstrated live exploit or proved failure of the actual PostgreSQL
0038 constraints. Those constraints and real rows were expressly *not*
exercised. A report/agent/Flow-resource consumer must **not** treat such a
metadata digest alone as independently certified original evidence. Consider
an additional read-time original SHA check and current-source-revision bound
in the Flow store/search boundary, independent of database immutability and
UI checks. The UI unified search client independently checks source revision
against the pinned Flow, but a direct API client does not get that extra
client-side fence.

## Production integration gaps before any readiness claim

1. Qualify `0039` and `0019/0038` against **real isolated PostgreSQL**
   transactions across two app replicas with actual constraints, locks,
   immutable original versions, delete/revision CAS and credential revocation.
   This test was deliberately read-only and cannot substitute for that.
2. Verify real signed ROE from the current authorization store, exact
   engagement/tenant ownership, Flow revision and approval lifecycle, without
   fake `guard_sql` or local JWT-only signer.
3. If exact global content is intentionally moved into Flow-local resources,
   require an **explicit human review and durable source-citation admission**:
   0039 owner+original revision+SHA, receiving tenant/Flow/Task, current
   signed ROE and separate reviewer, immutable bytes readback, tombstone and
   revocation checks, no original source becoming system instructions.
   The present unified endpoint is only discovery, not this bridge.
4. Preserve current negative provenance labels and **deny on partial sources**
   rather than promoting a cached global hit when a Flow-side query is denied.
   The two original stores are not read in one atomic cross-source snapshot;
   a concurrent delete/ROE change between reads remains unresolved.
5. Keep the UI and backend protections distinct: `OperatorGlobalLibraryPanel`
   is an accessible client of unified discovery, not a security boundary or
   independent proof of source owner/target effect. Neither the Flow resource
   alias/folder UI nor its manifests make a user-global note executable.

**Qualification command**

```powershell
poetry run pytest -o addopts='' tests/qualification/test_0039_actual_mounted_operator_join_20261021.py -q --disable-warnings --maxfail=1
```

**Observed:** **8 passed in 18.03 seconds** for the new file. Final adjacent
regression run, combining this new file with existing
`test_library_cross_source_ingestion_boundary_20261021.py`: **16 passed in
16.38 seconds**. Black format check and Python compilation both passed.
These runs used actual mounted routes and store SQL with simulated read-only
database and ROE/ledger fixtures. No application DB, Docker, Git mutation,
external target, scanner, provider or paid API was contacted.
**NOT PRODUCTION CERTIFIED / NOT READY.**

## Later same-day production read-time citation hardening (supersedes gap at lines 71–91)

The original qualification above intentionally demonstrated the *pre-fix*
Flow-local metadata flaw with a SELECT-only synthetic SQL interpreter. Prime
subsequently modified the actual `OperatorKnowledgeStore._assert_row` used by
Flow-local `list`, `search`, `get`, `update`, and `delete`, and added the same
validation after create/update `RETURNING`. Every original row is now checked
for exact tenant/Flow/owner/authorization lineage, an integral
`0 <= source_flow_revision <= current signed Flow revision`, a positive document
revision, and recomputed SHA-256 plus length of its original UTF-8 content
*before projecting any metadata citation*. No untrusted text is promoted to
agent instructions, reports, or target-owner evidence.

The adversarial mounted test now separately substitutes an incorrect digest,
an impossible future Flow revision, and both. It expects fail-closed HTTP
503/409 and **no partial global-source success**. Latest synthetic-mounted and
adjacent knowledge/security suite: **119 passed** with zero failures; Black
checks passed on knowledge store, adversarial test, and readiness files.
This does **not** certify real PostgreSQL 0038 constraint enforcement,
independent host-signed ROE or current original review/ingestion, multi-replica
atomicity, or a functioning target execution workflow.
