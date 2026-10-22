# Operator knowledge and independent user library: PentAGI parity checkpoint

**Date:** 2026-10-21. **Release verdict:** NOT PRODUCTION CERTIFIED / NOT READY.

This checkpoint analyzes the original heavily dirty `/burp_mcp/ai-osop`
working tree. Upstream comparison uses the **pinned PentAGI v2.2.0** source
inventory in `docs/PENTAGI_PARITY_INVENTORY_20261016.md`, including its
**2026-10-16 historically sampled `main`**. That inventory found matching Git
blobs only for named paths. We have **not** freshly fetched or verified moving
`main` and do not assert current upstream branch equivalence.

## Verified code paths and distinct semantics

| Capability | Shipped source in this original tree | Evidence grade / limitation |
| --- | --- | --- |
| Original Flow-local notes | `migrations/versions/0019_operator_knowledge_documents.py`; `src/ai_osop/memory/operator_knowledge.py`; `api/routers/operator_knowledge.py` | Authenticated owner can create/list/search/get/update/delete bounded inert `guide/answer/code` text under a particular signed Flow, tenant, expected Flow revision and authorization version. This is not user-global. |
| Flow-local ownership and revocation | `FlowArtifactStore._fence` checks `execution_flows` → durable session `created_by` under `FOR SHARE`, `guard_sql` current signed authorization/version, and exact Flow revision/status under `FOR SHARE` or `FOR UPDATE` for writes | No demonstrated senior reviewer bypass: the durable **session creator must equal request owner**, even for seniors. Revoked signed policy fails before document SQL. Fake-SQL checks exercise call order and result branches, not cryptographic verification. |
| Hardening after migration 0019 | `migrations/versions/0038_operator_knowledge_integrity.py` | Later additive migration checks preexisting rows and introduces composite `(flow_id, engagement_id)` FK and exact PostgreSQL UTF-8 content SHA-256 CHECK. Earlier raw-0019-only test deliberately demonstrates the gaps before 0038; that test cannot be read as a present-state bypass of 0038. Other worker independently qualified 0019/0038 Alembic Operations on a disposable PostgreSQL instance, not the full app. |
| Independent user-owned library | **Pre-existing at this checkpoint** `migrations/versions/0039_operator_global_library.py`, `memory/operator_global_library.py`, `api/routers/operator_global_library.py`, registered in `api/main.py` | Distinct from Flow-local notes. Persistent issuer/subject owner, bounded CRUD and literal search, append-only original versions, SHA verification, exact revision CAS and tombstones are implemented. Checked-in 0039 qualification exercises SQL/Alembic using disposable PostgreSQL with a synthetic fixture. This is useful *partial* parity, not a claim of user-global RAG behavior. |
| Additional strict user boundary | New `memory/user_knowledge_library.py` with `tests/test_user_knowledge_library_20261021.py` | Opt-in service facade reuses 0039, requires signed current JWT/OIDC through `verify_token` with durable credential revocation enforcement enabled; no Flow alias, database duplication, new migration or registered production route. Reads also recheck principal after fetching. Current global router remains the active API; this facade is **not** automatically wired into it. |

## Upstream comparison, pinned to reviewed evidence

PentAGI **v2.2.0** exposes independently managed user Knowledge CRUD/search in
`backend/pkg/server/services/knowledge.go` (`ListDocuments`, `GetDocument`,
`SearchDocuments`, `CreateDocument`, `UpdateDocument`, `DeleteDocument`) and
corresponding `frontend/src/pages/knowledges/knowledges.tsx`, while
`backend/pkg/tools/memory.go` searches memory/guide/answer/code. Those named
upstream paths were also sampled as matching `main` on **2026-10-16 only**.
See inventory rows 6, 7, 8 and 13; links are pinned to
`https://github.com/vxcontrol/pentagi/tree/v2.2.0`.

The historical inventory classified AI-OSOP's independent user KB as missing
on 2026-10-16; **as of this checkpoint 0039 changes that assessment**:
owner-scoped global CRUD with append-only content versions now exists and the
FastAPI router is registered. A distinct complete PentAGI-equivalent semantic
knowledge/RAG system, production UI knowledge-management route, embedding
pipeline, reviewer-bound retrieval, and source/version revocation propagation
to long-running agents **are still absent or unqualified**. Search in 0039 is
bounded PostgreSQL case-insensitive literal substring matching; it is not
vector retrieval, independent human review or permission for model ingestion.
No checked `ui/src` React consumer of `/operator/library` appeared in the
inspected working tree; the FastAPI route alone does not establish UI parity.

## Executed authorization and SQL contracts

- New `tests/qualification/test_operator_knowledge_store_sql_contract_20261021.py`
  invokes actual original `FlowArtifactStore._fence` with a recording DB and
  a mocked signed verifier, exercising owner mismatch before verifier, revoked
  verification before knowledge queries, stale Flow revision/status, signed
  authorization digest, scoped select/count/insert, revision CAS/failed update,
  tombstone delete and forbidden foreign/corrupt content reads. It inspects
  executable SQL text and bound values from actual store calls.
- Earlier `tests/qualification/test_operator_knowledge_real_disposable_pg_20261021.py`
  applies **migration-0019-derived** SQL to a disposable Unix-socket PG16 and
  uses two independent `psql` processes for revision CAS. It does **not** run
  full SQLAlchemy/0038/0039 or original signed cryptography; 0038 closes the
  earlier independent-FK and malformed-content-digest holes at database level.
- New `tests/test_user_knowledge_library_20261021.py` checks strict issuer
  and subject isolation, signer/role/credential denial, disabled or unavailable
  revocation ledger, mid-read revocation refusal, delegated CRUD parameters,
  and inert exact-version/digest matching with no agent-context promotion.

### Demonstrable limitations and safe next integration

1. **Flow revision lineage:** The Flow-local `_assert_row` checks tenant,
   Flow, durable owner, authorization version and authorization SHA, while
   returning `source_flow_revision` as provenance. It does not require stored
   `source_flow_revision` to equal the currently requested Flow revision.
   Therefore a note created under an earlier Flow revision can remain readable
   after a revision increment if the current signed authorization and owner
   still verify. Whether historical notes should remain readable is a product
   decision; this is not presently evidence of a signed-policy bypass.
2. **Create idempotence:** The Flow-local create path generates a fresh UUID
   and has no client operation idempotency key. A client retry after an UNKNOWN
   response may yield duplicate notes; count admission is serialized by the
   Flow write lock but does not deduplicate content. 0039 also uses new ids
   for global create. Add an immutable request-key CAS ledger before promising
   retry-safe create.
3. **Global credential revocation:** The registered global router uses the
   signed `_operator` dependency, which calls `verify_token` and its configured
   revocation check. The optional new user-library facade *requires* that
   enforcement be enabled, but revocation check and 0039 mutation execute in
   **separate transactions**. A concurrent revocation can race a write. Do
   not claim atomic credential revocation or distributed consistency without
   a same-transaction principal-revocation lock and live multi-client test.
4. **Human review and retrieval:** Neither operator knowledge source becomes
   reviewed agent context merely by writing a doc, verifying the SHA or
   returning HTTP 200. Build an additive signed human review of exact `0039`
   `document_id + revision + SHA + issuer/subject` in a durable transactional
   ledger. Bind review to the current principal and original Task/Flow/signed
   ROE at inference time; deny on tombstone, revision change, reviewer
   revocation or missing current review. Only after this implement bounded
   embeddings/search indexes with source SHA/provenance, deletion/revocation
   invalidation and the existing model budget/authorization controls. Test
   multiple independent database clients and rejection of prompt injections.
5. **No verified target-side or fleet E2E:** None of these tests prove a real
   browser/MCP provider, target ownership, exploit outcome, production API
   deployment, full 11-service integration or independently signed senior
   release. Keep those release claims denied.

**Observed status:** The existing Flow fence showed no verified forged-owner,
foreign-tenant or senior-reviewer bypass in the scoped SQL tests. Missing
review/RAG admission is a known capability gap, and the strongest currently
justified claim is authenticated inert, durable knowledge CRUD with partial
real PostgreSQL schema qualification.
