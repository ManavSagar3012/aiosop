# Knowledge workflows: source-to-agent/report trust boundary and PentAGI gaps

**Date:** 2026-10-21  
**Scope:** original shared, heavily dirty `/burp_mcp/ai-osop`  
**Disposition:** Partial implementation, **NOT** PentAGI feature parity or a production/RAG/release certificate.

## Reference provenance — keep dates and evidence grades separate

This bounded continuation inspected **current local AI-OSOP Python code** and
ran the **actual FastAPI production router objects** with controlled offline
stores and real ephemeral local HMAC JWT validation. It did **not** contact
PentAGI upstream again. The upstream comparison is the prior
`docs/PENTAGI_PARITY_INVENTORY_20261016.md`: **pinned PentAGI v2.2.0** and
only **named, historically sampled PentAGI `main` source files on
2026-10-16**. Those samples are not proof of what moving `main` implements
today, nor do they prove the referenced upstream behavior was deployed.

## Actual AI-OSOP execution paths

| Surface / direction | Observed code path and real contract | Ingestion authority |
|---|---|---|
| User-global knowledge management | `api/main.py` registers `/operator/library/documents` → `api/routers/operator_global_library.py` → `OperatorGlobalLibrary` → 0039 document/current-version and immutable-version rows. Owner is derived from signed issuer+subject; revisions and SHA are bounded, original UTF-8 content is returned only from explicit GET | **No model or tool context approval.** Search returns metadata only; GET returns `content` to the authorized operator with `approved_for_agent_context=false` |
| Signed-Flow operator notes | `/flows/{flow_id}/operator-knowledge` → `OperatorKnowledgeStore` → `FlowArtifactStore._fence` owner, current signed ROE/version and Flow revision → 0019 documents, hardened 0038 tenant FK/exact SHA | **No review-approved prompt ingress.** Explicit GET returns `untrusted_content`; search/list are metadata only |
| Unified operator discovery | `GET /operator/search/knowledge` calls the two stores independently, global first; source labels `user_global_0039` and `flow_local_0019_0038` | No original text, excerpt, owner or target claim; `atomic_cross_source_snapshot=false`, `approved_for_agent_context=false`, `synthesis_performed=false` and `reportable=false`. Denied Flow returns an error rather than partial global success |
| **Actual LLM context route** | `agents/base.py:BaseAgent._complete_supervised_messages` → current signed Task/context checks; optional graph research; optional `verified_reviewed_flow_knowledge` → `FlowArtifactReviewStore.read_approved_inert_text` → `model_window_admission` → `llm_client.complete` | **Different source type:** at most two Task-pinned `artifact-...` IDs and exact SHA, separately approved by a distinct senior, current signed Flow/Task/ROE revalidated before inference. Original note `lib-...` and `knowledge-...` IDs are not eligible. Optional reviewed context is quoted, schema-constrained factual JSON in a **user data** message, never system instructions |
| Reporting / target effects | `agents/reporting_agent.py:_validated_finding` hashes recorded graph evidence and strips raw body from the report. `report_attestations.py` has additional independent target-source release checks | Graph `validated` remains `graph_validated=true` and `source_authenticity_verified=false` / `UNKNOWN_graph_flag_only`. A graph flag, operator note, signed JWT or doc SHA cannot independently prove a target vulnerability or permit a senior release |
| Resource files / retention | 0013 `flow_artifacts` stores original immutable BYTEA plus SHA and forbids update/delete; 0015 has separate senior reviews; `flow_resource_exports.py` produces bounded **in-memory** inert exports, not unrestricted worker filesystem sync. 0039 versions are append-only; tombstone excludes from active search. 0019 note updates revise the same content row and delete marks `deleted_at` | These mechanisms have distinct lifetimes and trust domains. An artifact review does not silently convert a mutable 0019 or 0039 knowledge document into the reviewed artifact. There is no complete cross-source deletion/retention/reviewer-revocation invalidation and worker-propagation qualification |

The strict user-library service `memory/user_knowledge_library.py:get_exact`
can read a current original `document_id + revision + SHA` after checking a
signed principal, but it is **not a mounted automatic ingestion route** and
does **not** mint a senior approval or a model-context grant.

## Test run: direct route + agent boundaries (worker-36)

Created **only**:

- `tests/qualification/test_library_cross_source_ingestion_boundary_20261021.py`
- `docs/PENTAGI_KNOWLEDGE_WORKFLOW_GAPS_20261021.md`

**Executed:** the exact production `/operator/search/knowledge`,
`/operator/library/documents/{id}` and Flow-local `/operator-knowledge/{id}`
router objects, mounted into a minimal FastAPI application. `api/main.py`
registration of the unified route was checked separately. All auth
dependencies are real; local JWT HMAC signatures were actually verified
under temporary test settings. **Store methods were replaced by deterministic
in-memory source/owner fixtures; the revocation ledger was a synthetic
fail-closed implementation.** No application PostgreSQL, real OIDC/issuer,
Docker, provider, target, model API or scan was accessed.

The cases exercised:

1. Both sources contain the **same malicious instruction-shaped original
   text**, but unified search outputs only exact SHA/title/revision/byte-count
   metadata, source provenance and restrictive flags, not the original bytes.
2. An explicit **owner-authorized document GET** does expose that original
   body as `content` for global, and `untrusted_content` for Flow; both
   remain `approved_for_agent_context=false`. This is an intentional
   human read surface, **not** safe material for direct prompt synthesis.
3. Missing bearer and wrong JWT signature return 401; a differently signed
   valid owner cannot read the original Flow (403). Synthetic durable Flow
   revocation returns 403 **without** partial global success. Synthetic
   bearer revocation returns 401 before any source success.
4. Global current version/digest changes appear in search **as metadata
   only**; a global tombstone removes its active search and explicit GET
   access but does not hide an independently eligible Flow note.
5. The **actual `BaseAgent.think` model boundary**, using its existing
   signed Flow Task fake fixture and a mock LLM, was run with bait note IDs
   in Task payload. Neither `OperatorGlobalLibrary` nor
   `OperatorKnowledgeStore` was called for context, and no note body/ID
   entered the model messages. This does **not** prove no other arbitrary
   future/plugin code can insert user-authored text.
6. Actual `reviewed_flow_knowledge._refs` rejects both new document-ID
   families as approved source references. Actual `_facts` rejects raw
   prompt-injection strings and instructions disguised as `technology`
   or privileged role facts; it admits narrowly bounded factual JSON.
7. Real `ReportingAgent._validated_finding` does not copy graph evidence
   injection bodies or credentials into its draft and leaves provenance
   **UNKNOWN**. Resource-export validation denies executable HTML/script
   markup; the historical `_independent_target_authority_available`
   helper fails closed (the separate live release verifier must be assessed
   independently).

**Command:**

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts= -q --tb=line tests/qualification/test_library_cross_source_ingestion_boundary_20261021.py
```

**Observed result:** **8 passed**. The tests intentionally make no real
database/revocation-ledger or external-provider claims. Genuine mounted
PostgreSQL/Ed25519 ROE joins were separately qualified earlier in
`tests/qualification/test_unified_knowledge_mounted_pg_integration_20261021.py`
and its companion report, **not rerun or upgraded to ingestion** in this task.

The final combined regression with existing
`tests/test_unified_knowledge_search_20261021.py` returned **17 passed**.
Black formatting, Ruff lint and Python compilation of the newly owned test
all passed.

During an earlier failing-fixture run, `api/middleware.py:79-84`
`CorrelationIdMiddleware.dispatch` raised `UnboundLocalError` from
`finally` when its downstream `call_next` raised before assigning
`response`. That masks the original exception. The actual production
middleware file was **not modified**. For subsequent boundary tests, the
same production router objects were mounted in a minimal test-only FastAPI
app to separate that middleware defect from the route contract.

## PentAGI v2.2.0 comparison: substantive remaining gaps

The pinned historical source inventory identified PentAGI
`backend/pkg/server/services/knowledge.go` user Knowledge
CRUD/search, `backend/pkg/tools/memory.go` tool searches of
guide/answer/code/memory, `frontend/src/pages/knowledges/knowledges.tsx`,
resource/Flow-file management and worker resource preparation.
AI-OSOP now has real owner-global 0039 and signed-Flow 0019/0038
CRUD/search, plus a metadata-only combined discovery API. That **narrows
the older global-knowledge gap**, but does not prove equivalence to
PentAGI's worker-accessible memory search or per-Flow resource tooling.

**Production-safe next join (not implemented here):**

1. An *additive*, immutable independent review record must bind exact
   `issuer + owner + document_id + current revision + exact UTF-8 SHA`,
   stable tenant/Flow/Task and signed authorization identity; 0019's
   mutable original needs an immutable approved snapshot (e.g. separately
   pinned reviewed 0013 artifact), never just a legacy ID cast.
2. Require a separately authenticated senior reviewer, independent uploader,
   current reviewer authority, immutable approval/revocation and explicit
   opt-in consent. A document `approved_for_agent_context=false` can never
   become true merely through API search, graph tags or operator flags.
3. Recheck current signed ROE, owner, Flow revision, Task, live principal/
   review revocation, exact source bytes and SHA **at the model/worker
   consumption boundary**. Deny stale revision/tombstone/revoked source or
   ambiguous ACK; no silent fallback to unreviewed text. Separate transactions
   still require a final authority/dispatch fence and must not masquerade as
   an atomic cross-source snapshot.
4. Convert approved material **only** through a strict facts schema with
   redaction, prompt-injection rejection, bounded token/byte admission and
   explicit low-priority provenance. Never append raw text, titles or
   retrieved snippets as privileged system/developer/tool instructions.
   Any embedding/index record must be pinned to original SHA/revision and
   invalidated on updates, tombstones, review revocation or ownership changes.
5. Record retention/deletion/export semantics separately for immutable
   global versions, mutable Flow notes, reviewed BYTEA artifacts, indices
   and already-produced model/report outputs. Test two owners, two
   replicas, crash/retry/UNKNOWN, deletion races and proof that a previously
   read copy cannot be silently reused after revocation. Until then,
   **hard fail closed for cross-source auto-ingestion**.

**Unqualified:** production full-library RAG, vector matching,
tokenization/model-provider inference, independently signed senior release,
cross-source atomic snapshot, live revision/reviewer revocation during
inference, actual container resource mounts/retention enforcement,
unrestricted PentAGI tool parity, production multi-replica and target effects.
No extra source files were changed for this task.
