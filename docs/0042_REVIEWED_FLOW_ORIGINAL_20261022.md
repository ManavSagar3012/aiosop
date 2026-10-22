# 0042 Reviewed Flow Original: real atomic storage, permanently inert

## What is actually implemented

`migrations/versions/0042_reviewed_flow_originals.py` extends 0041 in the
**original shared repository**. It creates `operator_reviewed_flow_originals`,
an immutable Flow/engagement/owner-scoped original UTF-8 content table. Its
composite FK to the 0041 citation must match original citation id, exact Flow,
tenant, owner, original SHA256 and source type. PostgreSQL independently
verifies content byte length (1–8192), original SHA256, and irrevocable
`approved_for_agent_context=false` and `verified_target_evidence=false` flags.
UPDATE/DELETE are denied by trigger and downgrade refuses nonempty history.

`OperatorReviewedFlowAtomicWriter.store_reviewed_flow_original()` now provides
the production writer contract. The separately host-enrolled four signed
principal/reviewer/current Flow/Task/ROE witnesses and same session factory
are mandatory. The code locks current Flow, current PostgreSQL signed ROE,
running Task and current immutable 0039 source, checks exact source SHA and
revision and two independently verified signer rounds, then inserts both
0041 citation and 0042 exact original in **ONE PostgreSQL transaction**.
Any exception/constraint failure/cancellation rolls back both. The original
text is not returned, logged or injected into an agent. On a lost HTTP ACK,
the operation is UNKNOWN; there is no automatic retry.

The mounted signed-owner routes are:

* `POST /flows/{flow_id}/reviewed-library-import/store-reviewed-original`
* `POST /flows/{flow_id}/reviewed-library-import/store-reviewed-original/readback`

The second is nonmutating: re-checks the entire independent current authority
and exact source, then joins 0041 citation to its inert 0042 original. No row
or stale ROE means UNKNOWN, **not** proof the previous write did not commit.
The Flow operator UI offers explicit human-confirmed one-shot storage and a
distinct readback control; it burns previously attempted request scope so the
same UI cannot retry an uncertain request. The browser sends only IDs and
SHA/digests, no original text, approval tokens or arbitrary host paths.

## Explicit limits

- This *is* a real PostgreSQL Flow-local reviewed-original materialization
  and atomic immutable source citation implementation. It is **not** the
  application’s existing `operator_knowledge_documents` write, and no agent
  context loader consumes these original bytes. A separately signed future
  context admission/approval needs its own current transaction and trust roots.
- 0042 storage remains an **inert, untrusted user-authored document** even if
  independently reviewed. It is never an agent instruction, MCP authorization,
  target-owner-verified finding or signed release.
- In this checkout, independent host original-owner/reviewer/Flow/ROE
  enrollments are absent; the mounted route intentionally returns 503 without
  host-installed verified providers and exact session maker. Synthetic signed
  fixture results do not enroll production roots.
- A success response means PostgreSQL commit if received, never exactly-once
  HTTP delivery. A missing readback does not justify repeating a write.

## Qualification

`tests/qualification/test_0042_reviewed_flow_original_20261022.py` exercises
the actual 0042 writer with independent signed-source fixture callbacks,
including successful exact original metadata-only receipt, separate signed
readback, revoked/wrong owner/Task/ROE, forged reviewer, tampered or deleted
original and unconfigured host. Synthetic fake sessions cannot prove SQL
rollback, and their signed fixture keys have no production authority.

`tests/qualification/test_0042_reviewed_flow_original_real_pg_20261022.py`
opts in with `OSOP_0042_REVIEWED_FLOW_ORIGINAL_PRIVATE_PG=1` and runs real
online 0039→0041→0042 Alembic upgrades against fresh disposable **nonroot**
PostgreSQL 16 via a private 0700 Unix socket with TCP completely disabled.
It tests real original/citation same-transaction COMMIT, PostgreSQL-validated
original SHA/UTF-8, tenant+Flow+owner FK, denied agent promotion, immutable
UPDATE/DELETE, rollback of citation when original integrity fails, and
nonempty downgrade refusal. This private fixture uses minimal predecessor
tables and is NOT the application database or physical multi-host test.

The corresponding authenticated frontend service tests validate one-shot
credential/owner-scoped POST, bounded all-field metadata response, forgery
rejection, missing external host authority denial, no secret/original leakage
and signed readback with no automatic repeat. TypeScript/Vite production build
and mounted API route tests are separate checks, not target-effect proof.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
