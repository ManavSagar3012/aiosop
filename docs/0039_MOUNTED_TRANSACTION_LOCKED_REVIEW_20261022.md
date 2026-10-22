# 0039 global-to-Flow signed pending preflight: mounted transaction-locked join

**Date:** 2026-10-22. **Disposition: NOT production certified.**

## Actual API integration

The existing mounted `POST /flows/{flow_id}/reviewed-library-import/preflight` already gates independently signed current global original / reviewer / Flow / Task and ROE, and returns inert PENDING source metadata without original bytes. It has now gained an additional **trusted host-only optional enrollment**: `install_host_locked_reviewed_library_preflight(app, writer)` accepts only `OperatorReviewedFlowAtomicWriter` referencing the SAME prior installed `ReviewedLibraryFlowImport` service, with its real 0039 global library and Flow artifact database transaction factory. It refuses a duplicate installation, mismatched services and unauthenticated or incomplete host enrollment. No client request, query or environment variable can install it.

When present, the actual mounted route first completes the four-source current signed original PENDING readback, then calls `writer.inspect_pending(original_authenticated_proposal)`. The worker's real implementation locks current signed Flow, ROE, Task, and original 0039 global revision in the same PostgreSQL transaction and rechecks independently signed reviewer/owner/Flow/ROE witnesses. Only a bounded immutable PENDING identity is compared to the first readback. If original owner/source revision/SHA, Flow, Task, signed ROE, or any safe flags differ, **HTTP 409**, no original bytes and no trusted agent context. The `bind_to_flow` method still always denies until an actual same-transaction immutable citation provenance schema/writer and independent host signer enrollment exist. This addition never writes or automatically executes an action.

The default service remains host-unconfigured/503 and the previously signed preflight still operates in pending-only mode if the extra host writer is not installed. PENDING does not authorize any Flow knowledge import or imply independently proven target-side effects.

## Verification

`tests/qualification/test_0039_mounted_locked_reviewed_join_20261022.py` exercises the actual FastAPI router using synthetic user JWT, reviewer and same-database callbacks, checking required dual readbacks, stale source/revision/Flow/ROE and affirmative authority flags rejected, one-time host enrollment and denied cross-service installation. These are **synthetic route-contract fixtures**, NOT independent production signing roots or real PostgreSQL. The worker's real `OperatorReviewedFlowAtomicWriter` source and adjacent adversarial unit qualification remain separate and do not grant an atomic import.

Command with new mounted and adjacent reviewer tests: **34 passed**. Existing original 0039 disposable private PG source-revision/tombstone tests are separate prior evidence; no production reviewed import into Flow-local agent prompts was attempted here.

## Remaining gap

Real host-issued four independent current signing roots, immutable reviewer decision material, single-PG atomic 0039 original-to-0019/0038 provenance citation writer/readback/one-use CAS, verified current ROE/Task revision, cross-replica cancellation and authentic reviewer/owner authority remain unconfigured. Source text stays inert, never elevated to system prompt or report truth.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
