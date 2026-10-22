# 0039 reviewed global knowledge -> Flow: transaction contract

**Qualification on 22 October 2026: NOT READY.** This implementation
deliberately stops at a signed, locked, read-only metadata preflight.
No actual original-to-Flow citation is created, no original content is returned
to an agent, and no caller can promote a global document to model authority,
approved instructions, target evidence or executable resources.

## Why the existing writers cannot implement this atomically

The actual 0039 `OperatorGlobalLibrary._current(db, issuer, owner_hash, id)`
reads the owner-scoped current pointer using `FOR UPDATE`, then the version
table by current revision. Migration 0039 makes the immutable revision and
owner/tombstone state constraints durable. `OperatorGlobalLibrary.get()`
opens its own transaction, so a normal `get()` followed by a Flow-local
`create()` cannot safely join an intervening global revision or tombstone.

`OperatorKnowledgeStore.create()` (0019 plus integrity migration 0038)
and `FlowArtifactStore.upload()` (0013) independently begin separate
PostgreSQL transactions. Their usual write admission checks the signed Flow,
owner, revision and ROE, but no existing common citation writer binds
`global_document_id + immutable_revision + original_sha256 + issuer +
principal_subject + independent reviewer receipt + current Task/ROE`
to an immutable, auditable Flow-local citation in **the same commit**. The
knowledge schema has no 0039 provenance column or review citation table.
Merely inserting a note or an artifact could misrepresent an unreviewed copy.

The existing `ReviewedLibraryFlowImport.inspect_pending_citation()`
performs three independent original reads and two rounds of four Ed25519
signed witnesses (principal, separate senior reviewer, Flow and Task/ROE).
It is intentionally not a commit grant, since later mutation can occur.
The mounted `/{flow_id}/reviewed-library-import/preflight` is also
intentionally pending-only.

Migration 0014 supplies durable `operator_token_revocations` and
`operator_subject_controls` that must be consulted for a real final human
reviewer. The new preflight relies on separately signed current reviewer
readbacks; it does not possess the reviewer's live bearer digest/expiry, so
it cannot invoke `FlowArtifactReviewStore._reviewer_fence` as a final
in-transaction reviewer grant. The Task/engagement path uses `guard_sql`,
which checks the signing operator's subject-control state when required.
Migration 0040's leased durable subscriber cursor is a separate readback
facility; it is not a 0039 provenance link, reviewed citation table or
atomic Flow writer and must not be repurposed as one.

## Implemented read-only transaction

`OperatorReviewedFlowAtomicWriter` is a separately constructed host object
accepting only existing `ReviewedLibraryFlowImport` and `FlowArtifactStore`
objects. It requires the preflight's four distinct pinned roots/readers and
the **identical trusted SQLAlchemy session factory object** behind the source
library and Flow artifacts. The user request never selects keys, reviewer
receipts, a database, original text, trust state or a write callback.

`inspect_pending(request)` obtains one shared DB transaction and:

1. Runs `FlowArtifactStore._fence(db, ..., writing=True)`: session owner
   `FOR SHARE`, active `guard_sql` signed authorization, Flow row
   `FOR UPDATE`, exact Flow revision/status and active session phase.
   It checks the expected engagement ID, signed SHA and then calls
   `guard_sql` again for the exact authorization ID/tenant owner.
2. Reads a current Task `FOR SHARE`, requiring that actual persisted
   engagement/Flow/Task ID, running status, authorization version and
   all present planner/Flow revisions agree. Explicitly pinned authorization
   ID/SHA fields, if present, must match.
3. Loads 0039 through `OperatorGlobalLibrary._current` **using the same db
   transaction**, with owner hash SHA256(issuer + NUL + authenticated subject).
   The function refuses deleted originals, changed revisions and missing
   owner rows. `_projection(..., with_content=True)` recalculates the exact
   original UTF-8 SHA and length; `_original_signature` requires the requested
   source ID/revision/digest and inert classification. The content is never
   returned outside this stack frame.
4. Acquires two fresh sets of independent principal, reviewer, Flow and
   current Task/ROE signed readbacks, using existing verifier's strict domain,
   nonce, issuer, payload scope, signature, freshness, senior separation,
   revocation epoch and current owner rules. The two complete stable claim
   sets must match, excluding only timestamps and challenge nonce.
5. Reads the same locked original again, rejects any revision/SHA difference,
   and returns an immutable, **metadata-only PENDING** plan after ending the
   transaction. It contains no original text, review token, signer key,
   private issuer/subject, prompt or executable content.

This does not make the external signer callbacks transactional participants.
The pending plan has `transaction_committed_citation=False`,
`flow_local_document_created=False`, `approved_for_agent_context=False`,
`verified_target_evidence=False`, and `safe_for_execution=False`.
It cannot be replayed as a commit authorization.
`bind_to_flow(request)` always denies. No retry or write fallback exists.

## Production integration point and required later transactional write

The candidate host hook is immediately beside the mounted 0039 pending
preflight's trusted initialization, after the same `SessionMemory` exists and
after independently enrolled principal/reviewer/Flow/ROE readers are available:

```python
from ai_osop.memory.flow_artifacts import FlowArtifactStore
from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
    OperatorReviewedFlowAtomicWriter,
)

# trusted_preflight: actual host-enrolled ReviewedLibraryFlowImport,
# holding OperatorGlobalLibrary(session_memory), four distinct pinned roots,
# and external signed authority readers (never sourced from operator JSON).
locked_preflight = OperatorReviewedFlowAtomicWriter(
    preflight=trusted_preflight,
    flow_artifacts=FlowArtifactStore(session_memory),
)
pending = await locked_preflight.inspect_pending(host_bound_request)
# Metadata-only PENDING; do not send pending or original bytes to an agent.
```

There is no production enrollment or mounted endpoint for this new helper.
Prime owns main/routers; the hook above is illustrative and should only be
used when the existing host authority is independently enrolled.

An actual citation writer would additionally require an audited migration
and an explicit senior review record signed over **the original immutable
source revision**, with current reviewer credential revocation checks inside
the final transaction. A single durable transaction must lock all of
session -> signed ROE -> Flow -> Task -> 0039 current owner row, independently
validate the exact original bytes/SHA and unexpired reviewer approval, create
an inert Flow-local citation with provenance FK and unique idempotency key,
append a redacted auditable event/outbox entry, verify the returned citation,
and commit only if every check still holds. It must serialize source update,
delete, ROE revoke, Flow revision and concurrent duplicate imports. UNKNOWN
commit acknowledgments must be reconciled through durable readback; never
blindly replay. No currently installed path supplies this complete operation.

## Validation limits

`poetry run pytest tests/qualification/test_0039_reviewed_atomic_writer_20261022.py -q --no-cov`

Qualification uses synthetic test keys and fake transaction/row-lock ordering.
It covers forged/rejected/expired senior receipts, wrong nonce, reviewer
changes between rounds, source edits, tombstone, owner mismatch, original
hash tampering, wrong Task/Flow/ROE identity and revisions, absent host roots,
missing common session and zero writes. Synthetic readback is evidence of
validation behavior, **not** a host enrolled signer or live PostgreSQL
serialization result. No app DB, Docker, scanners, external services, or
repository operations were performed.
