# 0041: Immutable reviewed global-source citation (not agent import)

## Actual production wiring

`migrations/versions/0041_reviewed_global_flow_citations.py` adds an immutable
`operator_reviewed_global_flow_citations` PostgreSQL table with the exact global
original revision FK, Flow+engagement composite FK, bounded identifiers/digests,
unique source/reviewer/Task/authorization snapshot and a no-update/no-delete
trigger. Downgrade refuses if any original citation history exists.

`OperatorReviewedFlowAtomicWriter.record_reviewed_metadata_citation()` uses the
same database session factory as `OperatorGlobalLibrary` and `FlowArtifactStore`:

1. Lock and re-verify current Flow owner/revision, signed ROE and Task.
2. Lock and hash-check the exact current 0039 source original and verify its
   independent principal, reviewer, Flow and Task/ROE Ed25519 readbacks twice.
3. Insert the **metadata-only** immutable citation inside those same PostgreSQL
   locks and transaction, check the returned citation identifier, then commit.
4. If current roots are absent, scope/ownership changes, source is revised or
   deleted, commit races fail, or the outcome is ambiguous, return denial/UNKNOWN.

`POST /flows/{flow_id}/reviewed-library-import/record-citation` is mounted in
the existing main app. It requires the existing authenticated Flow operator,
the host-installed independently pinned `ReviewedLibraryFlowImport` four-root
verifier, and an explicitly installed `OperatorReviewedFlowAtomicWriter` using
the original session factory. The HTTP body cannot supply public roots or
signer claims, database credentials or arbitrary original text. Default 503
with no independent host enrollment is **intentional**.

The returned `RecordedReviewedCitation.transaction_committed_citation=true`
means the local PostgreSQL transaction successfully returned from its COMMIT.
It does **not** prove that the HTTP client received a response. Clients must
not retry an unknown outcome without separate trusted readback. The mounted
`POST /flows/{flow_id}/reviewed-library-import/record-citation/readback` now
performs **read-only** current four-signer/Flow/Task/ROE and locked-source
verification before selecting an exact committed record. A missing/stale
readback is `UNKNOWN`, not proof an uncertain write never happened. The Flow
operator panel burns each attempted scope within the mounted screen, offers
an explicit fresh readback (never another write), and refuses to auto-replay.
There is no automatic retry/replay, no approval field, and no agent-context
publication.

Legitimate historical execution Task creators usually persist the signed ROE
`_authorization_version` without optional `_authorization_id`/`_authorization_sha256`
payload hints. The writer requires their exact value via the separately
locked, cryptographically verified current `guard_sql` ROE row plus independent
signed four-role current reader; if optional Task hints exist, mismatches deny.
This avoids making legitimate version-only Tasks permanently ineligible while
maintaining signed current authorization as a hard requirement.

## Non-goals and remaining release blockers

- **This 0041 endpoint does not copy original text into Flow knowledge or
  prompts.** The independent **0042** API now atomically stores an exact
  reviewed, *inert* original in its own immutable Flow-scoped resource table
  (`docs/0042_REVIEWED_FLOW_ORIGINAL_20261022.md`); neither operation exposes
  the source to the agent context loader or grants execution authority.
- The 0041 table does not claim independently authenticated target effects,
  a process signer, native 0033 Action, current real deployment reviewer roots,
  multi-host PostgreSQL durability, physical client delivery, or release.
- A future agent-text context loader must independently enforce new current
  reviewer/Flow/Task/ROE readback and durable atomic authorization. It must not
  infer permission from mere existence of the new citation row.
- The preflight remains pending without independently enrolled trusted host
  reader/signers. Never create a signer service or self-issue approvals within
  the application to turn the pending state into a success.

## Qualification evidence

`tests/qualification/test_0041_reviewed_citation_commit_20261022.py` exercises
the actual mounted-route presence and writer against independently signed
synthetic fixture readbacks: positive content-free citation, wrong owner,
revoked/deleted/revised/tampered original, Task mismatch, missing enrollment,
ambiguous SQL failure, and signed nonmutating readback. These use mock database
sessions and are not live PG. A matched real reference is never promoted to an
agent grant; unconfirmed readback never executes a second INSERT.

`tests/qualification/test_0041_reviewed_citation_real_pg_20261022.py` opts in
with `OSOP_0041_REVIEWED_CITATION_PRIVATE_PG=1`. It boots fresh nonroot PG16
through a private 0700 Unix socket, online-executes real 0039 and 0041 Alembic
DDL over explicitly minimal predecessor tables, and checks constraints,
immutability, tenant FK, unique original/reviewer admission, and destructive
downgrade refusal. No application DB, TCP connection, Docker or scanner used.
This schema test is distinct from a live original SQLAlchemy app/host signer
transaction and does not simulate physical multi-replica deployment.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
