# 0039 user-global → Flow-local reviewed import qualification

**21 October 2026: metadata-only PENDING / not approved / not mounted / not production certified.**

The original shared checkout has useful independently scoped read/write
APIs, but no atomic cross-source reviewed promotion. This assignment built
only a read-only, independent-signer-gated operator metadata preview.
It cannot create a Flow-local document, sign a source citation, execute
agent instructions or mark a global document as verified target evidence.

## Real source and missing atomic binding

| Existing component | Current guarantee | Remaining blocker |
| --- | --- | --- |
| memory/operator_global_library.py (OperatorGlobalLibrary.get/update/delete) | 0039 current document scoped by issuer + principal owner hash; SHA256 of immutable original UTF-8, append-only revisions, CAS update, tombstones | Owner/version lock releases when its transaction ends. No transaction shared with a Flow/reviewer bind |
| api/routers/operator_global_library.py:112-140 | Computes owner namespace SHA256(issuer + NUL + signed principal subject) | The global owner hash is not automatically the same identifier as Flow owner; do not trust caller-supplied hash |
| memory/operator_knowledge.py:226-310 (OperatorKnowledgeStore.create) | Creates inert 0019/0038 Flow-local knowledge in its own signed Flow fence and PostgreSQL transaction | Cannot bind a global original ID/revision/SHA plus senior citation and reviewer signature atomically |
| memory/flow_artifacts.py:112-177 (FlowArtifactStore._fence) | Locks Flow tenant owner, current signed guard_sql ROE/version and Flow revision | Does not independently lock/check 0039 current owner/version or a senior-reviewed citation |
| memory/operator_knowledge_reviewed_admission.py:225-245 (worker36) | Explicit DENY-only 0039↔0019↔0013 admission | This implementation neither overrides that denial nor claims its missing durable signer/atomic citation has been implemented |
| memory/reviewed_flow_knowledge.py | Reviewed 0013 artifact fact retrieval has its own signed current Task/Flow checks | Does not establish lineage from a separately versioned 0039 user-global original |

The existing API for creating a Flow-local operator note **must not** be
used to copy the result of a global.get call. These are independent
transactions, and a global edit/delete or revoked review can win between
them, leaving an unauthenticated cross-source import.

## New helper: reviewed_library_flow_import.py

It exposes GlobalFlowImportRequest, ReviewedLibraryFlowImport,
PendingLibraryFlowCitation and ReviewedLibraryFlowImportDenied.
The scope specifies issuer/subject, Flow owner and engagement,
Flow ID/revision, current Task, signed ROE ID/version/SHA,
global document ID/revision and original SHA256.

The helper recomputes the exact 0039 namespace hash
SHA256(issuer + NUL + principal subject). Host configuration must
independently pin four *distinct* Ed25519 verification roots and
current protected readers for principal namespace, separate senior
reviewer, Flow tenant/owner/revision, and current signed ROE/Task.
They are supplied from the host trust plane, **not** an API body,
global document, operator chat, environment string or LLM.
The module only verifies signatures; it never mints a signing key.

The safe preview verifies the original source through
OperatorGlobalLibrary.get **three times**, including recomputing original
UTF-8 byte length/SHA256, current revision, tombstone absence and inert
source flags. Between reads it requires two rounds of four independently
signed, domain-separated fresh 128-bit challenge readbacks with bounded
strict JSON, duplicate member rejection, short expiries and the exact
source/issuer/owner/Flow/Task/ROE identity. The reviewer must attest
the exact current global original as a senior who is neither uploader
nor originating principal. Changed original, review, revocation epoch,
tenant, signer, flow or Task all deny; missing roots deny before source
read.

**Even successful signed readbacks are not an atomic durable snapshot.**
A write may race immediately after the final read, and the signer
services currently have no enrolled production implementation in
the checkout. On success the helper returns only pending metadata:
document ID, original revision/hash/type, engagement and Flow ID/revision.
It never exposes source title or text, never returns source content for a
prompt, never creates a Flow-local ID, and always has false flags for
agent-context approval, target evidence, execution safety and local
document creation. The operator-facing status is
pending_atomic_reviewed_bind.

The unscoped pending_status method is safe with missing signers and
reveals no library/Flow information. The bind_to_flow method always
raises reviewed-import denial regardless of caller opt-in, fake
signatures or preflight status; there is no writer to call.

## Prime-owned integration/mount point

When actual independent host signers are separately enrolled, prime
may add a read-only operator preview alongside
api/routers/operator_global_library.py or
api/routers/operator_knowledge.py, reusing the existing signed
operator authentication and no-store response headers. Build the
helper with OperatorGlobalLibrary(session_memory) and the four
*host-pinned* authentic verifier roots/readback endpoints; never accept
roots or trust-service URLs from request fields. With no enrolled
roots, return an unscoped pending status or fail closed, not a citation
or approval. No API route or orchestrator hook was mounted here.

Before an actual Flow-local import is possible, a prime-owned
cross-source single-database transaction must be implemented and
qualified: lock and CAS 0039 original/current owner/version/tombstone,
verify immutable bytes, sign/verify independent senior review tied to
that exact source, lock Flow owner/revision and signed current
ROE/Task, then atomically write both source-linked durable immutable
citation and inert Flow-local document. Include replay/idempotency and
UNKNOWN commit ACK fences across replicas. Never promote those bytes
to instructions, report truth, tool execution or a verified finding.

**Existing OperatorKnowledgeStore.create does not provide that API.**
The existing manual Flow-local note functionality remains independent
and does not demonstrate reviewed 0039 import.

## Qualification and limits

The new test file uses synthetic local Ed25519 signer fixtures and
mocked owner-scoped 0039.get. It verifies metadata-only positive
pending behavior plus stale revision/tombstone/owner/issuer/Flow tenant,
tampered SHA/bytes, forged reviewer, role/root reuse, wrong nonce,
concurrent edit, changed reviewer/Flow/ROE epoch, extra prompt field,
no executable content and unconditional no-writer denial.
It also verifies 0039-compatible HTTPS/OIDC issuer and opaque principal
namespaces without mistaking the Flow owner for the global-library owner.
**83 new tests passed; 169 focused new-and-adjacent tests passed together.**
Poetry Black --check and Python compileall passed for both new Python files.
It does not verify a live signer, PostgreSQL transaction, protected
Flow readback or production readiness. No app DB, Docker, external
target/provider, Git, main/routers/stores/migrations/UI or old test
files were modified.

**Release verdict: PENDING ONLY — do not claim 0039-to-Flow import is enabled.**
