# 0039 mounted global-to-Flow reviewed preflight — 2026-10-21

**Result: mounted and partially qualified; actual reviewed import remains blocked. NOT PRODUCTION CERTIFIED.**

## Reachable production boundary

- `src/ai_osop/api/main.py` mounts `ai_osop.api.routers.reviewed_library_flow_import.router` at `POST /flows/{flow_id}/reviewed-library-import/preflight`.
- The route requires the existing signed operator JWT identity, a body of at most 65,536 bytes with duplicate JSON fields prohibited, and exact source-global document ID/revision/SHA + Flow/Task/current ROE identity. It derives principal issuer/subject from verified auth; the caller cannot supply signer roots, reviewer approvals, executable content, or authority-bearing token data.
- The externally owned installation API is `install_host_reviewed_library_preflight(app, ReviewedLibraryFlowImport(...))`. The service must be created by an independently trusted host bootstrap with *four distinct enrolled* Ed25519 verification roots and current principal, separate senior reviewer, Flow and Task/ROE signed readback services plus a real original 0039 database reader. The route rejects its absence with HTTP 503 **before any original database access**. A production authority cannot be obtained by client-supplied keys, an environment flag, or merely presenting a signed operator JWT.
- If the operator-owned genuine service is installed, the underlying reviewed-library helper reads the exact owner-scoped original 0039 content three times and independently checks fresh principal/reviewer/Flow/ROE receipts twice. It validates original SHA-256 and revision, revocation/expiry and distinct signers. Its successful preflight projects **only** `pending_atomic_reviewed_bind` metadata without source text, authorizer secrets, prompts, agent context, Flow knowledge or target-effect attestations.
- `bind_to_flow` continues to DENY because no atomic single-PostgreSQL source-current + immutable independently signed review + Flow-local citation/Task/ROE write has been implemented. Preflight never calls a Flow writer and cannot authorize downstream tool calls.

## Operator experience

`ui/src/pages/FlowOperations.tsx` renders `ReviewedLibraryFlowImportPanel.tsx` alongside Flow-local knowledge for the selected Flow. It requires the exact current global original metadata, Task and ROE expected fields. `ui/src/services/reviewedLibraryFlowImport.ts` uses the existing in-memory verified JWT with HTTPS or localhost-only frontend origin, refuses redirects/cookies/referrer leaks, validates response source/Flow identity and all false authority flags, and shows only **PENDING**. It does not offer a copy, approval, publish or execute action. A change in selected Flow or signed operator resets the result. For a real host without enrolled roots, the user sees an actionable independent-enrollment denial.

## Qualification and next engineering requirements

`tests/qualification/test_0039_mounted_reviewed_library_preflight_20261021.py` uses real imported main.app registration and isolated FastAPI/ASGI signed synthetic JWTs to verify absent role, owner mismatch, illegal reviewer signature client field and absent host service. A separate synthetic service response confirms routing emits only non-promotable metadata, not that the actual external signers exist. Worker41's cryptographic helper remains covered by `tests/test_reviewed_library_flow_import_20261021.py`. Combined Browser/native/ping and 0039 API selection **145 passed** (18.33 s), local synthetic only. Frontend `npm --prefix ui run typecheck` and `npm --prefix ui run build` passed, Vite v7.3.3, 2,663 transformed modules, build 7.10 s.

The substantive missing next step is a separately enrolled current signer service and atomic durable writer preserving source current original + reviewer + signed Flow/Task/ROE under a single PostgreSQL serializable/fenced transaction, qualified with adversarial revision/owner/tenant/revocation/concurrency/crash-readback tests. **Do not** bypass this with a second independent transaction, in-app Ed25519 signer, SQL fixture signature, or immediate `OperatorKnowledgeStore.create` call, and do not count a pending citation as completed PentAGI parity.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
