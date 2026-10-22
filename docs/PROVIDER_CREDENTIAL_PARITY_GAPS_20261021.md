# Provider credential lifecycle and PentAGI parity — 2026-10-21

**Verdict: NOT READY / NOT PRODUCTION CERTIFIED.** This work added one standalone, read-only proof-verification contract and synthetic tests. No production credential service is connected. No vault secret, provider API, application database, Docker, migration, original routing or live budget reservation was touched.

## Existing production paths observed

| Source | What it actually does | Remaining gap |
| --- | --- | --- |
| memory/provider_credential_profile_refs.py, api/routers/provider_credential_profile_refs.py, migration 0028 | Signed-Flow- and owner/senior-fenced PostgreSQL CAS for **symbolic** primary/backup references. Register starts pending, independent senior approves/revokes, rotate increases generation and resets to pending. The public response explicitly sets credential_available_verified=false and execution_enabled=false. | No actual vault material presence, credential validity, usable version, backend rotation acknowledgment or route activation. |
| memory/provider_route_policy_reviews.py and corresponding router, migration 0025 | Canonical nonsecret intent, owner/senior review and signed Flow revision; approval is intentionally inert. | Cannot prove model availability, credential usability or served capabilities. |
| core/provider_routing.py and core/llm_client.py | Opt-in deployment allowlist references environment credential variables and checks Task, Flow, ROE, lease, role/capability declaration for v2 routing. | No current signed profile-generation-to-external-vault bridge. Env presence is not independent vault attestation. |
| memory/model_usage.py, ModelUsageLedger.reserve | Atomic PostgreSQL signed-ROE Task/Flow/lease and budget reservation before dispatch; ambiguous results remain UNKNOWN. | A read-only budget-status observation does not replace the committed per-call reservation. |

The historical local PentAGI comparison in docs/PENTAGI_PARITY_INVENTORY_20261016.md identifies pinned **v2.2.0** backend/pkg/providers/providers.go provider controller and CreateProvider/UpdateProvider/DeleteProvider/TestProvider, plus backend/pkg/providers/catalog.go. Its sampled upstream main snapshot dates to **2026-10-16**, covering only specified files. No current moving-head main verification was performed here. AI-OSOP provider credential CRUD/test/readiness does not have confirmed operational PentAGI parity.

## New fail-closed contract

src/ai_osop/core/provider_credential_lifecycle.py defines CredentialLifecycleVerifier, CredentialReadinessRequest and the advisory CredentialReadinessDecision.

The verifier accepts **only trusted host-provisioned readers and out-of-band pinned Ed25519 public keys** for six cryptographically distinct authorities. It generates a fresh random 128-bit challenge per decision. Each independently authenticated reader must query **current authoritative source state**, return at most 8 KiB canonical signed JSON with the same nonce, tenant and Flow, and sign claims under the domain prefix ai-osop-provider-credential-readiness-v1 followed by the specific authority kind. Duplicate JSON keys, nonfinite values, forged signatures, key collisions, missing readers, expired, future, overlong or oversized evidence deny. Default observation age is 15 seconds maximum. No secret bytes, credential paths or handles are accepted or returned.

| Independent authority | Exact observation required |
| --- | --- |
| **profile** | Current approved nonrevoked durable ref ID, generation, CAS revision and recomputed original reference SHA, owner, active independent senior, provider/slot, policy binding, signed authorization identity/version/SHA, Flow revision, validity |
| **flow** | Current running Flow, signed unrevoked authorization, owner/tenant, exact ROE ID/version/SHA and Flow revision |
| **principal** | Server-authenticated caller subject (must be owner), current operator/senior role, active subject and unexpired authenticated bearer; derived from middleware rather than caller parameters |
| **policy** | Independent approved nonrevoked owner/senior provider review, active reviewer, original canonical provider/model/allowed roles/operations/budget policy and SHA |
| **vault** | **External vault** directly attests actual secret-material presence, credential version digest, validity and exact profile CAS/generation/slot; rotation requires distinct new version plus **vault-side** revoked previous version. Symbolic refs and arbitrary booleans are insufficient. |
| **budget** | Independent current signed PostgreSQL budget observation for exact Task, model, operation, role, Flow revision and ROE version/SHA; bounded available micro-USD covers requested micro-USD |

A positive synthetic decision always returns **dispatch_authorized=false, budget_reserved=false, provider_contacted=false, provider_accepts_credential_verified=false**. The verifier does not activate provider routing or prove actual provider-side key acceptance/revocation. It is an advisory current snapshot; revocation may occur just after observation. No calling code is allowed to treat this as dispatch approval.

## Integration blockers and acceptance

1. **No protected host service readers or trusted key enrollment.** Existing 0028 rows are symbolic, and no independently authenticated current profile/Flow/principal/policy/vault/budget proof issuer is registered. A separate host service must query actual PostgreSQL under consistently fenced locks and independently verify reviewer/subject revocation before signing. Never accept a caller supplied reader, key, role or profile proof as authority. Without this service, the new verifier is **unwired and cannot return a real production readiness result**.
2. **No external vault integration.** Existing route and reference APIs do not inspect actual material or rotate provider credentials. A future vault reader must authenticate and attest current secret version *without exposing secret contents, handles or paths*. Vault-side revocation alone does not prove provider-side token invalidation. Any explicit provider-side test requires separate authorization, quota and real independent outcome evidence.
3. **No signed budget-readiness attestor or atomic dispatch join.** A budget read is a point-in-time estimate only. The existing ModelUsageLedger.reserve transaction, claimed running Task, ROE/lease fences and durable UNKNOWN behavior remain mandatory before any billable request. Do not reuse this readiness report as a budget or provider-call grant.
4. **Profile validity source unavailable.** The 0028 schema stores CAS revision/generation/status but no credential validity or external material version. The proof contract requires independently observed profile_valid_until and credential_valid_until; invented dates or hashes of symbolic refs cannot satisfy this in production. A concrete protected read service and real migration/reader verification are needed.
5. **No production end-to-end coverage.** Tests here only prove local cryptographic and decision validation against in-memory synthetic authorities. Deployment key rotation, multi-replica coherence, live database constraints, vault read races, provider-side disabled-old-key attestation and actual cost reservations remain unqualified.

## Focused validation

- Python pytest on tests/test_provider_credential_lifecycle_20261021.py: **59 passed**, synthetic authority signers only, no network/provider/DB.
- Python compileall on new module and test: **passed**.
- Ruff, Black and Flake8 are not available in this environment (No module named ...); no lint/format pass is claimed.

These changes document a clear authority seam; production provider administration and full PentAGI parity remain open.
