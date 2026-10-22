# Provider credential live wiring qualification — 2026-10-21

**Disposition: NOT PRODUCTION CERTIFIED / NOT READY.** The signed host-only vault adapter exists as a standalone, opt-in, read-only advisory component. It is **not enforced** by production LiteLLM dispatch, mounted profile reference routes, reviewed policy routes, or model ledger. All tests here use source-extracted production function bodies with mocked effects; no real application DB, provider, vault, target or Docker service was contacted.

## Actual registered runtime path

| Boundary | Direct original source evidence | Effect |
| --- | --- | --- |
| App bootstrap | src/ai_osop/api/main.py lines 341–346 builds LiteLLMClient with ModelUsageLedger(session_memory); lines 640–642 mount provider invoices, route policy reviews, and profile references. | No lifecycle adapter initialized/injected. |
| Profile admin | src/ai_osop/api/routers/provider_credential_profile_refs.py lines 22, 42–83, 139–182 and 185–267 register GET list/detail and POST register/rotate/approve/revoke. POST sends actor, expected Flow, ROE, operation and CAS fields to ProviderCredentialProfileRefStore.perform. | Metadata updates only. Does not query a vault, validate a live credential or alter deployment routing. |
| Rotation | src/ai_osop/memory/provider_credential_profile_refs.py lines 627–646 requires an approved reference for rotate, increments generation and resets status to pending; lines 674–721 increment the CAS revision with tenant/Flow WHERE filters. Public projection at lines 109–138 explicitly sets credential_available_verified=false, credential_rotated=false, execution_enabled=false, route_activated=false, and provider_contacted=false even for approved records. | Review approval and rotation have no provider material effect. |
| Policy administration | api/routers/provider_route_policy_reviews.py lines 194–361 expose create/list/detail/update/senior decision; memory/provider_route_policy_reviews.py lines 1–5 explicitly say intent is inert for ProviderRoutes and LiteLLM. | Senior-approved intent is not live provider configuration. |
| Informational catalog | api/routers/provider_invoices.py lines 169–193 returns locally configured capability report, provider_currently_available_verified=false and signed_budget_admission_still_required=true. | Catalog/budget explanation grants no model dispatch. |
| Live model call | core/llm_client.py lines 135–190 enters v2 Task/role authorization where configured; lines 211–245 resolve route/provider_kwargs, reading env-configured credentials; lines 257–317 check Task context and reserve durable model usage; lines 335–365 call LiteLLM and settle or record UNKNOWN. | HostVaultRuntimeReadinessAdapter.assess or CredentialLifecycleVerifier.assess is never invoked. |
| Model ledger | memory/model_usage.py lines 1068–1110 requires engagement/Task and signed admission, including v2 Task/Flow/lease revalidation. | Budget reservation is real protection, but accepts no credential profile ID, version, vault revision or revocation epoch. |

core/provider_routing.py lines 123–150 uses os.environ.get(self.credential_env) to build the provider key kwargs. ProviderRoutes.from_environment (lines 162–169) returns None when the opt-in route allowlist is absent. When v2 is configured, resolve (lines 311–339) checks Task ContextVar, signed Task role and route policy digest. Those real guards must be preserved.

In the inspected src/ai_osop tree, all references to HostVaultRuntimeReadinessAdapter occur inside its own defining module, core/provider_credential_lifecycle.py (class beginning near line 636, assess near line 875). There is no production instance provisioned with its seven distinct out-of-band Ed25519 roots, independent host TLS CA and bearer channels, or externally durable global vault/revocation version authority. Neither host service is proved deployed or independently enrolled.

## In-process test evidence and limitations

The new tests/qualification/test_provider_runtime_credentials_prod_wiring_20261021.py qualifies:

1. The real source registration of profile/policy/catalog endpoints and bootstrap ledger.
2. The unmodified statement bodies of the actual POST profile handler and its invocation wrapper compiled in isolation; with a fake store, the operation carries only symbolic rotation metadata, scoped Flow/tenant/CAS, and returns pending/false live-credential flags.
3. The actual profile store public-projection function compiled directly; an approved, senior-reviewed record still reports false for credential material and execution flags.
4. The exact statement bodies of LiteLLMClient._provider_call and _provider_call_admitted compiled in isolation with a fake Task context, fake v1 route, mock ledger, and fake provider. Missing ledger, denied reservation, storage outage, invalid reservation ID, and absent Task ID all prevent provider contact.
5. With an accepted synthetic ledger reservation, the fake provider receives a synthetic configured credential despite an attached vault mock that would deny readiness. The mock vault is never called. This proves the observed *missing vault check* in that source-backed legacy branch, not authorization to contact a provider and not a bypass of the signed v2 Task admission.
6. Actual verifier/host-adapter constructors fail closed without enrolled roots. A positive advisory readiness value never asserts reserved spending, allowed dispatch, or provider acceptance.

Local Python cannot directly import the full provider and API modules because litellm and neo4j are unavailable. These are source-backed **in-process qualified function bodies**, not a running ASGI application, real PostgreSQL migration, operating credential service or live provider test. External effects are mocked and the isolated test keys/credentials are synthetic. Positive mock outcomes cannot certify production.

## Precise candidate integration points for PRIME

**1. core/llm_client.py lines 193–317, especially 211–246, is the single completion/embedding dispatch boundary.** Add a protected host-side authoritative currentness gate before route.provider_kwargs retrieves any deployment credential and before the model ledger reserves spending. Input must be derived from authenticated Task, signed Flow/ROE, owner, independent approved provider policy, current CAS profile ID/generation/status and actual authorized route, rather than user-controlled metadata. Require separately enrolled signed current vault material and independent revocation observations; missing, stale, rotated, revoked, unconfigured or ambiguous evidence must deny. The resulting advisory value must never become a provider call authorization by itself.

**2. core/llm_client.py lines 135–190 and core/provider_routing.py lines 311–339.** Keep existing v2 signed Task/role/lease admission, exact model and capability checks, and pinned route policy digest. Bind the active credential version to the exact route used at the call site. The current host adapter only attests material presence/version; it cannot prove the os.environ-selected key sent by LiteLLM is that exact vault version. A protected host bridge is needed for this association without returning credential bytes to operator/UI. Legacy v1 or absent-route mode needs an explicit fail-closed managed-credential policy, otherwise the new check can be evaded by falling back to legacy dispatch.

**3. memory/model_usage.py lines 1068–1110 and api/main.py lines 340–346.** Bind a trusted readiness service during app bootstrap only after independently configured CA/service identity/signing-root enrollment. Preserve ModelUsageLedger.reserve atomic Task/Flow/ROE/lease and budget fencing and existing UNKNOWN handling. Race-safe current vault/revocation version admission across replicas needs durable authoritative revocation/high-water data and fresh admission at send time: the standalone adapter's local in-memory high-water fields cannot certify this. Read-only vault readiness never replaces a committed budget reservation or proves provider-side key validity/revocation.

These candidate changes would require PRIME to authorize existing-file ownership and deployment authority enrollment. No such production edits are part of this audit.

## Open release blockers

- No independently enrolled vault material/revocation signer roots, authenticated current issuer readback, deployed vault, provider-side accepted-key test, or durable multi-replica revocation fence was verified.
- No source demonstrates approved/ref-rotated 0028 profile changes the actual environment key or provider call route, so key rotation/revocation is not operational.
- No real FastAPI/PG/vault/provider end-to-end test was executed; source AST and synthetic in-process tests cannot replace those.
- PentAGI pinned v2.2.0 provider administration parity remains incomplete; prior sampled upstream main is historical, not independently refreshed by this task.

**Validation on 2026-10-21:** Python pytest of the new qualification suite plus the two existing lifecycle/runtime adapter suites produced **106 passed, 1 warning**. The new qualification suite alone contributed **15 passing cases**. Python compileall passed on the new test file. These validate the stated synthetic/source-backed scope only.

**Release disposition remains NOT READY.** Only the two assigned new audit files were created.
