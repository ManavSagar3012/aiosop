# LiteLLM host guard real-constructor readiness qualification — 21 October 2026

**Decision: NOT READY / NOT PRODUCTION CERTIFIED.** The 11-independent-root
credential dispatch guard exists as an opt-in library, but the original
shared application's current bootstrap **does not select it**. No genuine
external signer enrollment, host vault-to-live-key binding producer, signed
committed-ledger reader or cross-replica revocation/consumption fence was
established by this task. Only the two new test/document files named in the
worker assignment were created. No production source was edited.

## Grounded production constructor and ownership chain

1. **API main is the only source constructor.** The exact AST call in
   src/ai_osop/api/main.py:346 is
   LiteLLMClient(usage_store=ModelUsageLedger(session_memory)).
   No vault_guard_required=True, ProviderCredentialDispatchGuard,
   vault_guard instance or vault_binding_factory is supplied. The
   LiteLLMClient constructor in src/ai_osop/core/llm_client.py:121-153
   defaults vault_guard_required=False with None guard and binding factory.
   Consequently, this app bootstrap does not enable guarded dispatch.
2. **Orchestrator receives an already-created client.** API main lines
   355-360 passes the exact client to Orchestrator(llm_client=llm_client).
   src/ai_osop/orchestrator/orchestrator.py:137-149 accepts llm_client as
   a parameter and stores self.llm_client = llm_client; it does not
   construct its own LiteLLMClient. Agent contexts are constructed later
   by main; creating a guard only inside an operator API route could not
   protect this already-shared client or background work.
3. **Production source search.** In the inspected src/ai_osop Python
   tree, no production code outside the defining source modules builds
   HostVaultRuntimeReadinessAdapter or ProviderCredentialDispatchGuard,
   and no API router sets vault_guard_required=True or supplies a
   vault_binding_factory. This is a source-wiring result, **not** a claim
   about an operator's actual deployment configuration, private vault,
   external service inventory, or unknown installed integrations.
4. **The ordinary ledger alone does not prove vault currentness.**
   src/ai_osop/core/llm_client.py resolves models under signed v2
   Task/role admission and invokes the real ModelUsageLedger.reserve
   before provider dispatch. The signature of reserve in
   src/ai_osop/memory/model_usage.py takes engagement_id, task_id,
   model and operation; it returns a call ID. No production enrolled
   current four-root dispatch witness service is read here by the
   main-created (unguarded) client. The new guard requires an independently
   **signed, current** committed reservation readback; a return string or
   a caller-controlled reserved=True does not satisfy that contract.

## What pending guard mode actually prevents

The real imported LiteLLMClient can be constructed with
vault_guard_required=True and NO actual host enrolled roots/factory.
This is an intentional **DENY**, not mock readiness. Its live
_provider_call and _provider_call_admitted reject missing guard or
binding factory, missing or non-v2 route **before** the environment key
getter, route.provider_kwargs(), model budget reserve, catalog network
or LiteLLM completion/embedding call. Pending guarded complete and
embedding calls do not transparently retry or fall back. The opt-in
parameter is initialized only in a trusted Python constructor, not
from request kwargs; the v2 route direct-dispatch boundary explicitly
blocks vault_guard_required, vault_guard, vault_binding_factory,
vault_dispatch_permit, vault_dispatch_binding and api_key in
model-call kwargs. A forged object with authorize_reserved() is
not a genuine ProviderCredentialDispatchGuard and is rejected.

**Qualification scope:** tests/test_litellm_constructor_real_wiring_deny_20261021.py
uses source AST for app/orchestrator constructor identity and executes
the exact app constructor expression with a mock ledger. It also
instantiates the **real imported** LiteLLMClient under Poetry, injects
fully mocked provider, HTTP, local embedding, catalog, routes and ledger,
and deliberately leaves signer roots absent. Negative checks assert
no key-selection method calls, no reserve/settle, no network transport,
no provider calls, and no API-kwargs guard toggle on the selected v2
boundary. No DB or real vault is opened. These tests deliberately do
not claim a complete running FastAPI lifespan, genuine signed host
readback, actual PostgreSQL commit or production E2E.

**Critical separation:** The real application still runs the default
unguarded behavior until prime wires guarded selection at the
authoritative main constructor. The passing pending-guard denial tests
do NOT prove that the current running application is in guarded mode.
Also, a legacy/unconfigured provider route has different behavior;
v2 direct-dispatch kwargs are constrained, but a client without
configured routes must not be treated as globally signed-vault-safe.

## Exact minimal safe prime-owned integration seam

**Location:** src/ai_osop/api/main.py immediately before the existing
LiteLLMClient(usage_store=ModelUsageLedger(session_memory)) at line 346,
inside the application lifespan and **before** Orchestrator initialization
and agent registration.

Prime must first establish each of the following through a trusted host
bootstrap not controllable by HTTP requests or LLM output:

1. At least seven independently enrolled Ed25519 authority roots,
   genuine read-only current profile/Flow/principal/review/budget sources,
   and independently TLS-authenticated current vault-material and
   revocation services for HostVaultRuntimeReadinessAdapter.
2. Four **additional distinct** enrolled signing roots and genuine
   host-only readers for vault material version, independently current
   revocation ledger, the actual deployed environment/runtime provider
   key bound to the exact vault version and selected route, and a
   genuinely committed signed PostgreSQL model usage reservation.
   The protected runtime-key producer must correlate the *real key
   used by LiteLLM* without exposing it to the guard, operator, logs
   or tests. A signed user-supplied Boolean does not qualify.
3. A trusted async vault_binding_factory resolved from authenticated
   Task/Flow/tenant/ROE, current reviewed policy ref/CAS revision and
   selected route, exact model/operation and committed call ID.
   Never build such bindings or enroll roots from API POST bodies.
4. Durable cross-replica consumed-call-ID and revocation/version fencing
   tied to the model usage ledger and actual provider-send boundary.
   The current guard has only an in-process burn list; separate signed
   readbacks are not one atomic PG/vault snapshot. Rejected or lost
   post-reservation ACK must be treated as UNKNOWN, never blind retry.

**Then, and only then**, pass host-selected vault_guard_required=True,
vault_guard=the_enrolled_guard and
vault_binding_factory=the_protected_factory to the single constructor.
Fail application startup or deny managed-provider calls if mandated
host configuration is incomplete. Preserve the shared
ModelUsageLedger(session_memory), v2 Task/role/lease checks and current
fallback-UNKNOWN accounting. Do not provision roots or bind a
credential version by merely referencing an approved nonsecret
0028 profile record or environmental API-key variable.

## Release blockers / falsifiable gates

- No production constructor opts in or injects host guard/factory.
- No independently verifiable live signing keys/readers/host vault and
  postcommit current signed ledger readback shown in this checkout.
- No proof that actual outgoing LiteLLM credentials are a specific
  currently active, independently unrevoked vault generation.
- No durable cross-replica consumed-ID / revoke fence; per-process
  observations are not a completed distributed send transaction.
- No real app-lifespan + PG + host TLS + signer enrollment E2E
  qualification. Synthetic tests only establish expected denial.

**Do not mark READY based on a successful mock or an approved metadata
reference.** Prime must own all required production wiring and the
external independent authority infrastructure.

## Exact offline qualification result

The new constructor/wiring test file contributes **34 passing tests**.
The focused Poetry run with the existing real LiteLLM guarded-boundary,
signed-v2 Task admission and model-usage binding tests produced
**110 passed**. Black --check and Python compileall passed for the new
test file. The tests use real imported LiteLLMClient methods, fake
ledger/provider/HTTP sources, a read-only source AST inspection and
targeted environmental key-get interception. No signed production
root, real provider credential, app DB, or provider was accessed.

**This result does not establish production guard activation: the one
actual app constructor still chooses the default unguarded mode.**
