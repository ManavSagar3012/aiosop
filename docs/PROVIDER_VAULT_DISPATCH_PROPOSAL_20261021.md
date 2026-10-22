# Provider vault → model dispatch guard proposal (2026-10-21)

**Status: unmounted, synthetic qualification only; NOT production-ready.**

## Source trace and gap

The mounted provider profile-reference administration API and migration 0028
store maintain nonsecret symbolic references. Rotation advances generation
and resets status to pending; neither review approval nor rotation changes
the live deployed key. The public projection explicitly sets live credential
availability, rotation completion, execution and provider contacted flags
to false.

Production LiteLLMClient._provider_call_admitted in
src/ai_osop/core/llm_client.py lines 193–365 resolves route and calls
route.provider_kwargs() at lines 211–245. ProviderRoute.provider_kwargs()
in src/ai_osop/core/provider_routing.py lines 123–150 reads its locally
configured environment key. The client then performs mandatory
ModelUsageLedger.reserve() at lines 304–317 and only then dispatches
litellm.acompletion/aembedding at lines 335–345. The v2 Task/Flow/role
authorize_task scope lives at llm_client.py lines 135–190. **Preserve all
these guards.**

The existing HostVaultRuntimeReadinessAdapter in
src/ai_osop/core/provider_credential_lifecycle.py validates independently
signed current profile, Flow, principal, policy, material, revocation and
budget evidence. Its readiness observation explicitly returns
dispatch_authorized=false and budget_reserved=false; it does NOT establish
which environment key LiteLLM sends and has no production caller. The
absence of signed host binding remains a real production blocker.

## New injectable, unwired guard

File: src/ai_osop/core/provider_credential_dispatch_guard.py.
The ProviderCredentialDispatchGuard class takes an EXISTING genuinely
enrolled HostVaultRuntimeReadinessAdapter plus **four extra, different,
host-enrolled Ed25519 signing roots**, all distinct from the original
seven roots. It adds four protected asynchronous readers, each required
to observe the actual service (not blindly sign a caller's data):

| Signer | Required real observation |
| --- | --- |
| vault_material | Current **nonsecret** credential material version ID, monotonic vault revision and latest revocation revision from protected vault storage. No key bytes or exportable key digest. |
| vault_revocation | Independent ledger with the same active version and vault revision, current credential not revoked, and previous generation revoked after rotation. |
| route_key | Protected host that **actually correlates the runtime credential configured for the exact outbound LiteLLM route to the current vault material version**, signs exact route, reviewed policy, Flow, Task, ROE, credential generation, and reservation. A symbolic flag or operator-provided hash is not proof. |
| reservation | Independent signed PostgreSQL ModelUsageLedger readback confirms the exact call ID is **durably committed**, Flow/Task/lease/ROE fenced with positive ledger and lease generations, enough precharged micro-USD. A string returned by reserve() is insufficient. |

All four signed observations must contain the same locally generated 128-bit
challenge and exact tenant, Flow/revision, authorization/version/hash,
owner and actor, Task and agent role, provider/slot/model/operation,
approved policy ID/hash, profile ref ID/hash/CAS/generation, route
configuration and deployment digests, requested cost and committed call ID.
Signatures use disjoint domain labels, an exact allowlist of bounded
nonsecret JSON fields, fresh issuance/expiry, duplicate-field rejection
and explicit integer revisions; cross-signed/forged witnesses deny.
The new material and revocation revisions also must be at least the
already independently observed revision floors from the existing
signed readiness adapter; this is in-process rollback protection only.

Only AFTER a genuinely committed reservation is returned may
authorize_reserved() perform the current host readiness plus all four
signed joins. It burns the call ID before any I/O: a lost acknowledgment,
unknown outcome, signature mismatch, unavailable vault or forged claim
denies and makes that ID permanently unrepeatable within this process.
After success it returns an expiring, nonsecret in-memory DispatchPermit
that must be consumed once via consume_for_send() BEFORE any send.
No method in the guard fetches keys, accesses environment variables,
reserves spending, imports LiteLLM, sends a provider request or logs secrets.
Local replay tracking fails closed at a bounded capacity rather than
evicting an uncertain call ID.

## Minimal candidate PRIME-only wiring

1. **main.py lines 340–346**: Install the guard only from trusted host
   configuration after separate proof-root and readback-service enrollment.
   Missing roots/service/credential correlation must deny managed provider
   calls, including workers outside FastAPI. Do not accept signer roots
   or reader endpoints from operator or task input.
2. **llm_client.py lines 193–317, especially 211–245**: Keep v2
   authorize_task, caller-kwargs isolation, role/model limits, lease fences,
   catalog and signed PG budget. Resolve a CURRENT reviewed profile and
   exact deployed route policy from the authenticated Task/Flow, not from
   a symbolic approved record or request body. Move route.provider_kwargs()
   key selection to after the protected dispatch preflight, or bind it
   atomically through the host runtime-key verifier.
3. **llm_client.py lines 304–345**: The authoritative ledger reserve
   must succeed first; give its exact call ID and trusted binding to
   guard.authorize_reserved(). Consume its one-shot permit immediately
   before the single provider send. Denial must not call the provider.
   On denial after reservation, either atomically cancel ONLY if not sent
   and proven cancelable, or preserve/reconcile UNKNOWN. No silent second
   fallback, and no skipping for embeddings or legacy route mode.
4. **model_usage.py and runtime key bridge**: Introduce durable
   cross-replica consumed-ID fencing and current host vault/revocation
   version attestation under the same signed send lease. The prototype's
   local burn list and separate observations are NOT an atomic snapshot.
   Prove that the actual LiteLLM key is exactly the independently
   version-matched protected credential, not merely an env variable whose
   name appears in approved metadata.

Important nuance: existing readiness and the new four observations are
fresh but are **not one cross-source atomic snapshot**, and the
readiness decision does not export the vault version. Rechecking material
and revocation with the same fresh nonce in the new guard helps establish
their mutual version join but does not solve a race between readiness and
runtime key deployment. The host service and durable dispatch fence must
close that gap before any deployment.

## Verification and status

tests/test_provider_dispatch_guard_20261021.py reuses the genuine
seven-root locally signed synthetic readiness fixture, then creates
four additional independent synthetic roots. It checks correct one-use
permit behavior; denied material, revocation, deployed-key version,
generation or route, signed Task/tenant mismatch, insufficient committed
cost, absent signer roots, duplicate/secret-bearing JSON, forged signer,
stale evidence, ACK loss and no-retry after an uncertain provider response.
Negative cases assert no synthetic provider call and no key logging.

No real external vault, enrolled signer, deployed runtime-key verifier,
application DB, Docker, Git operation, target, provider or paid request
was used. **NOT PRODUCTION CERTIFIED / NOT READY** until these missing
protected services, actual dispatched-key binding and cross-replica
transactional revocation/ACK tests are genuinely implemented.

**Focused validation:** 76 new guard tests and 106 earlier provider
lifecycle/runtime/wiring tests passed together: **182 passed, 1 warning**.
Python compileall passed for the new guard source and its test file.
All witnesses were synthetic and all effect boundaries stayed mocked.

Ownership: Only the three NEW files named in this worker assignment
were created. Changes to existing production LiteLLM, main, model ledger,
or credential lifecycle files require PRIME's separate ownership approval.
