# Provider vault runtime join — 21 October 2026

**Release decision: NOT READY.** The host-only join is an opt-in library API.
The production lifespan in `src/ai_osop/api/main.py` still constructs
`pending_guarded_client(usage_store=ModelUsageLedger(session_memory))` outside
development/test. No provider key, actual provider call, host signing identity,
vault secret, real cross-replica PostgreSQL call CAS or credential service has
been provisioned or certified by this work.

## Production path implemented

`src/ai_osop/core/provider_vault_runtime_join.py` provides:

* `ProviderVaultRuntimeJoin(admission=None, call_fence=None)` and
  `.construct_client(usage_store=..., **ordinary_config)`. Missing host
  enrollment or a missing separately enrolled ledger fence produces an actual
  `LiteLLMClient` with `vault_guard_required=True` and no guard/binding
  factory. Direct and indirect paid calls therefore fail before provider,
  environment key lookup, reservation or model effects.
* `EnrolledOneUseCallFence` consumes an **additional** short-lived,
  independent Ed25519 ledger identity. The host root already verified by
  `HostVaultGuardAdmission` must sign a separate ledger enrollment containing
  its deployment ID, ledger public-key hash, and exact service commitments
  from the existing host enrollment manifest. The ledger key must be distinct
  from the 11 dispatch/readiness roots and the host enrollment root.
* For every real post-reservation call ID, `binding_factory` first invokes
  `HostVaultGuardAdmission.binding_factory` to resolve the current protected
  Task, flow, policy and route. Only then does the fence send the complete
  nonsecret `ProviderCredentialDispatchGuard._shared(binding, nonce)` tuple
  to a **host-owned** callback. The response must be signed by the enrolled
  ledger key and include the same nonce and identities, `claim_state =
  committed_atomic_one_use`, positive usage revision, current vault and
  revocation revision floors, version identity, and correct previous-generation
  revocation assertion. The adapter also reads three separately signed,
  current vault-material, revocation and deployed-key witnesses with the same
  nonce. It verifies their credential version, vault and revocation epochs,
  and rotation generation match the ledger claim. The receipt expires within
  five seconds and the host-enrollment lease. Unknown/lost acknowledgments
  burn the call ID locally without automatic retry.
* The underlying `ProviderCredentialDispatchGuard.authorize_reserved` still
  independently checks the seven-root current vault readiness, signed live
  vault material and revocation, deployed runtime credential/version binding,
  and signed already-committed model-budget reservation. Its separate
  `consume_for_send` one-shot permit must be consumed immediately before
  LiteLLM's only attempted provider request. The new fence is an additional
  prerequisite; it does not replace those checks.
* `.health()` only reports codes
  `PENDING_HOST_ENROLLMENT`, `PENDING_DURABLE_CALL_FENCE`,
  `PENDING_CURRENT_HOST_AUTHORITY`, or
  `HOST_ENROLLED_DISPATCH_UNPROVEN`, together with safe next-action text.
  `provider_dispatch_authorized`, `provider_contacted`, and
  `credential_exported` remain **false** in every state. This preflight is
  never proof of a successful remote provider dispatch.

## Host bootstrap integration point (prime-owned)

In the production branch of `api/main.py` near the existing
`pending_guarded_client` construction, after creation of the **actual**
`ModelUsageLedger(session_memory)` and before handing the LLM client to any
orchestrator, worker or planner:

```python
from ai_osop.core.provider_vault_runtime_join import ProviderVaultRuntimeJoin

# host_guard: HostVaultGuardAdmission constructed by independently pinned,
#              host-only verified root/manifest and trusted binding reader.
# call_fence: EnrolledOneUseCallFence constructed with separately enrolled
#             ledger root and a real durable atomic claim reader.
# On unprovisioned installations, both remain None.
join = ProviderVaultRuntimeJoin(admission=host_guard, call_fence=call_fence)
llm_client = join.construct_client(usage_store=ModelUsageLedger(session_memory))
operator_health = join.health()  # nonsecret; do not convert into "provider ready"
```

The above illustrates the approved injection location and parameter shape. It
**must not be pasted as production wiring before enrollment exists**. Neither
`host_guard` nor `call_fence` is created from request JSON, environment
provider secrets or symbolic platform flags. Both must originate from a
protected host runtime trust configuration. Do not expose either constructor
or signer key/reader as a public operator API control. A current manifest
verifies an enrollment for up to 15 seconds; the signed ledger enrollment
expires within that lease. Production needs a trusted renewing enrollment
source. Any renewal/restart with uncertain prior call IDs must retain the
durable external one-use fence and be reconciled before another attempt.

### Ledger service contract required for activation

The independent service must implement **linearizable, persistent and globally
unique** claim-once for the pair `(deployment_id, call_id)`, atomically bound
to the full signed Task/route/ROE/owner/Flow and budget-reservation tuple.
It must reject repeat claims across hosts/replicas, stale authorizations,
concurrent revisions, previous revoked generations that remain active,
revoked current credentials, downgrade to older revision fences, and any
uncommitted/settled/absent PostgreSQL reservation. It must keep a persistent
unknown/consumed outcome after any lost acknowledgment or process crash;
it must not issue signed success until the CAS commits. It must sign a
strictly bounded receipt using the independent enrolled root, and never return
provider credentials or hashes of raw API keys. The nonsecret credential
version SHA-256 is an opaque *version ID*, not a hash of a key.

The join can verify **a signed assertion** of an atomic CAS, but does not
establish that the host ledger really made a durable transaction or that the
signer controls the deployed service. A live implementation, protected
service identity, DB transaction, multi-replica crash/replay tests, and
independent audit are required. Production is NOT READY even if unit fixtures
successfully construct the opt-in client.

### Remaining security/functional gaps

1. No configured real host 12th enrollment root and the separate 13th ledger
   root, independently enrolled reader services, signatures, or persistent
   cross-process call CAS. All positive tests use disposable fixture signers.
2. The new join checks the signed call-fence credential version and epochs
   against independent current signed vault, revocation and runtime-key
   witnesses before returning the binding. The existing
   `ProviderCredentialDispatchGuard` independently rechecks these in its
   subsequent authorization. Rotation could still occur between these reads;
   the guard returns an opaque permit with no version field for a second
   direct comparison to the fence receipt. Real host services must enforce
   an atomic rotation/call-claim fence across the whole dispatch boundary.
3. The current `LiteLLMClient` obtains `route.provider_kwargs()` (and may
   check the provider catalog) after guard admission but before consuming the
   permit. A newer revocation during that window is bounded by proof expiry;
   there is no atomic remote revocation check at the exact provider socket
   write. Host-side key rotation must atomically fence the outbound deployed
   key. Provider acceptance, payment, settlement and remote execution remain
   unproven.
4. The current `HostVaultRuntimeReadinessAdapter` uses a process-local
   revision high-water mark. Multi-instance monotonic revision floors require
   a separately enrolled durable service and must survive restarts.

## Test scope

`poetry run pytest tests/test_provider_vault_runtime_join_20261021.py -q --no-cov`

Tests execute the real `LiteLLMClient._provider_call_admitted` negative path
and actual signed host/guard objects with test-owned keys, matching existing
synthetic fixture semantics. Cases cover absent/expired/mismatched enrollment,
cross-root substitution, spoofed Task/nonce/service commitments, forged and
stale receipts, invalid revisions, wrong rotation/revocation generation,
wrong version metadata, burned duplicates, and no LiteLLM/provider-key send.
No application database, host vault, provider, paid service, external target,
real signature service, Docker, migration, scanner or Git mutation is used.
