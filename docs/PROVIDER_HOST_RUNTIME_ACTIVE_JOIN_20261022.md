# Host-only current provider-vault runtime integration — 2026-10-22

**Result: production constructor has an explicit opt-in consumer of separate
host-enrolled signatures and a durable one-use call-fence. No trusted host
material is installed; production defaults to PENDING/DENIED.**

`src/ai_osop/core/provider_host_runtime_slot_20261022.py` defines a process-
local single-assignment host installation function. It accepts **only an actual
`ProviderVaultRuntimeJoin` object** which has independently verified current
host admission and an enrolled durable call fence. The installer never parses
HTTP, environment provider secrets, operator body/config, unreviewed symbolic
provider references, or self-proclaimed booleans. The installed object cannot
be replaced by a later request or reconnect. This module does not generate,
enroll or export keys, signed vouchers, credential material or a new signer.

`api/main.py`'s real production/staging/unknown-mode LiteLLM construction now
reads that trusted host slot during lifespan bootstrap. If empty it **still**
constructs the established `pending_guarded_client` with `ModelUsageLedger`.
If populated, `ProviderVaultRuntimeJoin.construct_client` rechecks current
route policy, independent current host guard/role, enrolled persistent
cross-replica one-use claim-fence and durable ledger before returning a
protected LiteLLMClient. Every actual protected provider call must still enter
the binding factory and burn its separate durable CAS before external send.

Host deployment must explicitly install an externally qualified join in each
worker before lifespan starts. The provider call-fence ledger, key generation,
revocation and one-use claim must be shared across workers, not recreated in
the app process or sourced from user fields. A process-local enrollment object
is **not** itself a cross-replica lock. Only real independent signed receipts,
real current vault bytes and current owner/Flow/Task/ROE permit actual paid
dispatch; none were provided here. After a lost ACK, never automatically retry
unknown payment/tool effects. Actual deployment qualification and external
provider execution remain absent.

Focus: `tests/test_provider_host_runtime_slot_20261022.py`, the existing
actual-main-constructor AST execution/security suite,
`tests/test_api_production_host_vault_pending_20261021.py`,
`tests/test_litellm_constructor_real_wiring_deny_20261021.py`, and
`tests/test_provider_vault_runtime_join_20261021.py` confirm default pending,
invalid/fake installation denied, a synthetic host's branch selection only,
and no direct production unguarded LiteLLM construction. Synthetic AST join is
**not** real host enrollment. No paid provider call, environment secret read,
application DB, external target, Docker, Git stage/commit/push or live vault
was used.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
