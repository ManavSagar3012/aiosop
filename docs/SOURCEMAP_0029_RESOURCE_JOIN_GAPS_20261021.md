# SourceMap 0029/0030 resource-join gaps — 21 October 2026

**Status: BLOCKED / FAIL CLOSED.** This is a source-based design and isolated
negative-test qualification, **not** an issued/redeemed SourceMap native grant,
live 0027/0029/0030/0033 transaction, host file staging, application migration,
or evidence of execution on any target. The independently reviewed 0036
PostgreSQL CHECK permits one SourceMap row *shape*, not permission to create a
row, transfer original files, or declare a supervised worker running.

## 1. Concrete runtime and schema inventory

| Existing authority | Actual source and durable facts | What it does **not** authorize |
|---|---|---|
| **0013 original bytes** | `migrations/versions/0013_flow_artifacts.py`: `flow_artifacts` has tenant/Flow/owner, immutable `content BYTEA`, `id`, name, size, original SHA, Flow revision, authorization version/SHA; `trg_flow_artifact_immutable` prohibits mutation. SourceMap `SourceMapSourceAuthorityStore._original_manifest` executes `octet_length(content)` and `encode(sha256(content),'hex')` **inside PostgreSQL**, refuses size/SHA mismatch, and selects exactly one artifact with the requested SHA. | A content hash or immutable row is **not** a senior approval, a grant for a native worker, or a filesystem-stage entitlement. |
| **0015 independent review** | `flow_artifact_reviews` pins artifact ID/SHA and signed Flow revision/authorization; `_original_manifest` requires `approve`, `senior_operator`, a reviewer distinct from uploader, and a currently enabled `operator_subject_controls` reviewer. | A reviewer row does not independently authorize staging, 0029 grant redemption, or a target/network action. |
| **0026 virtual catalog** | `migrations/versions/0026_flow_resource_folders.py` creates owner/tenant/Flow catalog with CAS revision, manifest SHA, folder names and artifact-ID/SHA assignments; event history is immutable. `approved_folder_stage_plan` (`native_mcp_folder_stage.py`) requires the **reviewed Task** `mcp_folder_catalog_revision` plus `mcp_folder_staging_sha256`, independently current 0026 catalog, complete artifact assignments, then hashes a canonical stage plan. | Without **both** pins it is RAM-only; a folder catalog alone is not a physical mount, supervisor observation or SourceMap host authorization. A partial pin is malformed and denied. |
| **0027 irrevocable Action** | `flow_mcp_action_dispatches`, `flow_mcp_action_dispatch_events` (`0027_flow_mcp_action_dispatch.py`); native and SourceMap source validators require original Action `status='unknown'`, not cancelled, same signed tenant/Flow/Task/Subtask/reviewer/lease, and a durable `dispatch_attempted` event bound to original intent. SourceMap additionally rechecks exact source request/Action digest (`_intent`) and `receipt_sha256 IS NULL`. | UNKNOWN means the original call **may already have happened**; neither grant issuance nor a missing ACK permits re-invoking the Action or converting UNKNOWN to safe-to-retry. |
| **0029 signed native grant** | `native_mcp_execution_grants.py`: Ed25519 domain `ai-osop/native-grant/v1\x00`, *exact 19 claims* including `grant_id`, Action/request/tenant/Flow/Task/Subtask, `server_id`, `tool_name`, `parameters_sha256`, `manifest_sha256`, `authorization_*`, lease, `resource_sha256`, timestamp and `side_effect_class`. Original Action/approved Task are rechecked under transaction; distinct Action/request unique constraints, immutable events, short TTL, signed token, and revision/status CAS prevent double issue/redeem. `manifest_sha256` is **original declaration hash**, whereas `resource_sha256` is the **resource manifest hash**. | It has no original **artifact ID**, 0035 **preflight ID**, native stage source/issuer association, or source-specific signed Task/offer join. Current `_validate_claims` pins Go's `authority_status` with **empty `{}`** params and exact builtin declaration. `_require_operational_pair`, `_original`, `_resources`, and `_verify` still reject SourceMap. |
| **0030 one-shot byte offer** | `native_mcp_resource_delivery.py`: authenticate native service and `_verify(token)`, require **redeemed** 0029 grant with non-null `resource_sha256`, recheck original signed authority and `_resources`; read/revalidate all senior-reviewed BYTEA, `make_manifest`, optional 0026 stage plan, then **INSERT once** into immutable `native_mcp_resource_offers` (PK grant_id, UNIQUE request_id, status `offered`) **before returning any base64 files**; lost response is UNKNOWN. | Returning an envelope/recording an offer is **not** proof a process received, staged or examined bytes. No documented authenticated SourceMap host-only provisioning, mounted-original readback, or safe transport into that process is established by this generic Go-native route. |
| **0031 folder SHA** | Adds nullable `folder_staging_sha256` to 0030 offer, derived only from a complete current approved 0026 plan. | NULL is expressly RAM-only; non-null digest is *also* not host-stage or readback proof. This is **not** SourceMap's host signer/one-use journal. |
| **0033 native supervisor** | `native_mcp_worker_supervision.py` requires an independently authenticated and Ed25519-signed observation, a verifiable **0029 token**, current original Action/Task/Flow/lease, 0030 offer + stage receipt consistency, dedicated epoch sequence and revision CAS, immutable signed-hash event. Running requires a **redeemed** grant; resource-bearing running requires an offered resource. Current worker identity/container/folder must agree with the grant. | A caller assertion, historical 0033 row, self-reported readback or only an issuer bearer **cannot** replace current independently signed supervisor/process observation. Present source never obtains a valid native SourceMap grant for this route. |
| **0035 SourceMap preflight** | `native_sourcemap_source_preflights` has independent Ed25519 domain `ai-osop/sourcemap-original-preflight/v1\x00`; single immutable preflight per `request_id` AND `action_id` with `preflight_id`, artifact SHA, manifest SHA, reviewer/lease, original Action, TTL at most **10 seconds**. `SourceMapSourceAuthorityStore._source` recomputes exact original original-byte SHA, checks signed Task's `resource_artifact_id`, `resource_artifact_sha256`, `resource_authorization_sha256`, `resource_command_sha256` and `resource_manifest_sha256`, signed ROE and active reviewer/lease. | No `grant_id` or FK to 0029; no atomic linkage to 0030 resource offer or 0033 current supervision. This preflight's signature is **not** a 0029 native grant signature. Reissue after UNKNOWN/ACK loss is prohibited. |
| **0036 CHECK-only** | `0036_sourcemap_native_grant_pair.py` replaces **only** `ck_native_mcp_grant_inert_tool`: `READ_ONLY` and either one of six pinned Go IDs with `authority_status`, OR `source-map-mcp/inspect_local_original_sourcemap`. The migration checks existing rows under an exclusive table lock and refuses downgrade if SourceMap grants exist. | A syntactically legal PostgreSQL row is not an admitted issuer, signed token, native resource delivery, current supervisor, or authority to replay 0027. Runtime still denies SourceMap. |

## 2. Exact mismatch — digest equality is not authorization equality

SourceMap's `_metadata_manifest` reconstructs `ai-osop-inert-flow-resources-v1`
metadata with `artifact_id`, approved file name, SHA, size and classification;
generic `flow_resource_exports.make_manifest` hashes the **same canonical
base** after reading and validating BYTEA. **For valid benign text, the two
manifest SHA-256 values can be identical.** The focused test demonstrates
this actual equality. Thus a blanket claim of "incompatible hash algorithms"
would be incorrect. The *attestation and Task-pinning paths* do not coincide:

| Required binding | 0035 SourceMap original source | 0029/0030 Go-native resource source |
|---|---|---|
| Selected artifact | Task `resource_artifact_id`, SHA `resource_artifact_sha256`; one original matching 0013 SHA | Generic all-artifacts snapshot manifest `mcp_resource_sha256`; not pinned to a specific SourceMap artifact ID by a grant claim |
| Declared command | Task `resource_command_sha256` equals Action `parameters_sha256` (SourceMap uses `{artifact_sha256}`) | 0029 builtin expects canonical `{}` params and `authority_status` declaration SHA |
| Reviewed original manifest | Task `resource_manifest_sha256` plus `resource_authorization_sha256` | Task `mcp_resource_sha256`, with optional separate `mcp_folder_catalog_revision` and `mcp_folder_staging_sha256` |
| Signature purpose | 0035 SourceMap original preflight and limited 10-second source verification | 0029 grant domain and issued/redeemed state, then 0030 one-shot byte offering and separate 0033 supervisor observation |
| Receiver and stage | Host-only original/read-only staging needs its own independently reviewed authority, readback and irreversible journal | 0030 `content_b64` envelope and optional 0031 folder SHA; *worker-reported* 0032 receipt is not host-observer proof |

**Concrete bypasses forbidden:** (1) treating a SourceMap Task's
`resource_manifest_sha256` as if it automatically supplied
`mcp_resource_sha256`; (2) supplying null `resource_sha256` so `_resources`
skips the artifact check; (3) allowing a 0035 preflight to masquerade as
`DOMAIN = ai-osop/native-grant/v1\x00` or redeem against 0029 without its
signature; (4) accepting a 0031 `folder_staging_sha256` as proof of staged
original SourceMap bytes; (5) declaring 0033 running without a real redeemed
grant, durable offered original and independently signed process observation.

### Independent uniqueness does not mean cross-table atomicity

`0029` enforces one `action_id`/`request_id` per grant; `0030` enforces one
offer per grant/request; `0035` enforces one preflight per Action/request.
**There is no existing FK or unique cross-table claim joining 0035 to 0029,
0030 and 0033.** Independently successful inserts in different tables could
otherwise create incompatible custody or replay beliefs. A preflight alone
must never be regarded as an already-redeemed grant/host byte receipt.

## 3. Minimal defensible extension — **proposal only; NOT implemented**

1. **One coordinating owner and additive join:** After verifying the actual
   live Alembic head and negotiating ownership, add an immutable,
   transactionally enrolled *SourceMap-grant binding* (separate additive
   migration; do not widen 0036) with `grant_id` unique FK to 0029,
   `preflight_id` unique FK to 0035 **only after the one-preflight/bootstrap
   dependency is safely resolved**, and original `action_id`, `request_id`,
   tenant/Flow/Task/Subtask/owner, reviewer/lease, authorization version/SHA,
   declaration/parameters SHA, original artifact ID/SHA, whole resource
   manifest SHA, command SHA, signed source claim SHA and signing authority.
   Enforce unique Action/request at the *join owner*, compare to the actual
   original row and source proof; no caller-controlled source facts. Preserve
   append-only audit and CAS. Do not mint a competing preflight to satisfy
   the join, or enforce an impossible circular FK at first-use startup.
2. **Exact typed SourceMap 0029 issuer/validator**: only the literal 0036
   SourceMap pair, `READ_ONLY`, current signed 0027 UNKNOWN and independent
   `dispatch_attempted`, current signed Flow/ROE/Task/Subtask, live reviewer,
   human-approved original artifact and command SHA, original BYTEA SHA
   recheck, bounded manifest and lease. Bind actual SourceMap declaration SHA
   to 0029 `manifest_sha256` and *separately* approved original resource
   manifest to `resource_sha256`; never substitute a declaration for bytes,
   forge Go builtin `{}` or accept unsigned callback booleans. Issue exactly
   one grant under the Action lock with one-use CAS and Ed25519 native grant
   signature; per-service native bearer never controls issuance.
3. **One-use original-byte offering and stage contract:** Decide explicitly
   whether to implement a *separate host-only* immutable source offer (safer,
   given current SourceMap provisioner) or formally support SourceMap in
   0030/0031 with a new signed Task pin and exact same canonical bytes. Any
   compatible path must attest the selected 0013 artifact ID, original byte
   SHA, whole Task-pinned manifest, current 0026 folder catalog/assignments if
   staging requested, signed host-only receiver and a durable one-use request
   tombstone *before* crossing the byte boundary. The existing RAM-only
   0030 envelope or folder digest is insufficient. Never send issuer credentials
   into a native worker. Require independent host readback/immutable journal.
4. **Current independent 0033 source and first-use bootstrap:** Link the exact
   signed grant, source offer and independently signed supervisor admission to
   immutable 0033 events, monotonic epoch/CAS and current process/container,
   read-only mount and worker identity. Resolve the existing “current 0033
   authority before first 0035 preflight / 0035 proof before 0033 status”
   bootstrap dependency via a separately reviewed **non-consumptive**
   bootstrap attestation and one authoritative issuer. Then require freshly
   signed current status *after* the one 0035 commit. No historical event-only
   proof, caller PID or unsigned acknowledgement.
5. **Hard stops and crash qualification:** Never replay 0027 UNKNOWN on
   communication loss; 0029 issue/redeem, 0030/host source offer, 0035
   preflight and stage journaling each have exclusive one-use CAS. Revoke
   Flow/ROE/reviewer/Task/lease/0026 assignment between each boundary and
   assert failure before bytes/capability use. On duplicate or lost ACK,
   reconcile read-only and return UNKNOWN rather than minting another token or
   staging again. Keep six existing Go authority-status grants unchanged.

The above must be coordinated across the **actual** native grant issuer/store,
source authority, 0030 offering or new host-offer owner, 0026 stage plan, 0033
independent supervisor, and 0035 original authority. Merely editing a CHECK,
grant claim validator, existing Task JSON, or SourceMap native transport in
isolation is not production-ready.

## 4. Focused qualification and limitations

`tests/qualification/test_sourcemap_grant_offer_consistency_20261021.py`
tests the actual `0036` SQL predicate with isolated SQLite, actual runtime
SourceMap denial despite schema acceptance, strict 19-claim 0029 domain,
missing 0035↔0029/0030/0033 FK/join, manifest *equivalence* without authority
equivalence, rejection of SourceMap's Task fields by the **actual** generic
`_resources` checker, rejection of absent/partial approved folder pins by the
**actual** 0026 plan, failure on bad original BYTEA digest via a scripted
read-only DB response, 0033 denial of inconsistent 0030 offer, and separate
0035 one-use semantics. These are static and isolated **negative** tests.

**Evidence boundary:** No real PostgreSQL application instance was queried;
no live 0027/0029 issuance, 0030/0035 commit, native or host staging, current
0033 process observation, provider, target or Docker execution was performed.
Existing separate disposable-PG tests of literal 0036 CHECK and Alembic DDL
do not certify the missing cross-table SourceMap production authorization.
