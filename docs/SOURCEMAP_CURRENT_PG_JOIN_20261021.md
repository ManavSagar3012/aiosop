# SourceMap current 0035 source → STATUS join qualification

**Date:** 2026-10-21  
**Result:** **PASS within the explicitly limited, migration-derived PostgreSQL scope.**  
**Test:** `tests/qualification/test_sourcemap_real_pg_status_join_20261021.py`

## What actually ran

On Windows, the repository's existing Python virtual environment compiled
**the actual Alembic `upgrade()` operations** of the checked-in **0013,
0015, 0027, 0029, 0033 and 0035** migration modules to PostgreSQL DDL. An
isolated WSL Ubuntu process initialized **fresh PostgreSQL 16**, bound it
exclusively to a temporary, owner-only UNIX socket, and applied that generated
DDL. Minimal explicitly identified FK predecessor tables and the exact
`reject_target_authority_nonce_mutation()` function from 0016 were created
first. No existing application database or repository migration stamp was used.

This qualification deliberately freezes its table contract at **0035**.
Migration **0036** changes the 0029 native grant pair CHECK and requires a
separate online transactional Alembic migration; it was read but **not
applied here**. Any subsequent additive migration (including proposed or
present 0037) is outside this test. This test never assumes `head == 0035`,
`head == 0036`, or any later head. The separate existing 0036 qualification
owns that migration's native grant CHECK behavior.

One synthetic but structurally valid, domain-digested 0027
`status='unknown'` Action and immutable dispatch-attempt event were inserted
alongside a real 0013 BYTEA artifact and real 0015 senior review row. The
artifact SHA, Task manifest/command/authorization digests and source
preflight claims were computed using the currently imported production
canonicalization and manifest helpers. A real Ed25519 key signed the 0035
claim, and the resulting proof hash was stored in the migrated 0035 table.
The **synthetic rows were inserted directly in SQL**. This is a schema and
join qualification; it does **not** assert that the production admission
stores issued those rows.

Two different `psql` backend process identities were observed through the
private socket. Client A committed the 0035 row; its success acknowledgment
was intentionally disregarded. Client B could read the durable committed
record but a second issuance using that same Action/request was rejected by
PostgreSQL uniqueness. An ordinary duplicate insert failed too. The source
preflight immutable UPDATE/DELETE triggers rejected changes. The migrated
original artifact and senior review immutable triggers also rejected updates.

The qualification executed a **test-authored SQL join** against the real
migrated Action, dispatch event, source preflight, senior review, exact
artifact bytes, Task pins, current ROE, current reviewer control and current
lease. It returned the committed original during the valid state, and
returned no row after each of the following changes:

| Case | Actual PostgreSQL result |
| --- | --- |
| Valid source Action/request, exact immutable SHA and active reviewer/lease | PASS: joined once; Action remained UNKNOWN |
| Repeated independent status read | PASS: non-consuming; original preflight count remained one |
| Source issuance after simulated lost acknowledgement | PASS: replay refused; original count one |
| Source preflight UPDATE or DELETE | PASS: migrated immutable trigger rejected |
| Original 0013 artifact or 0015 senior review UPDATE | PASS: migrated immutable triggers rejected |
| Disable independent senior reviewer | PASS: no current join |
| Cancel original execution lease | PASS: no current join |
| Revoke fixture ROE read-only permission | PASS: no current join |
| Change Task's pinned original manifest digest | PASS: no current join |
| Request different original SHA | PASS: no current join |
| Restore valid fixture state | PASS: original joins; no grant row, no settlement |

The returned PostgreSQL record was checked by the **actual production
`SourceMapStatusAuthorityStore._verify_issued`** function, including its
signed-claim hash, immutable binding, current signing key ID and manifest
checks. Forged claim hashes, mismatched signing key IDs and manifest
alterations were rejected. Its exact `STATUS_FIELDS` were signed with
`STATUS_DOMAIN`, using the same issuer signing key as the source proof
(matching the current production `signer()` behavior); the Ed25519 signature
verified and the expected STATUS lifetime was five seconds.

## Measured validation

```text
.venv\Scripts\python.exe -m pytest tests/qualification/test_sourcemap_real_pg_status_join_20261021.py -q -o addopts='' -rs
1 passed, 1 skipped
SKIPPED: Explicit isolated UNIX PostgreSQL opt-in required

Opt-in with OSOP_SOURCEMAP_STATUS_UNIX_PG=1:
2 passed in 16.13s (final expanded real-PG run)
```

The opt-in run verified `SHOW listen_addresses = ''`, an actual PostgreSQL
16 version, an existing `.s.PGSQL.<port>` Unix socket, separate database
client process IDs, and owned process stop/temporary-file cleanup.

To repeat from this Windows workspace without changing the user's permanent
environment:

```powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_SOURCEMAP_STATUS_UNIX_PG']='1'; raise SystemExit(pytest.main(['tests/qualification/test_sourcemap_real_pg_status_join_20261021.py','-q','-o','addopts=','-rs']))"
```

On a nonroot Linux host with local
`/usr/lib/postgresql/16/bin/{initdb,pg_ctl,psql}`, use the same pytest path
and set `OSOP_SOURCEMAP_STATUS_UNIX_PG=1`. Default operation is safe,
with the actual PostgreSQL case skipped unless explicitly enabled.

## Precise limits and outstanding qualification

- **No full production flow.** The full application Alembic chain, real
  `FlowMCPActionStore.prepare/reserve/mark_dispatched`, production
  `SourceMapSourceAuthorityStore.admit`, and
  `SourceMapStatusAuthorityStore.admit` have **not** been qualified together
  in real PostgreSQL here. The dedicated source/status HTTP service bearers
  and actual production router-to-store paths have their separate in-process
  tests; this test does not establish their production deployment identity.
- **SQL join scope.** The test-authored join covers material revocation,
  lease, ROE, original-byte and Task digest predicates. It is **not** a
  substitute for the entire production `_source()` authorization fence,
  signed ROE cryptographic verification, approval payload signature, Flow
  revision serialization, or transaction concurrency across those gates.
  Original 0013/0015 and 0027 rows are synthetically constructed.
- **STATUS signing scope.** PostgreSQL returns the original committed 0035
  row; actual `_verify_issued` vets that row. A test caller signs the
  resulting production-shaped five-second STATUS claim with the same issuer
  key. Production `SourceMapStatusAuthorityStore.admit` is not executed on
  that connection, and no claim is made of production STATUS issuance.
- **ACK-loss scope.** The first client committed successfully and its ACK was
  intentionally ignored before a second client retried; no network
  partition, crash during PostgreSQL commit, or cross-host failover occurred.
- **No 0029 SourceMap grant.** Zero rows were inserted into
  `native_mcp_execution_grants`. 0036's schema identity expansion, any
  0037 binding changes, native redemption, supervision attestations, host
  staging, scans, provider effects, and original Action settlement are
  unverified in this test.

No Docker calls, dependency installation, targets, paid providers, existing
application DB, shared source edits, migrations, central reports, or Git
operations were used.

## Addendum — 0037 live Alembic Operations on isolated PostgreSQL16

**Date:** 2026-10-21

**New qualification:** tests/qualification/test_sourcemap_0037_real_disposable_pg_20261021.py

**PASS: 2 passed in 18.02 seconds**, with explicit opt-in
OSOP_DISPOSABLE_SOURCEMAP_0037_PG=1.

This independent follow-on initializes fresh, nonroot PostgreSQL 16 inside
WSL Ubuntu. Its port is random, TCP listening is disabled, and only a private
Unix socket in a 0700-owned temporary directory is used. Existing Windows
virtualenv **pure Python** SQLAlchemy, Alembic, and psycopg libraries run in
Linux without a dependency installation.

The test invokes the actual checked-in live Alembic upgrade functions for
**0013, 0027, 0029, 0035, 0036, 0037** against precise minimal dependency
tables and the immutable trigger function from 0016. It calls the actual
0037 downgrade on an empty table, verifies success, upgrades again, and
calls the actual downgrade against a nonempty table to confirm transactional
denial without dropping the row.

| Actual 0037 schema behavior | Real PostgreSQL outcome |
| --- | --- |
| Four FK references: Action, original 0035 preflight, 0029 grant, 0013 artifact | PASS; missing reference refused (23503) |
| Four unique columns: Action/request/preflight/grant | PASS; each collision refused (23505) |
| Two independent SQLAlchemy/psycopg clients race an exact duplicate binding | PASS; one commit and one 23505 |
| Three CHECK constraints: bounded IDs, inert bound_only state, valid hashes | PASS; invalid rows refused (23514) |
| Immutable UPDATE/DELETE trigger | PASS; changes refused (P0001) |
| Actual empty 0037 downgrade and reupgrade | PASS; table drops only while empty |
| Actual 0037 downgrade with a committed binding | PASS; refused, table and record preserved |
| Original Action state after binding | UNKNOWN remains unchanged |

**Evidence limit:** All 0013/0027/0029/0035 parent records are explicit
synthetic SQL fixtures. This is a real constraint and Alembic migration test,
not positive production SourceMap execution or grant issuance. It does not
invoke a production Action dispatcher, native grant issuer, source/status
router, native redemption, verifier, external target, or provider. The four
foreign keys protect referenced row existence; they do not enforce equality
of repeated tenant, owner, reviewer, artifact SHA, or authorization fields
across those references. That semantic join remains a separate central
verifier responsibility.

Without the explicit opt-in, test collection is safe: **1 passed,
1 skipped**. To repeat the real PG test on this Windows host:

~~~powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_DISPOSABLE_SOURCEMAP_0037_PG']='1'; raise SystemExit(pytest.main(['tests/qualification/test_sourcemap_0037_real_disposable_pg_20261021.py','-q','-o','addopts=','-rs']))"
~~~

Teardown stops the exact owned PostgreSQL instance and removes its
temporary files. No Docker, application DB, package installation, paid
provider, target, production deployment, shared source, or Git operation.
