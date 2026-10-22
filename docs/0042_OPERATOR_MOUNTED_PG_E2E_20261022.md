# 0042 operator mounted API → isolated PostgreSQL qualification

**Scope and release decision: NOT PRODUCTION CERTIFIED / NOT READY.**

This qualification uses the current original shared dirty checkout without
editing any production code, router, migration, application database, UI or
shared report. The only new artifacts are:

- `tests/qualification/test_0042_operator_mounted_pg_e2e_20261022.py`
- This report.

## What the qualification actually exercises

The **opt-in** `OSOP_0042_OPERATOR_MOUNTED_PG_E2E=1` test boots the existing
disposable nonroot WSL Ubuntu PostgreSQL 16 test helper, with an owned
`/tmp` directory (0700) and a private Unix-domain socket only. PostgreSQL
does **not** listen on TCP. Windows Poetry runs real FastAPI, HTTPX
TestClient, actual Ed25519 validation, `guard_sql`, existing
`OperatorGlobalLibrary._current` locking and
`OperatorReviewedFlowAtomicWriter.store_reviewed_flow_original`. A
parameterized-SQL local **stdio** adapter exchanges SQL with the WSL child.
No application database URL or running application database is used.
Bootstrap executes actual online 0009, 0014, 0019, 0038, 0039, 0041 and
0042 Alembic migrations. Only the predecessor session/Flow and Task
tables are minimal, private disposable fixtures, not the entire app ORM.

The test mounts the **unchanged actual production** reviewed-library router
on a separate isolated FastAPI app, with the real host install functions
and exact same session factory shared by global source and Flow writer.
This is a genuine ASGI → writer → parameterized SQL → real PostgreSQL
transaction/COMMIT; no production main-app lifespan is entered.
It creates **five disposable signing keys**: a JWT-authenticated operator
plus a separate Ed25519 signed test ROE and **four mutually distinct**
Ed25519 signer roots (principal/reviewer/Flow/ROE). Their test callbacks
sign exact claim sets, challenges and short-lived readbacks.
They are synthetic and are **not independently host enrolled services**.

The mounted write attempts only `POST
/flows/{flow_id}/reviewed-library-import/store-reviewed-original`
and separately signs and reads `.../store-reviewed-original/readback`.
The test verifies PostgreSQL persisted the immutable 0041 citation and 0042
inert original in the **same transaction**, that the response contains
only bounded receipt metadata (never the original UTF-8 text), that it
does not assert model prompt, execution, target-evidence or agent approval,
and that an explicit separate readback does not insert again.

Negative cases include unauthenticated request, wrong signed operator
owner, forged request owner, original submitted as an extra JSON field,
forged or revoked mock senior reviewer, changed reviewer between signature
rounds, expired witness, running-Task revision mismatch, updated 0039
immutable source revision and revoked PostgreSQL signed ROE. After the
first successful creation, exact duplicate insert must fail rather than
claim a second successful write. Late readback with changed authorities
must be **409/UNKNOWN**, not auto retry. The persisted inert 0042 original
remains in private PostgreSQL after subsequent authority changes.

**Observed issue and prime-owned fix:** The first private-PG qualification
exposed a caller-supplied forbidden `content` value echoed via default
FastAPI/Pydantic `detail[].input` on HTTP 422. This was not a disclosure of
an existing private PostgreSQL original, but it violated a strict no-text
echo property. Prime subsequently fixed the scoped validation response in
the production `reviewed_library_flow_import` router. The dedicated
regression is now a **normal required-pass test**, not an xfail; this worker
made no edits to that router. Accepted write/readback responses and
authorization/unknown denials also enforce absence of original text.

This exercise is a **single-process, single-connection stdio adapter** to
real PostgreSQL for the main ASGI flow. Sequential stale-revision and
revocation cases do not establish a real concurrent cross-replica
linearizability proof. A separate, instrumented multi-connection
concurrency qualification remains necessary for overlapping source edit/
tombstone, Flow change, token revocation, deadlock/timeouts and uncertain
HTTP delivery. The application UI is not opened or modified; absence of
original text is asserted at the API JSON boundary, not rendered-browser
screen capture. Separate source checks confirm the installed frontend
request carries only IDs, revisions and SHA digests and models the 0042
result strictly as inert metadata without content fields. A 0014 durable
subject-disable-before-readback check verifies the existing authentication
and revocation chain rejects current disabled identity (the mounted API may
deny before the 0042 writer/PG guard; observed HTTP 401). Re-enabling this
disposable fixture subject permits a separately current readback. This does
not prove the signed-ROE guard itself ran for the disabled-user request.

## Run and limitations

Safe no-PG default:

```powershell
poetry run pytest tests/qualification/test_0042_operator_mounted_pg_e2e_20261022.py -q --no-cov
```

Full private-PG opt-in, where nonroot Ubuntu WSL and PG16 exist:

```powershell
$env:OSOP_0042_OPERATOR_MOUNTED_PG_E2E='1'
poetry run pytest tests/qualification/test_0042_operator_mounted_pg_e2e_20261022.py -q --no-cov
Remove-Item Env:OSOP_0042_OPERATOR_MOUNTED_PG_E2E
```

Absence of a real host signer means the original production main-app 0042
routes remain **503** absent separately injected verified roots and exact
database factory. The test-only independently generated private keys and
local JWT secret must NEVER be substituted as deployed enrollment. A
successful response reports a committed PostgreSQL transaction, not
guaranteed client receipt; a lost ACK is UNKNOWN and must be reconciled with
an explicit independent readback rather than a repeated POST.

No external targets, paid providers, Docker, app DB, shared migrations,
operator production keys or Git operations were used.

## Actual execution results (22 October 2026)

| Check | Observed result |
| --- | --- |
| Default no-database qualification | **3 passed, 1 skipped** |
| Nonroot disposable PG16 opt-in mounted ASGI→writer→PG | **4 passed**, 48.54 seconds |
| Black formatting check on new qualification file | **passed** |
| Python bytecode compilation on new qualification file | **passed** |

The opt-in pass includes an accepted original/citation COMMIT followed by
an exact nonmutating readback; forged and expired test signer responses,
wrong owners, duplicate writes and changed Task/source/current 0014 identity
are denied, with persisted content never returned to successful API or UI
receipt fields. Explicit 0042 route response redaction test also **passes**
after prime's existing production-router change.

No live independent signer enrollment, full application ORM/migrations in a
deployed cluster, external IdP, cross-replica race or real browser rendering
has been certified. These are important release blockers despite the tests
passing.
