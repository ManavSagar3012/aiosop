# Cloud MCP: local Terraform static-IaC qualification (2026-10-21)

**Verdict: BOUNDED LOCAL ASGI/SYNTHETIC CHECKOV CONTRACT VERIFIED AND AN
EXISTING REAL LOCAL CHECKOV 3.3.30 FIXTURE REGRESSION PASSED; NOT LIVE CLOUD
IAM/ACCOUNT VERIFIED; NOT PRODUCTION CERTIFIED / NOT READY.**

## Original implementation and actual mounted contract

Inspected `mcp-servers/python/cloud_mcp.py` in the original heavily dirty
`/burp_mcp/ai-osop` checkout (the file had pre-existing uncommitted changes).
It mounts `GET /health`, `POST /mcp/initialize`, `POST /mcp/execute` with a
single optional operation `scan_local_iac`. This is **not** the previously
advertised `analyze_iam_trust_policies`/live-account path and is not a usable
cloud account/remote provider MCP capability.

An actual successful operation requires the host to opt in with
`OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED=1`, absolute operator-pinned
`OSOP_CLOUD_MCP_IAC_ROOT`, absolute interpreter
`OSOP_CLOUD_MCP_CHECKOV_PYTHON`, and a 32–512 ASCII-byte
`OSOP_CLOUD_MCP_BEARER_TOKEN`. The process checks an exact bearer, strict
8,192-byte pre-Pydantic JSON (duplicate-key and nonfinite-number rejection),
empty caller parameters, syntactically constrained `req-*` request id, local
`.tf`-only pinned input tree (1–50 entries, max 1 MB bytes, no accepted
symlinks), and input manifest SHA-256 before and after scanning.

The Checkov runner, **when a working operator-pinned Checkov environment is
actually present**, launches a Python interpreter for Terraform JSON results
with `--skip-download --download-external-modules false`, a fresh disposable
home, blank `BC_API_KEY`, a short allowlist of process variables, a 2 MB stdout
cap, 60-second stdout timeout and 5-second exit-wait timeout; an unfinished
process is killed in `finally`. The scan is static only. The returned source
is `CHECKOV_LOCAL_IAC_UNVERIFIED`, with every finding marked
`STATIC_IAC_ONLY` and `live_cloud_account_verified=false` and
`target_effect_verified=false`.

The host bearer is a **locally configured service credential**, not proof of
independently signed end-user identity, current tenant/Flow/Task/ROE, scoped
cloud IAM consent or remote target ownership. The Cloud MCP server itself does
not perform an AWS/Azure/GCP API call or contact a cloud IAM identity. Full
orchestrator tool authorization and release gates are separate and were not
qualified by these isolated ASGI tests.

## New qualification and evidence boundary

`tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py` loads the
**actual** Cloud FastAPI app with `httpx.ASGITransport` (no socket/listener).
It creates and destroys an inert Terraform file under `tmp_path` and uses
`monkeypatch` to configure the host. An `AsyncMock` replaces `_scan` in the
successful ASGI test. To examine the **actual** `_scan` command-line and
environment-building logic, `asyncio.create_subprocess_exec` is replaced with
an in-process fake pipe/process. **This new qualification file invokes no
real Checkov subprocess, cloud account, external target, provider, network
request, app database, Docker or package installation.** Separately, the
existing `tests/test_cloud_local_iac_mcp.py` was also run in the combined
regression: it invoked an *already installed* local Checkov interpreter on
its preexisting inert Terraform fixture (see environment results below).

Verified test cases:

1. Unconfigured `/health` returns 503; initialize advertises zero tools and
   execute returns `local_iac_unavailable`, without trying the scanner.
2. With a strictly test-owned pinned tree, an unsigned or bad bearer fails
   401; valid host bearer yields a strictly **static/unverified** mocked result
   with exact input-manifest hash and no fake target effect.
3. Arbitrary caller paths, directories, framework selection, non-`req-*`
   identifiers, extra fake cloud verification assertions, duplicate JSON
   fields, oversized input, NaN/nonfinite numbers, and non-JSON media cannot
   promote a scan or alter its pinned source.
4. Non-`.tf` files, more than 50 files, greater than 1 MB, native links (when
   the test host permits creating symlinks) and **simulated** symlink detection
   reject the source before any scanner runs. The symlink simulation is not
   claimed as a physical filesystem escape qualification.
5. Modifying the Terraform input mid-scan forces `scan_unknown` 503 at the
   final manifest readback.
6. Source parsing accepts known `.tf` paths rooted in the pinned directory and
   rejects nonexistent, non-Terraform, traversal and Windows drive paths. The
   mocked Checkov runner verifies no host cloud credential environment is
   forwarded, no remote modules are requested in CLI options, a disposable
   home is used, and oversize/timeout paths kill an unfinished fake child.

The NEW test is an isolated unit/ASGI **contract qualification**. Its fake
process only proves the code builds these arguments and bounds. The existing
local Checkov regression adds genuine static Terraform parsing/finding results
from a pre-existing fixture, but **neither test proves OS-level network
isolation or enforces a network sandbox for a subprocess**. The Checkov
invocation used `--skip-download --download-external-modules false` and a
restricted subprocess environment. We observed neither network traces nor any
live cloud IAM evidence and cannot certify absence of outbound network traffic
merely from command flags. No remote cloud account credentials should be used.

## Demonstrated fail-closed production corrections

Two demonstrable gaps were found and narrowly corrected in
`mcp-servers/python/cloud_mcp.py`, preserving its original app, routes and
service contract:

- `_ExecuteRequest` previously silently ignored arbitrary additional request
  properties, including `live_cloud_account_verified=true` and
  `target_effect_verified=true`. Although the server output did not echo those
  claims, accepting forged intent creates an ambiguity and a potential
  downstream call-contract confusion. `model_config=ConfigDict(extra='forbid',
  strict=True)` now rejects all unknown fields before `_scan`.
- `_findings` previously stripped leading slashes from scanner-reported file
  names without verifying that they identify a present Terraform file inside
  the operator-pinned root. A malformed JSON report could label an arbitrary
  absolute drive or nonexistent path as a local IaC finding. The parser now
  takes the operator-pinned root, checks canonical confinement and `.tf`
  existence/non-symlink and refuses drive-colon paths, while allowing
  Checkov's expected root-relative `/main.tf` convention. The result still
  remains **unverified static source**.

Neither correction constitutes a remote target/cloud security proof.

## Environment / exact local commands and results

The main Windows repository `.venv/Scripts/python.exe` environment had
`httpx` but no importable `checkov` module or `checkov` on PATH. A subsequent
explicit file check, however, confirmed the **separate already installed**
`.runtime/checkov-venv/Scripts/python.exe` and its
`checkov-3.3.30.dist-info` package. Therefore the existing
`tests/test_cloud_local_iac_mcp.py` **did run actual local Checkov** against
its existing inert `tests/fixtures/local_iac` Terraform sample. It passed
with static findings, including both `CKV_AWS_*` and `CKV2_AWS_*` IDs. The
package directory establishes an installed version label, not an independently
verified artifact hash/lockfile pin or network-isolation certification.

```powershell
& .venv/Scripts/python.exe -m pytest -q -o addopts= --tb=line tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py
# 17 passed, 1 skipped (host cannot create native symlink)

& .venv/Scripts/python.exe -m pytest -q -o addopts= --tb=line tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py tests/test_cloud_local_iac_mcp.py tests/test_cloud_mcp_preparse_body_20261021.py
# 19 passed, 1 skipped (native symlink); includes 1 ACTUAL local Checkov 3.3.30 regression

& .venv/Scripts/python.exe -m py_compile mcp-servers/python/cloud_mcp.py tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py
# passed
```

No package was installed, no app DB/cloud provider/target was contacted by the
Cloud MCP API test, and the new qualification's process was entirely mocked.
The actual local Checkov process from the existing test is **not** evidence of
independent live cloud IAM or a network-isolated Checkov sandbox.

## Required next independent qualification

Before any release claim: verify the installed Checkov interpreter's full
artifact pin/integrity and enforce an offline network sandbox and separate
unprivileged worker; test its
actual `.tf` report path forms and exact root attribution; add bounded
subprocess life-cycle failures (spawn errors, cancellation/kill/reap, output
backpressure); prove hard reparse/junction parent and TOCTOU confinement on
target OS; and validate current operator/ROE/tenant/Task binding through the
registered fleet with no reusable cloud credentials or remote effects. Cloud
IAM read/write capabilities would require separate independently approved
scope, owner identity and tool-specific authorization, not a label change.

**Final decision: New isolated ASGI/mock-Checkov contract plus a distinct real
local Checkov 3.3.30 inert-fixture regression passed. Live cloud IAM, target
effects and network isolation remain UNVERIFIED. NOT PRODUCTION CERTIFIED /
NOT READY.**
