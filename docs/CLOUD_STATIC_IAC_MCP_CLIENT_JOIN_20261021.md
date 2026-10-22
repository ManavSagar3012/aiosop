# Cloud MCP real HTTP interoperability — isolated local static-IaC

**2026-10-21 · Original heavily dirty `/burp_mcp/ai-osop` · NOT PRODUCTION
CERTIFIED / NOT READY**

## Actual registry/transport join

The new qualification
`tests/qualification/test_cloud_static_iac_actual_mcp_client_join_20261021.py`
starts the existing Cloud FastAPI app on a **test-owned numeric
`127.0.0.1:<ephemeral>` socket**, uses `MCPRegistry.register_server` and
`initialize_server` with a test-only operator-pinned bearer, and observes
the *real* `/health` and `/mcp/initialize` HTTP responses through the
registry's `aiohttp` client. The manifest negotiates exactly the bounded
`scan_local_iac` tool, declared `READ_ONLY`, `scope_check=true`,
`requires_approval=true`, and `local_iac_static_unverified` capability.
This confirms HTTP initialization interoperability, not Task authorization.

The original MCPRegistry sends `timeout_override: null` as part of its
serialized `MCPExecuteRequest`; the original Cloud FastAPI `_ExecuteRequest`
strictly rejected that otherwise valid registry field. Cloud now defines a
strict optional `timeout_override` with bounded validation (1–70 seconds
when present), without accepting remote path/target/provider parameters.
This is a protocol parsing compatibility fix, **not** an authorization grant
or execution enabling switch.

`MCPRegistry.execute_tool('cloud-mcp', 'scan_local_iac', {})` using this
test connection **fails closed when there is no signed original Task,
engagement-specific ROE, independent approval or durable tool-budget
admission**. The loopback server observes **zero `/mcp/execute` requests**
from that denied registry dispatch. We did not install an artificial success
budget callback, mint a fake ROE/Task or alter the registry/protocol/main to
evade this gate. An API bootstrap session cannot call this approval-required
static scan: `check_tool_authorization` explicitly restricts bootstrap
operations to inert discovery/health only.

## Direct host-authorized local server execution — separate from registry

As a distinct **local native-server** check, the test supplies the server's
configured test bearer directly over loopback HTTP to `/mcp/execute`. The
Cloud API requires a test-owned absolute Terraform root, local Checkov
interpreter, enabled opt-in, strict empty scan parameters, and bounded wire
bytes. Unknown bearer is rejected; a caller-selected target or cloud account
is rejected with 422. The successful direct call uses the already present
`.runtime/checkov-venv/Scripts/python.exe` (Checkov `3.3.30` installed) and
only a fresh synthetic `aws_s3_bucket` `.tf` file under pytest `tmp_path`.
It executes real Checkov against an **independently frozen private snapshot**
and returns actual Checkov findings with `STATIC_IAC_ONLY`,
`CHECKOV_LOCAL_IAC_UNVERIFIED`, `live_cloud_account_verified=false`,
`target_effect_verified=false`, and bounded source-manifest SHA-256.

The synthetic `aws_s3_bucket` is a local text declaration, **never an AWS
resource created, read, checked remotely or owned by any cloud account**.
Checkov has no permission to prove that the declared resource exists. No
AWS/Azure/GCP key, cloud principal, cloud inventory or remote security target
was configured or queried. The scanner's `--skip-download` and
`--download-external-modules false` flags, filtered env and Python socket
audit hook are defense in depth; **they do not independently certify OS
network isolation**. Do not treat the direct host-bearer test as an
authorized `MCPRegistry` production execution.

If the pinned local Checkov interpreter is missing, only the positive
direct-Checkov test skips. All registry/deny and unconfigured-503 cases remain
useful without it. No runtime packages are installed by the tests.

## Current missing production wiring: precise non-bypass mount hook

The existing `src/ai_osop/api/main.py::configured_mcp_server_specs()`
already contains a `cloud-mcp` entry using the central
`settings.cloud_mcp_auth_token`, host and port. Cloud's host-side bearer is
currently read from `OSOP_CLOUD_MCP_BEARER_TOKEN`; these must be provisioned
consistently by **trusted operator host configuration**, not an HTTP body,
user-selectable path, UI field or untrusted tool metadata. The registration
server itself must be the exact owned loopback service and the verified
Checkov/root must be operator-pinned. Never surface bearer bytes in fleet
readiness/UI or pass them in a URL.

More important, even with that configured transport/health handshake,
`MCPRegistry.execute_tool` must receive the original durable
engagement/Task/Flow/signed ROE/approval/budget **from its already existing
central authorization and execution-event machinery**. See
`src/ai_osop/mcp/protocol.py::MCPConnection.execute` and
`src/ai_osop/mcp/tool_budget.py::check_tool_authorization` and
`check_tool_budget`. No equivalent authority can be minted by the Cloud MCP
server's local bearer or by a global bootstrap `register_server` call.
The next integration owner must use the existing authorized Task-scoped
dispatch path and independently verify its original signed records and quota
before invoking the Cloud tool. If any part is absent, keep execution
**unavailable**. This worker did **not** edit main, protocol, registry, the
central credential router, UI, workers, database or release reports.

## Commands and exact evidence

```powershell
& .venv/Scripts/python.exe -m pytest -q -o addopts= --tb=line tests/qualification/test_cloud_static_iac_actual_mcp_client_join_20261021.py
# 3 passed; real loopback HTTP, real MCPRegistry initialization,
# protected denied registry execution, and separate real local Checkov run

& .venv/Scripts/python.exe -m pytest -q -o addopts= --tb=line tests/qualification/test_cloud_static_iac_current_bytes_20261021.py
# 8 passed; synthetic current-byte/frozen-subprocess, stage tampering and cancellation checks

& .venv/Scripts/python.exe -m pytest -q -o addopts= --tb=line tests/test_cloud_local_iac_mcp.py tests/test_cloud_mcp_preparse_body_20261021.py tests/qualification/test_cloud_static_iac_actual_mcp_client_join_20261021.py tests/qualification/test_cloud_static_iac_current_bytes_20261021.py
# 13 passed: 11 new qualifications plus 2 adjacent Cloud regressions
```

The linked current-byte custody report documents exact source confinement,
staging, readback and residual gaps. This test does not qualify live cloud
IAM, a target-side effect, independent signed operator deployment, or a
production 11-service MCP dispatch certificate. **NOT READY.**
