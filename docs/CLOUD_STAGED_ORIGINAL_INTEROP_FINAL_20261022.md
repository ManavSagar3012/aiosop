# Cloud MCP staged-original interoperability — final narrow qualification

**Date:** 2026-10-22  
**Repository:** Original heavily dirty shared `/burp_mcp/ai-osop`  
**Conclusion:** Local static-IaC snapshot and existing Checkov/HTTP interoperability
are supported by the tests below. **NOT production/cloud-IAM certified.**

## Exact scope and change

Only the previously obsolete original qualification test was modified:
`tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py`.
This report is the only new artifact for this follow-on. **No production
`mcp-servers/python/cloud_mcp.py`, application main, registry, protocol,
configuration, tests owned by other workers, database or UI code was edited.**

The prior test `test_actual_scan_command_is_strictly_local_subprocess_environment`
required the mocked Checkov invocation to use `--directory` and subprocess
`cwd` equal to the **mutable operator-pinned source root**. That assertion
had become incorrect after Cloud MCP was hardened to scan a private staged
copy of the exact manifest-checked source bytes. The old assertion failed
for the correct security behavior; reversing the staged production logic
would have reopened the read-time/source-manifest race.

The reconciled test now inspects the fake subprocess invocation while the
temporary private stage exists. It requires:

- `--directory` and `cwd` resolve to the **same private
  `osop-checkov-stage-*` directory**, distinct from the operator source;
- The stage's actual `main.tf` bytes equal the operator test fixture's exact
  original bytes at process invocation (not only the same filename);
- The subprocess interpreter/argv retain `Checkov().run()`, Terraform-only
  framework, `--skip-download`, and `--download-external-modules false`;
- The subprocess environment excludes test-injected AWS/Azure/GCP credentials
  and clears `BC_API_KEY`, while `HOME`, `USERPROFILE`, and `PYTHONPATH`
  refer to an isolated disposable Checkov home;
- The original Terraform fixture is unchanged and both the staged source
  directory and disposable home are gone when `_scan` completes.

**Important evidence distinction:** In this one repaired subprocess test,
`create_subprocess_exec` is monkeypatched with a fake process. It validates
the real production command assembly, stage creation and cleanup; it does
**not** execute Checkov or certify network isolation. Real Checkov execution
is evidenced separately by the existing test listed below.

## Additional adversarial coverage in this owned test

`test_native_hardlink_escape_denies_before_any_scanner_call` creates an
outside-of-root, **test-owned inert** `.tf` file and adds a native hardlink
inside the approved source tree. On this host the hardlink was created;
the actual Cloud app returned HTTP **503** `local_iac_unavailable` before
calling the mocked scanner. This exercises the `st_nlink != 1` fence in
the live source-read path; no private data or real-world target is used.

`test_private_stage_digest_tamper_rejected_before_http_success` patches only
the fake frozen-scanner function to mutate its **private stage copy after
snapshot creation**, without touching the original fixture. The actual
Cloud ASGI route returns HTTP **503** `scan_unknown`, the private stage
gets removed, and the original source bytes stay unchanged. This exercises
the private-stage post-scan digest check rather than falsely accepting a
finding with the original manifest. The existing tests also cover an
original-source digest change during scanning and a source-copy admission
race; these remain fail-closed.

The original test's physical symlink escape attempt is **SKIPPED** because
this Windows test identity could not create the native symlink without
additional privilege. The simulated `Path.is_symlink` fail-closed test in
the same file **passes**, but does not replace a true Windows reparse/
junction/symlink escape qualification. This limitation is explicit.

## Joined real local Checkov + registry HTTP evidence

The final command exercised these five existing/new qualification modules
without source edits to the other modules:

| File | Actual coverage |
| --- | --- |
| `test_cloud_local_iac_inert_runtime_20261021.py` | Repaired stage-based fake process, test-owned ASGI, malformed/oversized JSON, bearer, simulated/native link attempt, native hardlink and digest mutation |
| `test_cloud_static_iac_current_bytes_20261021.py` | Private stage/current-byte checks, original and staged mutation, hardlink, invalid timeout/target parameters, mocked spawn/cancellation cleanup |
| `test_cloud_static_iac_actual_mcp_client_join_20261021.py` | Real ephemeral `127.0.0.1` ASGI HTTP and actual `MCPRegistry` handshake, no-ROE execute denial, and independently host-authorized real local Checkov run |
| `test_cloud_local_iac_mcp.py` | Real previously installed Checkov static scan on the repository's inert Terraform test fixture |
| `test_cloud_mcp_preparse_body_20261021.py` | Actual mounted ASGI strict pre-Pydantic JSON/body bounds |

The actual MCPRegistry connection initializes the Cloud MCP declaration
with `scan_local_iac` marked local, read-only in tool metadata, scope-checked
and approval-required. **Without legitimate signed Task/Flow/ROE plus
durable budget and approvals, the registry refuses execute before any
`/mcp/execute` HTTP request.** The operator-configured local host-bearer
direct endpoint is a separate demonstration of the actual installed
`.runtime/checkov-venv/Scripts/python.exe` (Checkov 3.3.30 installed) on a
temporary inert Terraform directory. That direct call is **not a bypass
claimed to be valid production registry execution**. Real Checkov findings
remain labeled `CHECKOV_LOCAL_IAC_UNVERIFIED` and `STATIC_IAC_ONLY` with
`live_cloud_account_verified=false` and `target_effect_verified=false`.

No AWS/Azure/GCP principal, live cloud account, provider API, remote security
target or IAM action was used. The Terraform file text is an inert example,
not a deployed bucket or proof that an actual cloud resource exists.

## Command and observed results

Executed using the existing repository Windows Python environment:

```powershell
& .venv/Scripts/python.exe -m pytest -q -o addopts= -rs --tb=line `
  tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py `
  tests/qualification/test_cloud_static_iac_current_bytes_20261021.py `
  tests/qualification/test_cloud_static_iac_actual_mcp_client_join_20261021.py `
  tests/test_cloud_local_iac_mcp.py `
  tests/test_cloud_mcp_preparse_body_20261021.py
```

**Observed: 32 passed, 1 skipped in 28.36s.** The single skip was:

`SKIPPED ... test_cloud_local_iac_inert_runtime_20261021.py:238: Host cannot create symlinks without privilege`.

```powershell
& .venv/Scripts/python.exe -m black --check `
  tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py
```

**Observed: 1 file would be left unchanged (pass).** No installation,
app DB, Docker, Git mutation, cloud account authentication or external
security scanning was performed.

## Remaining release blockers

Passing tests establish a bounded isolated local static-IaC capability,
**not** independently signed production Task/ROE authorization to execute
through the registry, an OS-enforced network/egress and resource sandbox,
universal Windows reparse/junction confinement, a cryptographic vendor
binary pin, or verified IAM/target-side effects. Checkov's no-download flags,
restricted subprocess environment, and Python audit hook are defense in
depth, but are not independent proof of zero network access. Production
availability should remain fail-closed when signed authority is missing.

**Final disposition: obsolete mock assertion reconciled without weakening
staging; real local Checkov and registry HTTP discovery work within the
tested inert scope. Not fleet-production-certified; no live cloud IAM
verification.**
