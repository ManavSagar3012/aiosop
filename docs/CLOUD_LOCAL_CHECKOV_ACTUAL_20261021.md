# Configured Cloud MCP — real offline local Checkov and fail-closed source results

**Date:** 2026-10-21  
**Verdict:** **Local Terraform static analysis reachable; live cloud IAM/account and target effects NOT VERIFIED; NOT PRODUCTION CERTIFIED / NOT READY.**

## Real executable source qualification

The *original* `mcp-servers/python/cloud_mcp.py` implements `scan_local_iac` only when `OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED=1`, `OSOP_CLOUD_MCP_IAC_ROOT` names a pinned absolute safe `.tf` tree, `OSOP_CLOUD_MCP_CHECKOV_PYTHON` points to an installed executable and a host bearer is supplied. Without this configuration `/health` is 503 and initialize lists no tools. Turbo Intruder remains separately disabled 503.

Under the existing `tests/test_cloud_local_iac_mcp.py` test, the original ASGI Cloud `/health`, `/mcp/initialize` and `/mcp/execute` are called against the installed private `.runtime/checkov-venv/Scripts/python.exe` and inert preexisting `tests/fixtures/local_iac/main.tf`, without an external cloud, network provider, app DB or target. The source retains `--skip-download`, `--download-external-modules false`, operator bearer, fixed root, SHA-pinned root manifest before and after scan, bounded stdout/timeout and nonsecret response fields.

Initial actual live qualification **failed** (`HTTP 503 scan_unknown`) even though the local binary was installed. Two independent production causes were reproduced from the original subprocess contract:

1. The intentionally restricted subprocess environment excluded `HOME` and `USERPROFILE`, and Checkov imported a component invoking `pathlib.Path.home()` which raised `RuntimeError: Could not determine home directory` before any Checkov scan. Rather than passing through the actual host user's private home/credentials, `_scan` now creates a new **test-/process-owned temporary isolated home** and supplies only that path to the short-lived Checkov subprocess, removing it afterward.
2. With this repaired environment the **real Checkov process** returned normal exit code 1 and a valid ~31 KB JSON document with **11 failed Terraform checks**, including ordinary `CKV_AWS_*` and standard `CKV2_AWS_*` names. The original `_CHECK` identifier regex accepted only `CKV_`; valid `CKV2_` failures caused the parser to raise and falsely classify a normal static-IaC result as `scan_unknown`. `_CHECK` now accepts strictly bounded `CKV_` or `CKV2_` identifiers. The actual API test additionally checks that both observed categories survive the original response projection.

Actual combined qualification after both production fixes:

~~~text
.venv\Scripts\python.exe -m pytest -q -o addopts= --no-cov --disable-warnings --tb=short \
    tests/test_cloud_local_iac_mcp.py \
    tests/test_mcp_no_simulated_cloud_turbo_success_20261020.py \
    tests/test_operator_knowledge_agent_isolation_20261016.py \
    tests/test_user_global_library_preparse_fence_20261021.py
17 passed in 20.67s
~~~

The older permanent-stub tests were updated to assert the **now-correct, unconfigured** Cloud response rather than invent obsolete `server_unavailable`/`execution_enabled` fields. The stale Flow-knowledge agent-isolation test was also corrected to include only the new authorized metadata-only two-source search router and still prohibit agent prompt/retrieval admissions. Focused Black checks passed. **This is a genuine local installed Checkov invocation with local Terraform, not a mocked subprocess**, but it does *not* contact AWS/Azure/GCP, validate live cloud account IAM, prove provider-signed findings, inspect a real target, authenticate a target owner or establish production release approval. The configured runtime remains an operator-gated static-IaC aid only.
