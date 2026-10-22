# Cloud MCP: current-byte static-IaC custody and Checkov subprocess bounds

**Status: local static-IaC custody contract qualified; cloud IAM/target effects
unverified. NOT PRODUCTION CERTIFIED / NOT READY.**

## Why this follow-on was needed

The original `mcp-servers/python/cloud_mcp.py` calculated a SHA-256 manifest
before executing Checkov directly against the **mutable** operator-pinned
Terraform directory. Even with a matching post-scan manifest, Checkov could
have opened intermediate bytes while a local process altered a file. A static
finding labeled with the original manifest could therefore describe content
different from the bytes actually read by the scanner. File symlinks and
Windows junction/reparse intermediates also require host-side exclusion.

## Owned implementation (Cloud MCP server only)

`_source_bytes(root)` now reads each exact bounded Terraform file using an
opened file descriptor (`O_NOFOLLOW` where supported) and compares inode,
device, byte length, modification time, and non-link metadata around each
read. It rejects directory/reparse/symlink and multi-link files, including
symlink/junction/reparse ancestors, via `_safe_path`, and retains the existing
50-entry / 1 MB limits and deterministic SHA-256 manifest. Windows `lstat`,
`FILE_ATTRIBUTE_REPARSE_POINT`, and `Path.is_junction` (where provided) are
checked. The OS may still have filesystem-specific alias behavior this suite
does not emulate: no claim of generic Windows reparse/junction certification.

`_scan(root, interpreter)` copies those **current bounded bytes** into a
separate private `TemporaryDirectory` and verifies the stage and live source
digest before starting Checkov. It invokes `_scan_frozen` against that **stage,
not the original operator tree**. After parsing, it rechecks both snapshots.
`mcp_execute` also compares the independently re-read original manifest to
the pre-execution manifest, returning `503 scan_unknown` if any checked
source changed. This closes a substantial original live-file read race and
prevents mutable source bytes from silently being relabeled as an earlier
scan, while still leaving a narrow final-check-to-response race and possible
same-user filesystem/OS attacks outside the verified boundary.

`_scan_frozen` accepts *only* the configured interpreter, JSON Terraform
framework, Checkov `--skip-download --download-external-modules false`, a
fresh disposable HOME/USERPROFILE, filtered process environment, a 2 MB
stdout limit, 60s stdout timeout, 5s exit wait, 10s subprocess-spawn deadline,
and bounded kill/reap. Any unknown/malformed result is rejected; no original
cloud IAM or external target is queried by the Cloud server API. An isolated
`sitecustomize` audit hook rejects Python socket connects and nested Python
subprocess launches before Checkov imports. **This is a process-level Python
control, not an OS-level network namespace, egress firewall, credential
sandbox or Windows Job Object.** Native extensions and a compromised
interpreter are not independently contained by this hook; further OS resource
caps (address space, process count, CPU/memory accounting) remain needed.

The input controller still disallows caller-defined paths, cloud accounts,
frameworks, secret material and external provider targets. Checkov findings
are untrusted static source observations, never genuine cloud exposure proof.

## Focused qualification

`tests/qualification/test_cloud_static_iac_current_bytes_20261021.py` creates
only inert Terraform within pytest's own temporary directory. It asserts:

- Only the staged copy reaches the subordinate scanner, not the original root;
  the stage is deleted after use and has the same bytes as the approved file.
- Mutation during a scan and mutation during source-copy admission produce
  fail-closed outcomes; a scanner never succeeds with the stale original SHA.
- Hard-linked or unsafe nonregular content denies preflight where the host
  permits constructing the fixture.
- The registry's null timeout metadata is accepted; invalid overrides and
  caller-selected targets cannot be used to broaden execution.
- A **mocked** `create_subprocess_exec` verifies the real subprocess command
  points only at the staged copy, with downloads disabled and host cloud
  credential environment excluded. This is not real Checkov evidence.

The separate
`tests/qualification/test_cloud_static_iac_actual_mcp_client_join_20261021.py`
uses a real loopback server, and an **already installed local Checkov 3.3.30**
against its own inert Terraform fixture. It reports actual static findings,
not cloud IAM or independently attested effects. The Checkov package label
is an installed version, not cryptographic proof of its vendor artifact.

## Legacy test update needed (outside worker ownership)

The earlier
`tests/qualification/test_cloud_local_iac_inert_runtime_20261021.py`
contains a fake subprocess assertion requiring
`--directory <original mutable source root>` and `cwd=<original root>`.
That **is no longer a valid safety expectation**. The secure production
behavior instead sets both to a disposable `osop-checkov-stage-*` directory
with identical source bytes. The earlier fake-process expectation now fails;
it should be updated by that test's assigned owner to assert the staged bytes
and not demand a return to the insecure live path. The previous genuine
Checkov fixture test remains independently valuable and is not itself an
authority for target-side outcomes.

## Unqualified security and release boundaries

No app PostgreSQL, Docker, Git mutation, cloud IAM authentication, provider
API call, original target scan or installed package upgrade was performed.
The test does not prove outbound OS networking was impossible, Windows
reparse points are completely fenced, an untrusted Checkov native extension
cannot read other user files, or a real multi-replica Task/ROE admission and
durable budget decision authorize an MCP scan. These require separate
qualifications and deployment hardening before production release.
