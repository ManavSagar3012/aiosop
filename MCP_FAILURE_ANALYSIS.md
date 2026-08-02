# MCP Failure Analysis

**Generated:** 2026-06-24
**Companion to:** `MCP_CAPABILITY_MATRIX.md`, `TOOLING_READINESS_REPORT.md`

This document records each defect found during MCP Reality Validation: root cause, evidence, impact, and remediation status.

---

## F-1 — Entire tooling layer launches as no-op stubs (CRITICAL)

**Root cause.** `launch_all.ps1` starts `mcp-servers/python/mcp_stub.py` on all MCP ports (8082–8098). `mcp_stub.py` implements only `/health` and `/mcp/initialize` (returning `tools: []`) and has **no `/mcp/execute`**. The real servers (`mcp-servers/go/cmd/*`, `browser_mcp.py`) are never started.

**Evidence.**
- `mcp_stub.py` body: returns `{"capabilities":["tool"],"tools":[]}`.
- During the first engagement run, recon failed with `Tool nmap_scan not available on server recon-mcp` — the stub exposes no tools.

**Impact.** Any engagement run against the launched stack performs **zero real reconnaissance, scanning, or exploitation**, while still transitioning phases and writing assets — i.e. it *looks* like it ran.

**Remediation.** Real Go servers built and launched for validation (`nuclei-mcp.exe`, `recon-mcp.exe`); Burp Suite already serving real MCP on 8081. **Launch path not yet permanently rewired** — see Readiness report, Action A-1.

---

## F-2 — recon-mcp (Go) is a mock, not a scanner (HIGH)

**Root cause.** `mcp-servers/go/cmd/recon-mcp/main.go` registers 8 tools but every `Handler` returns a hardcoded literal. There is **no `os/exec`** in the file. `nmap_scan` always returns `127.0.0.1` with ports 80/443; `shodan_lookup`, `httpx_probe`, `wayback_urls` are explicitly commented "Mock".

**Evidence.**
```
POST /mcp/execute nmap_scan {"targets":["scanme.example.test"]}
→ {"hosts":[{"ip":"127.0.0.1","ports":[{"port":80,...},{"port":443,...}]}]}
```
Arbitrary target → identical canned localhost result.

**Impact.** Recon "succeeds" with fabricated assets. Downstream phases build on fiction. This passes a naive health+registration probe, so it is invisible without an execution-level reality test.

**Remediation.** Documented. A real recon-mcp must shell out to `subfinder`/`nmap`/`httpx` (which also must be installed — see F-5). Not implemented in this pass (out of stated scope; scope was *validation* of recon, plus the four named criteria).

---

## F-3 — heartbeat_loop_error: missing `timedelta` import (FIXED)

**Root cause.** `src/ai_osop/agents/base.py` imported `from datetime import datetime` but `_heartbeat_loop()` (line ~451) uses `datetime.utcnow() + timedelta(seconds=90)` to set the task lease. `timedelta` was undefined, so **every heartbeat raised** `name 'timedelta' is not defined` every 5s for every agent.

**Evidence (before).** `heartbeat_loop_error agent_id=recon-agent-001 error=name 'timedelta' is not defined` (repeating).

**Fix.** `from datetime import datetime, timedelta`.

**Verification.** Post-fix API runtime: `heartbeat_loop_error` count = **0**, `timedelta` occurrences = **0** over sustained uptime (multiple heartbeat cycles).

---

## F-4 — GraphMemory contract break: `get_task_dependencies` missing + wrong direction (FIXED)

**Root cause.** `task_scheduler._trigger_downstream_tasks()` called `graph_memory.get_task_dependencies(...)`, but `GraphMemory` had **no such method** → `AttributeError`, caught and logged as `graph_lookup_failed`, aborting the entire downstream-trigger pass. Two compounding defects:
1. The method never existed.
2. `upsert_task` never persisted `Task.dependencies`, so even a correct method had **no data** to read.
3. The first call site wanted the parent's **dependents** (reverse edge), but used a "dependencies" (forward) name.

**Evidence (before).** `graph_lookup_failed ... 'GraphMemory' object has no attribute 'get_task_dependencies' parent_id=task-bc85dcfa45b2`.

**Fix.**
- `upsert_task` now persists `t.dependencies` as a native Neo4j string array.
- Added `get_task_dependencies(task_id)` (forward: task's own deps) and `get_task_dependents(task_id)` (reverse: tasks depending on it); both return `[]` on miss/error rather than raising.
- `_trigger_downstream_tasks` first call corrected to `get_task_dependents(parent.id)`; per-child re-check uses `get_task_dependencies(child.id)`.

**Verification.** `hasattr(GraphMemory,'get_task_dependencies')` and `...'get_task_dependents'` → both `True`; post-restart `graph_lookup_failed` count = **0**.

---

## F-5 — SkillEngine constructor mismatch disabled the skill library (FIXED)

**Root cause.** `main.py` called `SkillEngine(graph_memory, session_memory)`, but the constructor is `SkillEngine(skills_dir: str, llm_client=None, stats_path=None)`. Passing `GraphMemory` where a path string was expected raised `expected str, bytes or os.PathLike object, not GraphMemory` inside `os.path.join`, so the **entire skill library silently never loaded**.

**Evidence (before).** `SkillEngine initialization failed: expected str, bytes or os.PathLike object, not GraphMemory`.

**Fix.** Resolve the bundled skills dir from the `ai_osop.agents` package and pass it correctly: `SkillEngine(os.path.join(dirname(agents.__file__),"skills"), llm_client=llm_client)`.

**Verification.** Standalone load → **794 skills indexed**. Post-restart: no `SkillEngine initialization failed` warning (it logged loudly when broken, so absence = success).

---

## F-6 — nuclei-mcp ignored its `templates` parameter → every scan ran ~13k templates (FIXED)

**Root cause.** `nuclei-mcp/main.go` declared a `templates` parameter but the handler built args as `-jsonl -silent -target <t>` and **never forwarded `-t`**. So a targeted single-template request silently ran the full template set (~12,907), turning a 2-second test into a multi-minute scan and causing `/mcp/execute` timeouts.

**Evidence.** First `/mcp/execute` (single template requested) hit the 60s curl timeout; the equivalent **direct** `nuclei -t <one template>` returned in seconds. Source review confirmed `params["templates"]` was unused.

**Fix.** Handler now appends `-t <tmpl>` for each requested template; server rebuilt.

**Verification.** Post-fix `/mcp/execute` with one template → **HTTP 200 in 2.6s, 10 real findings**, `template-id: http-missing-security-headers`.

---

## F-7 — browser-mcp real but `playwright` absent from `.venv` (OPEN)

**Root cause.** `browser_mcp.py` uses real `async_playwright`/Chromium, but the `playwright` Python package is **not installed in `.venv`** (the API's interpreter). It *is* present in the system Python, and Chromium browser builds are already downloaded under `~/AppData/Local/ms-playwright`.

**Evidence.** `.venv` import → `ModuleNotFoundError: No module named 'playwright'`. System Python → real navigation to `127.0.0.1:9099` returned **HTTP 200**.

**Impact.** Browser MCP cannot run under the API's venv as-is. Capability is real; only the dependency placement is wrong.

**Remediation.** Install `playwright` into `.venv` (`pip install playwright`; browsers already cached). Not yet applied — see Readiness Action A-2.

---

## F-8 — Required recon binaries not installed (OPEN)

`nmap`, `subfinder`, `amass`, `sqlmap` are absent from PATH. These gate any *real* recon-mcp and the security-bridge server. `nuclei` ✓, `node`/`npx` ✓, `httpx` (python) present. Installing the missing binaries is prerequisite to upgrading recon-mcp/security-bridge from STUB/BROKEN to REAL.
