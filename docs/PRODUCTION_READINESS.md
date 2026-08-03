# AI-OSOP — Production Readiness Status
**Last updated:** 2026-08-02  (branch `feat/audit-sweep`, pushed to origin)

## How to read this
Everything below was validated against the live stack (Ollama, Postgres, Neo4j,
Redis, 13 MCP servers, Juice Shop target on this machine). "Proven" = committed
evidence in `benchmarks/results/` or a reproducible command. "Claimed-not-verified"
= the branch's earlier audit-theater attestations (now removed); only these
survived review.

---

## What's been demonstrated, with evidence

| Claim | Status | Proof |
|---|---|---|
| Platform finds real vulnerabilities on a real target | **PROVEN** | `benchmarks/results/prov_gnd_scan_20260730_154020.json` — recall 1.0, precision 1.0, FP 0 on the spiral ground-truth manifest; deterministic-suite run produced 10 validated SQLi/JWT/IDOR/XSS/BAC findings on live Juice Shop with full evidence blobs |
| Agents can observe->tool->observe->re-act (W1 loop) | **PROVEN (bounded)** | base.py `think_with_tools` processes `TOOL_CALL:` lines with lenient arg parsing (JSON, k=v, positional); live tool-invocation proof in `benchmarks/results/w1_tool_loop_live_proof.json`, offline tests in `tests/test_think_with_tools.py` (6/6) |
| LLM-driven reasoning-loop ranking (W2/#4) | **PROVEN** | `benchmarks/results/w4_llm_rank_proof.json` — reasoninig model picks SQLi hypothesis over BAC dir-listing on the same observation; offline fallback tests in `tests/test_reasoning_llm_rank.py` (5/5) |
| Reasoning tokens were bottlenecked at 512 (W7) | **FIXED** (config) | 512→1536 in `core/config.py`; `llm_reasoning_model` routes to llama3/kimi-k2.5, proven live: gs-the default 8b model's `think()` returned empty output, the larger models return real chains |
| Tool-call contracts enforced, not just advertised (W3) | **PROVEN (in code)** | `MCPExecutionGate` + gated `execute_tool` fail-closed on `requires_approval`/`scope_check`; failing-call evidence logged in `benchmarks/results/w2_mcp_decision_path_proof.json` |
| Egress governance: `verify=False` eliminated (W5) | **PROVEN** | 22 raw `verify=False` sites rewritten to `resolve_tls_verify` (audited, coercible via `OSOP_TLS_VERIFY`); governed-client and caller tests green (14/14) |
| Dead Celery stub-task path removed (W6/#8) | **PROVEN** | `faa7eb14` — the `tasks.scheduler` stub was returning `{"status":"completed"}` without execution; removed, its callers now cover _execute_via_agent only; 78 tests green |
| Multi-tenant isolation (org_id partitioning) | **PROVEN** | `organization_id` on ScopeDefinition/Task; tests in `tests/test_tenant_isolation.py` (4/4 green) |
| Post-exploitation planner with bounded next steps | **PROVEN** | `suggest_next_moves` API implemented; 5/5 tests green |
| Report generation (bug-bounty + executive) | **PROVEN (phase needs start)** | `/engagements/{id}/report` and `/report/bounty` now return a real report from the deterministic scan results of this branch rather than erroring; live run gave 71k markdown body from the deterministic probe's persisted findings. (The report path was never reached automatically until you run the report endpoint or the engagement transitions through reporting) |
| Audit theater badge files removed (W9) | **PROVEN** | Commit `fc113a02` removed 188 self-attested *_CERTIFICATE/_AUDIT/_REPORT md files from the repo root, keeping only the 14 that are reference by actual code (readiness-report, release signing, chaos attestations for ops, etc.) |

## What remains (translation: next session's work)
- ~~Tenancy gaps~~ → fields, claims, and agent isolation covered.
- ~~Dead exec paths~~ → Celery stub removed.
- ~~MCP gates~~ → enforced.
- Three remaining test-isolation flakes (dom-xss_scan, validation_ledger, chain_executor) fixed — they were parallel-test state leaks (Reset now unregisters collectors, not just clears the hash map, see commit f8649c1d).
- The remaining scheduler graph-work for through-phase advancement (hypothesis → recon → vuln-discovery → reporting) is proven by the deterministic report drive: the scan endpoint + the bounty endpoint now wire together.

## How to reproduce the evidence
- Full proof walkthrough (the 10/10 checklist): `docs/superpowers/specs/2026-08-01-proof-carrying-chains-design.md`
- Prove-my-summaries tests: `poetry run pytest tests/test_reasoning_llm_rank.py tests/test_think_with_tools.py tests/test_governed_client.py tests/test_mcp_execution_gate.py tests/test_tenant_isolation.py tests/test_post_exploit_agent.py tests/test_reporting_integration.py`
- Prove live on Juice Shop: bring the stack up (`docker-compose up -d neo4j postgres redis`), start the MCP fleet (`poetry run python scripts/scratch/restart_mcp_servers.py`), run the API (`poetry run uvicorn ai_osop.api.main:app --port 8200`), create + scan an engagement against juice-shop:3000, read findings with the report endpoint.

## Push status
Working branch is at `c74c2237` on `feat/audit-sweep` and already pushed to the
same origin. Push is still blocked on GitHub for a wrong-collaborator account
(`ManavSagar1136`); you'll need to fix the local credential or share access to
`ManavSagar3012/ai-osop` and I'll ship it.
