# AI-OSOP Capability Matrix — Runtime Audit (2026-08-24)

Evidence basis: live engagement `eng-20260824…-eng-qosmos-live` against
https://qosmos.qnulabs.com (authorized), plus this cycle's gate suites
(37+8 tests) and live scope-gate/tool-reality proofs. "Runtime verified"
requires observed execution + persistence, not code existence.

| Capability | Exists | Wired | Runtime verified | Evidence quality | Gap |
|---|---|---|---|---|---|
| Engagement lifecycle (signed scope, phases) | ✅ | ✅ | ✅ qosmos run; phase auto-advanced to vuln_discovery | Strong | backward transitions (re-planning) not exercised |
| Coordination bus (Redis Streams, signed events) | ✅ | ✅ | ✅ signed task.scheduled/assigned observed in stream | Strong | — |
| Scope enforcement (client-side choke point) | ✅ | ✅ | ✅ live denial vs real recon-mcp; foreign IP refused pre-dispatch | Strong | — |
| Tool Reality scheduling (blocked→revive) | ✅ | ✅ | ✅ burp_scan parked while down; tiered /health probe fixed Go 404 FP | Strong | revival-under-recovery observed only via logs |
| MCP fleet (11 real servers) | ✅ | ✅ | ✅ identity-checked health; recon `real_execution_verified` | Strong | burp needs operator Burp |
| Recon → attack graph | ✅ | ✅ | ✅ Asset(domain)+Endpoint(https) persisted for qosmos | Medium | depth: no subdomain/JS/API fan-out triggered automatically |
| Nuclei execution → findings | ✅ | ✅ | ✅ completed task; findings in Neo4j w/ evidence | Strong | — |
| Finding Intelligence (classify/fingerprint/dedupe) | ✅ | ✅ | ⚠️ unit-proven + replay of live distribution (36→27); graph re-write pending next engagement | Medium | apply retroactively to stored qosmos findings |
| Observation/Weakness/Vulnerability classes | ✅ | ✅ | ✅ classification tests + live-shape replay | Strong | dashboard/report consumers still show raw counts |
| Confidence model (deterministic scores) | 🆕 this cycle | ✅ | ✅ unit-tested | Medium | exploitability/impact inputs need Validation Engine |
| Validation lifecycle (UNTESTED→VALIDATED/REJECTED) | 🆕 this cycle | ✅ (model+persist) | ⚠️ state machine tested; no active validator yet | Weak | **Validation Engine itself = P2 gap** |
| Service assessment TLS | ✅ | ✅ | ✅ live qosmos:443 — TLSv1.3-only, zero legacy accepted | Strong | DER cert parse empty on CDN chains |
| Service assessment SSH | ✅ | ✅ | ✅ live :22 correctly unreachable; rule tests for banners | Medium | algorithm enumeration (ssh-audit parity) |
| DNS deep assessment | Partial | ❌ | ❌ crt.sh via recon only | Weak | zone-transfer/DNSSEC/dangling-CNAME logic absent |
| JS intelligence feedback loop | Partial | ⚠️ adapters exist (source-map/js-analyze) | ❌ not demonstrated in qosmos run | Weak | auto-scheduling from discovered bundles |
| Hypothesis engine | ❌ | ❌ | ❌ | — | **P2 core** |
| Adaptive planner (info-gain ranking) | ❌ | ❌ | ❌ | — | P2 |
| AuthN/AuthZ differential testing | Partial | ⚠️ DiffAuth components exist | ❌ not demonstrated | Weak | identity graph nodes absent |
| Attack-chain reasoning | ❌ | ❌ | ❌ | — | P3 |
| Impact analysis | ❌ | ❌ | ❌ | — | P3 |
| CVE intelligence keyed on services | Partial | threat-intel-mcp exists | ❌ unkeyed to service fingerprints | Weak | P3 |
| Retest lifecycle | ❌ | ❌ | ❌ | — | P3 |
| Reporting by class (confirmed/weak/info/rejected) | Partial | ⚠️ certification engine exists | ❌ still emits flat counts | Medium | consume finding_class |
| Benchmark harness (ground truth) | ❌ | ❌ | ❌ | — | P4 |

**Top gaps (priority order):** Validation Engine → hypothesis/planner loop →
report class-sections consumer → JS/discovery auto-scheduling → benchmark lab.
