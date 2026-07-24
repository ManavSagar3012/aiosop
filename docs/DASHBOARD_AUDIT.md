# AI-OSOP Dashboard Audit Report

## Executive Summary

The AI-OSOP dashboard has a solid foundation with 15 pages, live WebSocket updates, and real backend connectivity for findings, agents, and engagement lifecycle. However, the dashboard **critically underrepresents the cognitive architecture** that was built across the last 10+ commits. The reasoning loop, business context engine, graph pathfinder, uncertainty tracker, pivoting broker, adversarial critic, WAF character probe, param miner, and remediation engine are all **invisible to operators** — they run in the backend with zero API exposure and zero dashboard visibility.

**Overall Dashboard Quality: 4/10**

The dashboard accurately represents the OLD fixed-pipeline architecture (engagements → findings → agents → reports) but completely fails to represent the NEW cognitive architecture (OODA loop → hypotheses → reasoning trace → uncertainty → chains → critique → pivots).

---

## 1. End-to-End Architecture Map

### Data Flow (what works)

```
UI Pages (15 pages)
    ↓
Zustand Stores (useSwarmStore + useIntelligenceStore)
    ↓
NetworkService (hydrate: 8 REST calls + WebSocket connect)
    ↓
REST API (24 endpoints consumed) + WebSocket (1 endpoint)
    ↓
FastAPI Routers (11 router files, 52+ routes)
    ↓
Backend Services (orchestrator, graph_memory, session_memory, agents)
    ↓
Neo4j + Postgres + Redis + MCP Servers
```

### What's Connected (verified working)

| Backend Capability | API Endpoint | UI Consumer | Live? |
|---|---|---|---|
| Engagement CRUD | POST/GET `/engagements` | Header.tsx, NetworkHealth.tsx | ✅ |
| Findings list | GET `/engagements/{id}/findings` | network.ts hydrate | ✅ |
| Evidence vault | GET `/findings/{fid}/vault` | FindingsVerification.tsx | ✅ |
| Agent status | GET `/agents` | network.ts hydrate | ✅ |
| Audit log | GET `/engagements/{id}/audit-log` | network.ts hydrate | ✅ |
| Graph data | GET `/engagements/{id}/graph` | network.ts hydrate + WS push | ✅ |
| Phase transitions | POST `/engagements/{id}/transition` | Administration.tsx | ✅ |
| Engagement halt | POST `/engagements/{id}/halt` | Administration.tsx, Header.tsx | ✅ |
| Bounty report | GET `/engagements/{id}/report/bounty` | MissionReport.tsx | ✅ |
| Skill stats | GET `/system/skills/stats` | SkillIntelligence.tsx | ✅ |
| Approvals | GET/POST `/approvals/*` | ApprovalQueue.tsx | ✅ |
| WebSocket events | WS `/ws/engagements/{id}` | NetworkService.connect() | ✅ |
| Diff-auth findings | GET `/engagements/{id}/diff-auth` | network.ts hydrate | ✅ |
| Uncertainty (legacy) | GET `/engagements/{id}/uncertainty` | network.ts hydrate | ✅ |

### What's DISCONNECTED (backend exists, no API, no UI)

| Backend Capability | Backend File | API Endpoint? | UI Page? |
|---|---|---|---|
| **ReasoningTrace** | core/reasoning_trace.py (186L) | ❌ No API | ❌ No UI |
| **UncertaintyTracker** | core/uncertainty_tracker.py (209L) | ❌ No API | ❌ No UI |
| **BusinessContextEngine** | core/business_context.py (247L) | ❌ No API | ❌ No UI |
| **GraphPathfinder** | core/graph_pathfinder.py (265L) | ❌ No API | ❌ No UI |
| **PivotingBroker** | orchestrator/pivoting_broker.py (138L) | ❌ No API | ❌ No UI |
| **WAFCharacterProbe** | core/waf_character_probe.py (183L) | ❌ No API | ❌ No UI |
| **ParamMiner** | core/param_miner.py (164L) | ❌ No API | ❌ No UI |
| **RemediationEngine** | core/remediation_engine.py (252L) | ❌ No API | ❌ No UI |
| **CriticAgent.audit_findings** | agents/critic_agent.py (244L) | ❌ No API | ❌ No UI |
| **LogicalBusinessStateMachine** | core/business_state_machine.py (116L) | ❌ No API | ❌ No UI |
| **Attack paths** | intelligence.py:61 | GET exists | ❌ Not consumed by UI |
| **Hypotheses** | intelligence.py:91 | GET exists | ❌ Not consumed by UI |
| **WAF profiles** | intelligence.py:194 | GET exists | ❌ Not consumed by UI |
| **Vulnerability education** | intelligence.py:122 | GET exists | ❌ Not consumed by UI |
| **Observatory traces** | observatory.py (5 routes) | GET exists | ❌ Not consumed by UI |
| **MCP health** | system.py:67 | GET exists | ❌ Not consumed by UI |
| **DLQ management** | system.py + dlq.py (8 routes) | GET/POST exists | ❌ Not consumed by UI |
| **Trust score** | system.py:153 | GET exists | ❌ Not consumed by UI |
| **Sandbox status** | system.py:51 | GET exists | ❌ Not consumed by UI |

---

## 2. WebSocket / SSE Event Audit

### Events PUBLISHED on the coordination bus

| Event Topic | Publisher | UI Listener? |
|---|---|---|
| `observation` | BaseAgent.observe() | ✅ via WS as `agent_observation` |
| `finding.recorded` | GraphMemory.add_vulnerability() | ❌ NOT forwarded to WS |
| `hypothesis.generated` | ReasoningLoop | ❌ NOT forwarded to WS |
| `chain.discovered` | ReasoningLoop (GraphPathfinder) | ❌ NOT forwarded to WS |
| `task.scheduled` | TaskScheduler | ❌ NOT forwarded to WS |
| `task.assigned` | TaskScheduler | ❌ NOT forwarded to WS |
| `task.completed` | TaskScheduler | ❌ NOT forwarded to WS |
| `task.failed` | TaskScheduler | ❌ NOT forwarded to WS |
| `feedback.payload_validated` | ExploitAgent | ❌ NOT forwarded to WS |

### Events the WebSocket actually sends to the UI

| Event Type | Source | UI Handler |
|---|---|---|
| `heartbeat` | main.py push loop (2s) | Latency capture |
| `phase_transition` | main.py push loop | Store update |
| `agent_observation` | coordination bus → WS bridge | Audit log append |
| `budget_update` | (legacy) | Store update |
| `finding_update` | (legacy) | Store update |
| `mission_update` | (legacy) | Store update |
| `graph_update` | (legacy) | Re-fetch `/graph` |
| `verification_update` | (legacy) | Store update |

### Critical gap: 7 of 9 published events are NEVER forwarded to the WebSocket

The coordination bus publishes `finding.recorded`, `hypothesis.generated`, `chain.discovered`, `task.scheduled/assigned/completed/failed`, and `feedback.payload_validated` — but the WebSocket bridge in main.py only forwards `observation` events. The reasoning loop's entire event stream is invisible to the operator.

---

## 3. Reasoning Visibility Audit

### What the operator CAN see

| OODA Stage | Visible? | How? |
|---|---|---|
| Observe | ⚠️ Partial | Audit log shows agent observations |
| Orient | ❌ No | BusinessContextEngine results not exposed |
| Hypothesize | ❌ No | HypothesisEngine has API but UI doesn't consume it |
| Select | ❌ No | Reasoning trace records selection but no API |
| Dispatch | ⚠️ Partial | Task scheduler creates tasks visible in audit log |
| Evaluate | ❌ No | Hypothesis confirmed/refuted status not exposed |
| Critique | ❌ No | CriticAgent.audit_findings results not exposed |
| Learn | ❌ No | FindingsKnowledge recall not exposed |
| Graph Pathfinder | ❌ No | Chain discovery results not exposed |
| Explainability | ❌ No | ReasoningTrace has no API or UI |
| Decision rationale | ❌ No | Trace records rationale but not queryable |
| Confidence | ⚠️ Partial | Finding confidence shown in findings list |
| Rejected hypotheses | ❌ No | Trace tracks this but not exposed |
| Alternative hypotheses | ❌ No | Trace tracks this but not exposed |
| Memory recall | ❌ No | FindingsKnowledge recall not exposed |
| Business context | ❌ No | Categorization not exposed |
| Uncertainty | ⚠️ Partial | Legacy uncertainty endpoint exists but new tracker doesn't |
| Strategic pivots | ❌ No | PivotingBroker not exposed |
| Critic analysis | ❌ No | audit_findings results not exposed |
| Reasoning trace | ❌ No | Trace has no API endpoint |

**Score: 1/10** — the operator cannot see what AI-OSOP is thinking.

---

## 4. Mock Data & Hardcoded Values

### Actively-present mock data

| Page | Issue | Severity |
|---|---|---|
| RealityVerificationCenter.tsx | Hardcoded findingLedger (2 fake findings) | HIGH |
| RealityVerificationCenter.tsx | Hardcoded "82%" verification rate | HIGH |
| RealityVerificationCenter.tsx | Hardcoded "3" rejected hypotheses | HIGH |
| VisualContext.tsx | Entirely static — no fetch, hardcoded data + Unsplash image | HIGH |
| UncertaintyEngine.tsx | Hardcoded "SWARM_GOVERNOR // RATIONALE:" narrative | MEDIUM |
| UncertaintyEngine.tsx | Hardcoded "MOST UNCERTAIN STACK" + "HIGHEST DATA GAP" | MEDIUM |
| Administration.tsx | Hardcoded API key masks ("••••sk-4a") | LOW |
| Administration.tsx | Hardcoded default values (5 agents, 500 budget, 7.5 threshold) | LOW |
| AuthAudit.tsx | Hardcoded "98%" admin access + "12%" guest restriction | MEDIUM |
| DifferentialAuth.tsx | Hardcoded verdict text "CRITICAL ANOMALY" | LOW |
| NewMissionModal.tsx | Placeholder text "ginandjuice.shop" | LOW |
| load_test.ts | Synthetic mock events (intentional — stress testing) | OK |

### Already-removed mocks (documented in code)

FindingsVerification.tsx (removed fabricated "92.4%" evidence integrity), LearningAnalytics.tsx (removed fabricated AI-vs-human curve), Administration.tsx (removed fabricated KPI counts).

---

## 5. Final Scorecard

| Dimension | Score | Justification |
|---|---|---|
| Architecture Integration | 5/10 | Good REST + WebSocket foundation; but cognitive architecture is completely disconnected |
| Backend Connectivity | 7/10 | 24 REST endpoints consumed; 1 WebSocket; but 18+ backend routes unconsumed |
| Frontend Connectivity | 6/10 | 15 pages exist; 8 fetch from API; but several pages are static/mock |
| API Coverage | 4/10 | 52+ backend routes exist; only 24 consumed (46%); intelligence.py + observatory.py + system.py mostly unconsumed |
| WebSocket Coverage | 2/10 | Only 3 of 9+ published event types reach the UI; reasoning loop events invisible |
| Reasoning Visibility | 1/10 | 18 of 20 reasoning components have zero UI exposure; OODA loop invisible |
| Memory Visibility | 2/10 | FindingsKnowledge not queryable; reasoning trace not exposed; only legacy uncertainty endpoint |
| Graph Visibility | 4/10 | KnowledgeGraphs page renders attack/workflow/cloud/learning modes; but no pathfinder results, no chain viewer |
| Agent Observability | 3/10 | Agent list shows status; no current task, reasoning, hypothesis, evidence, or next action |
| Finding Quality | 6/10 | Evidence vault + confidence + validation pipeline shown; but no critic review, no reasoning, no chain link |
| UX | 5/10 | Cyberpunk aesthetic is distinctive; but operator can't understand "what is the AI thinking?" |
| Performance | 6/10 | Zustand stores are efficient; WebSocket is good; but 8 sequential REST calls on hydrate is slow |
| Debuggability | 2/10 | No reasoning trace; no hypothesis viewer; no OODA stage indicator; no critic output |
| Production Readiness | 3/10 | Multiple hardcoded mock values; 3 pages entirely static; cognitive architecture invisible |
| Research Readiness | 2/10 | Cannot evaluate reasoning quality through the dashboard; cognition benchmark exists but has no UI |
| **Overall Dashboard Quality** | **4/10** | Solid foundation for the OLD architecture; completely fails to represent the NEW cognitive architecture |

---

## 6. Prioritized Improvement Roadmap

### CRITICAL (P0) — Connect the cognitive architecture to the dashboard

| # | Problem | Why It Matters | Effort | Impact |
|---|---|---|---|---|
| 1 | ReasoningTrace has no API endpoint | Operator cannot see what the AI is thinking or why it made decisions | Low (add 2 GET routes to intelligence.py) | Critical — enables explainability |
| 2 | Hypotheses API exists but UI doesn't consume it | The hypothesis list is the core of the OODA loop — invisible to operators | Medium (add Hypotheses page + fetch) | Critical — makes the reasoning loop visible |
| 3 | finding.recorded + chain.discovered + hypothesis.generated events not forwarded to WS | Real-time reasoning events don't reach the dashboard | Low (add bus subscriber in main.py WS bridge) | Critical — makes the loop live |
| 4 | GraphPathfinder results not exposed | 32 attack chains discovered per engagement but operator sees 0 | Low (add 1 GET route) | High — shows attack chain reasoning |
| 5 | UncertaintyTracker not exposed | 34 uncertainties detected per engagement but operator sees 0 | Low (add 1 GET route) | High — shows active info-seeking |

### HIGH (P1) — Remove mock data + connect unconsumed APIs

| # | Problem | Why It Matters | Effort | Impact |
|---|---|---|---|---|
| 6 | VisualContext.tsx entirely static | Displays fake data as if real | Medium (wire to real adapter or remove) | High — trust |
| 7 | RealityVerificationCenter.tsx hardcoded findings + percentages | Displays fabricated metrics | Medium (wire to real verification data) | High — trust |
| 8 | UncertaintyEngine.tsx hardcoded narrative | Fake "brain dump" text | Medium (wire to ReasoningTrace API) | High — trust |
| 9 | Attack paths API unconsumed | GET `/attack-paths` exists but UI doesn't call it | Low (add to KnowledgeGraphs page) | Medium |
| 10 | Observatory traces unconsumed | 5 observatory routes exist but UI doesn't call any | Medium (add observability page) | Medium |
| 11 | DLQ management unconsumed | 8 DLQ routes exist but no UI | Medium (add DLQ management page) | Medium |
| 12 | MCP health unconsumed | GET `/mcp/health` exists but no UI | Low (add to system health card) | Medium |

### MEDIUM (P2) — Add missing visualizations

| # | Problem | Why It Matters | Effort | Impact |
|---|---|---|---|---|
| 13 | No OODA loop stage indicator | Operator can't tell which cognitive stage the system is in | Medium (add OODA indicator to MissionControl) | High |
| 14 | No reasoning trace timeline | Can't see the step-by-step decision history | Medium (new ReasoningTrace page) | High |
| 15 | No critic review panel | Can't see which findings the critic flagged | Low (add to FindingsVerification) | Medium |
| 16 | No business context panel | Can't see endpoint categorization (payment/admin/auth) | Medium (add to findings detail) | Medium |
| 17 | No pivot indicator | Can't see when the system pivoted strategy | Low (add to timeline) | Medium |
| 18 | No WAF profile display | WAF detection runs but results invisible | Low (add to recon page) | Low |
| 19 | No agent deep detail | Agent list shows only status, not task/reasoning/hypothesis | Medium (add agent detail panel) | Medium |

### LOW (P3) — Polish

| # | Problem | Effort | Impact |
|---|---|---|---|
| 20 | 8 sequential REST calls on hydrate | Low (batch or parallelize) | Low |
| 21 | No SSE fallback when WebSocket drops | Medium | Low |
| 22 | No dark/light theme toggle | Low | Low |
| 23 | NewMissionModal has placeholder text | Low | Low |
| 24 | Administration has hardcoded defaults | Low | Low |
