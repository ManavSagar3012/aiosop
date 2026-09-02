# AI-OSOP Dashboard — Design Benchmark & Redesign Specification

**Date:** 2026-08-05 · **Author:** Staff Product Design / Frontend Engineering review
**Scope:** Full 8-phase benchmark against the industry's best security, SOC, observability, AI-first SaaS, and offensive-tool dashboards. Produces a complete redesign spec and a prioritized, engineer-practical roadmap.

---

## Phase 1 — Current-State Analysis (What AI-OSOP Has)

### Stack
- **UI:** React 19 + Vite 7 + TypeScript, react-router-dom 7 (19 lazy routes + per-route error boundaries), zustand 5 (2 stores), Tailwind 4 design tokens, recharts, @xyflow/react + dagre (attack graph), raw-WebSocket `NetworkService`, `useApiData` hook, toast system, ModalShell (a11y focus trap).
- **Design system (already strong):** token-driven dark-slate ramp + restrained cyan accent, self-hosted fonts (Inter/Space Grotesk/JetBrains Mono), light theme with FOUC-safe init + toggle, `prefers-reduced-motion` support, `:focus-visible` rings, 16 shared components (Card, StatTile, StatusBadge, DataTable with sort/search/pagination, EmptyState, ErrorState, Skeleton, ModalShell, ThemeToggle…).
- **Real-time:** WS `/ws/engagements/{id}` with 2s heartbeat (real Redis latency), phase transitions, `agent_observation`, `verification_update`, `learning_update`; short-lived WS ticket auth (`GET /ws/ticket`).
- **Backend surface:** 65 REST endpoints across 12 routers — engagements, tasks, agents, approvals, DLQ, sessions, findings/diff-auth/evidence vault, intelligence (graph, attack-paths, hypotheses, vuln-edu), system (config, trust-score, sandbox, MCP health), observatory (traces, telemetry), cognition.
- **Live data:** 67 engagements, 75 agents, DLQ (~10k entries), approvals queue, findings with evidence packages + replayability, hypotheses, reasoning traces, cognition summaries, skill stats, payouts.

### Current UX strengths (verified in earlier audit pass)
1. Token discipline and component consistency are above average for security tooling.
2. Everything is wired to a real backend — no mock data remains.
3. WS event-driven updates for the live stream; evidence-backed findings with replay + vault export.
4. A11y foundations (focus trap modals, reduced motion, focus rings, aria-labels).
5. Light/dark themes, self-hosted fonts, sortable/searchable tables.

### Current UX weaknesses (the gaps this redesign targets)
1. **18 flat nav items** — navigation tax; no grouping by analyst job (Falcon/Defender/Elastic all group into sections).
2. **No global search / command palette** — `g <letter>` chords exist but there is no Cmd+K; industry-standard (Linear, GitHub, Slack, Defender, Datadog, Grafana, Raycast).
3. **Landing page is KPI-led, not queue-led** — the best consoles land on a prioritized triage queue (incidents/signals/approvals), not stat tiles.
4. **No saved views / persistent filters** — Datadog "Saved View", Elastic "Saved query", GitHub saved filters are table stakes.
5. **No notification center / aggregated activity feed** — the timeline page exists but there is no header bell or cross-engagement feed.
6. **No AI copilot** — ironic for an AI platform; no natural-language query of findings/graph (Defender Copilot, Splunk AI Assistant pattern).
7. **Graph viewer is a single static lens** — no pathfinding (BloodHound), no scope overlay (Burp Target), no drill to evidence timeline.
8. **Interaction flatness** — tables lack inline row actions (Elastic hover filter-in/out pattern); context switching is page-hop heavy.
9. **Charts are basic** — no sparklines in tables, no heat maps, no severity time-burst views.
10. **Density is inconsistent** — some pages airy, some cramped; no density control.
11. **Mobile is minimal** — sidebar drawer only; wide tables not horizontally manageable.

---

## Phase 2 — Industry Research Digest (verified via web research)

### Security / SOC / observability (Splunk, Falcon, XSIAM, Defender, Elastic, Grafana, Datadog, Wiz, Snyk, Prisma)
**Strong shared patterns:**
- **Severity is the universal sort key** — critical→red, high→amber, med/low→blue/grey, everywhere (Defender, Elastic, Datadog, Wiz, Snyk), including filters.
- **Left-rail IA with job-titled sections** (Falcon: Detect/Investigate; Defender: Incidents/Hunting/Actions; Elastic: Discover/Dashboards/Alerts/Cases), shallow depth.
- **The queue is the landing page** — home = prioritized triage list; analytics serve the queue, not vice versa (Falcon Detect, Defender Incidents, Wiz Issues, Datadog Signals).
- **Correlation first** — Defender/XSIAM auto-group alerts into attack stories/cases before the analyst sees them.
- **Drill-down is a slide-over, not a page hop** — Elastic details flyout, Wiz side panel; full-page nav reserved for committing to an investigation.
- **"Investigate one thing at a time"** — Falcon/Defender incident pages are self-contained stories (actors → timeline → evidence → actions).
- **Persistent global search** — Defender entity search, Datadog Cmd+K, Grafana Cmd+K; entity-first (users/hosts/files) beats free-text.
- **Saved views/queries are table stakes** — Datadog Saved View, Elastic saved query menu.
- **Inline row actions** — Elastic hover actions (Filter In/Out, Add to timeline, toggle column).
- **Clickable severity pills / chips reopen pre-filtered views** (Datadog).
- **Real-time is expected but quiet** — stream/poll, but the queue order is the live signal (Elastic "Today" default, Datadog Live Tail, Splunk streaming).
- **Dark theme, high density, small-caps headers, monospace for raw data** — near-universal in SOC.
- **Redact noise, celebrate wins** — Defender Boxed, Datadog FP-rate reporting.

**Overrated for a small team:** deep multi-level IA (Prisma, Splunk app sprawl), pro-code hunting languages (SPL/KQL/XQL), custom Grafana design narratives, kiosk mode, "agentic auto-response" without auditability.

### AI-first SaaS / dev tools (Linear, Vercel, GitHub, Raycast, Warp, Cursor, Retool, Notion, Slack, LangSmith)
**Strong shared patterns:**
- **Cmd+K is table stakes** — Linear, Notion, Slack, Vercel, Warp, GitHub, Cursor, Raycast. Absence reads as legacy.
- **Goto-chord navigation** (`g <letter>` GitHub, Cmd+1-9 Warp) beats nested menus.
- **Esc is a state machine** — back one view (Raycast), select block (Notion), close overlay (Slack).
- **Restrained color, one accent** — monochrome + one brand accent; status color reserved for signal.
- **Search is instant, fuzzy, global, in-memory** — the one unforgivable sin is slow search.
- **Skeletons over spinners** — show structure, fill data.
- **Empty state is the onboarding** — `/` menu (Notion), import flow (Vercel), prompt-to-app (Retool).
- **Motion is nearly invisible** — speed is the premium feel, not animation.
- **Personalization is saved state** — favorites, saved filters/views, themes, remappable keys (Linear Display Options, Warp keysets).
- **Progressive disclosure** — GitHub `?` context dialog, Warp inline keybind-conflict warnings.

**Hype vs useful for an ops console:** palette-for-everything (Raycast) suits a launcher not a dense tool; Cursor's plan surface is good but not for an ops console; gratuitous motion is noise.

### Offensive security tools (Burp, Metasploit, Cobalt Strike, BloodHound, Nuclei, ZAP, K8s consoles)
**Strong shared patterns:**
- **Linear engagement flow over feature soup** — Burp intercept→send-to, ZAP Quick Start→Scan, BloodHound collect→ingest→explore. Sequence the work.
- **Per-target/per-engagement workspace isolation** — Metasploit projects, PD Cloud workspaces.
- **Evidence captured at every step** — raw request/response pairs, persisted per action (Nuclei JSONL, CS consoles).
- **Replay/reproduce affordances** — Burp send-to-Repeater, PD retest: "run again with inputs preserved" is one click.
- **Scope visualization** — Burp Target, ZAP Sites tree, K9s readonly: scope must be a persistent visible primitive.
- **Dashboard is a task queue, not a chart gallery** — Burp Dashboard, ZAP footer live alert counts.
- **Dual table + graph for the same state** — Cobalt Strike (Beacon tables + topology graph), Octant (tables + Resource Viewer): tables are the record of truth, graph is the comprehension layer.
- **Live progress with layered detail** — Burp's 7 scan sub-views; summary→detail drill-down on running work.
- **"Operator knows exactly what ran and why"** — Elastic Inspect-underlying-query; Metasploit prompt re-labeling. Every action exposes params/inputs/outputs.
- **Keyboard-first with progressive disclosure** — K9s `:pod`, Burp palette, ZAP contextual tabs.
- **Deliberate destructive-action semantics** — K9s delete (confirm) vs kill (no confirm).
- **Density is a feature** — operators optimize rows-per-screen and greppability.
- **Dark severity-coded chrome** — but the biggest risk is a "pretty" dashboard that abandons the evidence trail + replay story.

### Benchmark bar (what "best in class" means for us)
The benchmark target is not one product. It is: **Falcon/Defender job-titled left-rail IA + queue-led landing, Elastic inline table ergonomics + query transparency, Datadog saved views + Cmd+K, Linear/GitHub keyboard-first craft + instant fuzzy search, Cobalt Strike/Octant dual table+graph, Burp/Nuclei evidence-replay discipline, XSIAM correlation-before-analyst.** Everything validated against our real backend (65 endpoints, WS events) so nothing ships without a data source.

---

## Phase 3 — Benchmark: AI-OSOP vs. Best-in-Class

Scores are 0–10, calibrated against the researched bar, not against each other.

| # | Category | AI-OSOP | Best-in-class (benchmark) | Notes |
|---|----------|--------:|--------------------------:|-------|
| 1 | Overall appearance | 8 | 9 (Falcon, Linear) | Strong dark tokens; some pages visually uneven |
| 2 | Professional quality | 8 | 9 | Feels custom-built but polished; a few rough edges (mixed caps, ad-hoc spacing) |
| 3 | Information density | 7 | 9 (K9s, Cobalt) | Good but inconsistent; no density control |
| 4 | Readability | 8 | 9 | Type ramp now locked; small-caps microcopy is legible but aggressive |
| 5 | Navigation | 6 | 9 (Defender, Elastic) | 18 flat items; no grouping, no command palette |
| 6 | Discoverability | 6 | 9 (ZAP, GitHub) | `g`-chords exist but unlisted; features hidden in pages |
| 7 | Consistency | 8 | 9 | Component system strong; per-page variance remains |
| 8 | Accessibility | 8 | 9 | Focus traps, reduced motion, labels — no full a11y test suite |
| 9 | Responsiveness | 6 | 8 (Datadog 3-layout) | Mobile = drawer only; tables don't degrade |
| 10 | Component quality | 8 | 9 | 16 primitives; missing Button/Input/Select primitives (inline classes still) |
| 11 | Visual hierarchy | 7 | 9 | KPI-led landing buries the operational queue |
| 12 | Security-analyst workflow | 7 | 9 (Falcon, Defender) | Good per-page tooling; no triage-first flow, no cross-page context |
| 13 | Real-time monitoring | 8 | 9 (Slack, Defender) | WS push exists; no notification aggregation, no per-entity live views |
| 14 | Data visualization | 6 | 9 (Grafana, Wiz) | Basic charts; no sparklines/heat/topology analytics |
| 15 | Interaction quality | 6 | 9 (Elastic, Linear) | No inline row actions, no Cmd+K, no flyout drill-down |
| 16 | Performance | 8 | 9 | 223 kB main + split chunks; 19 lazy routes; charts/graphs heavy but split |
| 17 | AI-first experience | 4 | 8 (XSIAM, Defender Copilot, LangSmith) | An AI platform with no copilot or NL querying — biggest strategic miss |
| 18 | **Overall** | **6.9** | **8.9** | |

**Gap percentage:** ~22% (6.9 → 8.9 benchmark). The redesign targets close ~18 of the 22 points; the residual is enterprise scale (i18n, SSO UI, RBAC admin, multi-tenant org chrome) that is backend work, not design.

### Weakness detail (brutally honest)
1. **Navigation (5/10 → target 9):** the sidebar is a flat 18-item wall (`Sidebar.tsx`). Why weak: users must read every label to find anything; no hierarchy communicates "this is the operational queue vs. the knowledge layer." Industry: Falcon/Defender group into 3–5 sections by analyst job; Elastic allows reorder/hide. Impact of fixing: analysts find the right surface 2–3× faster.
2. **No command palette (4/10 → 9):** the `g`-chord system exists but is invisible and incomplete. Industry: Cmd+K is universal and instant-fuzzy. Impact: power users stop hunting; every page reachable in 2 keystrokes.
3. **Landing is KPI-led (5/10 → 9):** Overview leads with stat tiles; the operational signal (pending approvals, running tasks, new findings) is buried below the fold. Industry: Falcon Detect, Defender Incidents, Wiz Issues all land on a prioritized queue. Impact: MTTA drops because the queue is the first thing seen.
4. **Data viz (6/10 → 9):** charts are static bars/donuts; no sparkline columns in tables, no severity heat map over time, no topology analytics on the graph. Industry: Grafana's "dashboard is an argument"; Defender's attack-story timeline. Impact: pattern recognition (bursts, drift) becomes possible.
5. **AI-first (4/10 → 8):** zero copilot surface despite owning the entire agent stack. Industry: XSIAM/Defender auto-correlate + narrate; LangSmith makes agent traces the product surface. Impact: this is the differentiating move — NL query over findings/graph is uniquely ours to build.

---

## Phase 4 — Feature Gap Analysis

| Feature | Have | Why it matters | Fit for AI-OSOP |
|---|---|---|---|
| Global search | ✗ | Defender entity search, Datadog Cmd+K — find finding/agent/task/endpoint in one box | **YES — P0** (we have Neo4j graph + PG + Redis; search across findings, agents, tasks, engagements) |
| Command palette | Partial (`g`-chords) | Linear/Raycast/GitHub — every action 2 keystrokes | **YES — P0** (extend chords into Cmd+K with actions: navigate, new mission, halt, approve, refresh) |
| AI copilot | ✗ | Defender Copilot, Splunk AI — NL query over findings/graph; explains decisions | **YES — P0** (differentiator; can wrap existing `/intelligence/*` + reasoning-trace endpoints) |
| Notification center | ✗ | Defender bell, Slack unread — approvals, task failures, phase changes aggregated | **YES — P0** (WS already carries the events; missing is aggregation + bell UI) |
| Saved views / filters | ✗ | Datadog Saved View, Elastic saved query — persist triage context | **YES — P1** (localStorage + per-engagement persistence; filter state serializable) |
| Activity feed (cross-engagement) | Partial (per-engagement timeline) | Datadog signal trends, Defender activity log | **YES — P1** (aggregate WS events into a global feed w/ filters) |
| Custom dashboards / widgets | ✗ | Grafana, Retool | **Later** — small team; value low until queue/search/feed land |
| Drag-and-drop widgets | ✗ | Grafana, Retool | **Later** — heavy; not core to analyst flow |
| Attack-graph pathfinding | Partial (single lens) | BloodHound pathfinding — "is there a path to X?" | **YES — P1** (backend has `attack-paths`; surface pathfinding + scope overlay in graph) |
| Timeline explorer | Partial (list) | Defender attack-story timeline | **YES — P1** (upgrade MissionTimeline into filterable, entity-filtered explorer) |
| Live agent monitoring | Partial (agent list) | K9s `:pulses`, LangSmith traces | **YES — P1** (live agent grid w/ heartbeat freshness, task queue depth, per-agent trace link) |
| Workflow builder | ✗ | Splunk SOAR visual playbook editor | **Later** — backend has no workflow-builder API; out of frontend scope |
| Heat maps / severity bursts | ✗ | Datadog trends, Defender | **YES — P2** (severity-by-time heat on findings; cheap with existing data) |
| Health monitoring | ✓ (ConnectionManager) | — | Keep; fold MCP per-server detail into it |
| Session replay | ✗ | Datadog/Elastic investigation replay | **Partial** — we have replay-scripts + vault; add a per-finding replay timeline later |
| Advanced filtering | Partial (DataTable) | — | **P1** (faceted filter bars on Findings, Approvals, DLQ) |
| Progressive disclosure | Partial | ZAP hidden tabs, GitHub `?` | **P1** (sidebar collapse groups; contextual `?` dialog already exists) |
| Multi-monitor layouts | ✗ | Grafana kiosk, Splunk | **Later** — niche |
| Theme customization | ✓ (light/dark) | — | Keep; add density toggle (comfortable/compact) |

**Features to remove or demote (nothing ships without a backend):**
- Remove nothing that is wired — but **demote** "Knowledge Base Statistics" placeholder (already an honest empty state) and keep `load_test.ts` client-only sim clearly labeled as a stress sim, not telemetry.
- Do **not** build a workflow builder, custom-dashboard drag-drop, or session-replay UI until backend APIs exist — they would violate the "no fabricated UI" rule.

---

## Phase 5 — Design Specification: The Ideal AI-OSOP Dashboard

### 5.1 Navigation architecture (Falcon/Defender job-titled rail + Elastic reorderability)

Sidebar groups (each collapsible), top to bottom:

```
OPERATE            Overview · Mission Control · Approvals (badge count) · Tasks & Traces
INVESTIGATE        Findings · Verification · Diff Auth · Auth Audit · Visual Context
KNOW               Knowledge Graphs · Attack Chains · Hypotheses · Reasoning · Cognition
LEARN              Skill Intelligence · Learning & Analytics · Uncertainty
ADMIN              Administration · Mission Report (when session active)
```

- Each section is a labeled group with 2–5 items (no more). Groups collapse to icons (progressive disclosure).
- Badges: live counts on Approvals (from WS), Findings (verified vs open), Tasks (running).
- Bottom: NetworkHealth + ThemeToggle + density toggle + operator identity chip.

**Rationale:** every benchmarked console converges on job-titled sections, shallow depth, and live badges; our 18-item flat wall is the single biggest navigational cost.

### 5.2 Header (Defender top bar + Slack presence)

- Left: workspace/engagement switcher (current select) + phase + data-freshness.
- Center: **global search** (Cmd+K or `/`): one box that searches findings (id/title), agents (id), tasks, endpoints (Neo4j), engagements; as-you-type suggestions with entity icons; Enter opens detail.
- Right: **bell notification center** (typed: approvals pending, task failed, phase changed, finding verified — from WS); NEW MISSION, PRINT REPORT, EMERGENCY HALT, ThemeToggle.

### 5.3 Home / Overview (queue-led landing, Falcon Detect pattern)

New layout, top to bottom:
1. **Operational queue strip** (replaces KPI-only): pending approvals (live from WS), running tasks + traces, findings awaiting verification — each a compact card with count + latest item, click → drill into that page pre-filtered.
2. **Live activity feed** (right rail): the last ~20 WS events across the engagement with severity coloring + "jump to" links.
3. **KPI strip** moves below the queue (verified, critical, trust-score, spend) — numbers serve the work, not the reverse.
4. Findings ledger (searchable/sortable/paginated — already done) stays.

**Rationale:** Falcon/Defender/Wiz all land on the queue; the queue is the live signal, KPIs are the summary.

### 5.4 Engagement workspace (Metasploit project isolation + Burp linear flow)

- Top: scope chip row (domains in-scope / excluded, phase progress rail, elapsed time, budget gauge).
- A single "engagement object" owns: findings, agents working it, tasks/traces, graph slice, sessions, timeline — every page already scopes to `sessionId`; add a persistent workspace header so context never requires remembering the URL.

### 5.5 Findings explorer (Elastic inline ergonomics + Defender attack-story)

- **Filter bar:** severity chips (clickable → pre-filtered, Datadog pattern), status, category, provenance, saved views (P1).
- **Table:** rows with inline hover actions — View evidence (flyout), Replay, Verify, Resolve, Open in graph. No page hop.
- **Detail = slide-over flyout** (Wiz/Elastic), not a new page: title, category, severity, confidence, evidence chain, raw request/response, workflow trace, replay script, integrity hash, actions.
- **Attack story** per verified finding (Defender): actor → endpoint → vulnerability → exploit → evidence chain as a mini-timeline.

### 5.6 Agent control center (LangSmith traces + K9s pulses)

- Grid of live agents: status dot (heartbeat-freshness), agent_type, current_task, queue depth, derived spend.
- Click → right panel: per-agent trace waterfall (from `/engagements/{id}/traces` + observatory `trace/{task_id}`), recent observations, task history.
- Group by agent_type; filter by status; live-updating from WS `agent_observation`.

### 5.7 Knowledge Graphs (Octant/Cobalt dual table+graph + BloodHound pathfinding)

- Graph canvas: keep dagre layout; **add** scope overlay (in/out-of-scope tint), pathfinding mode ("shortest path between two nodes", from `/attack-paths`), node click → evidence timeline, legend.
- **Dual-pane toggle:** Graph ↔ Table of same data (Cobalt Strike pattern): table is the record of truth, graph is comprehension.

### 5.8 Attack chains viewer (Defender attack-story + XSIAM narrative)

- Chain cards → interactive stepper (type→title→url per step), confidence, MITRE mapping where available; click a step → jump to its finding detail flyout.
- "Narrative" toggle: LLM-generated summary of the chain (from existing reasoning/hypothesis data).

### 5.9 Logs / Timeline (Elastic Discover grammar)

- MissionTimeline → filterable event explorer: event-type facets, severity filter, actor filter, time-range slider, full-text filter; jump-to-entity links; searchable.
- Reuse the DataTable grammar so filters/saved views work identically across Timeline, Findings, Approvals, DLQ.

### 5.10 Reports (Snyk-ish clean + Defender evidence)

- Keep print/PDF export (already wired). Add: severity summary strip, per-finding evidence deep-links, "export package" already working. Add report metadata (generated at, engagement, operator).

### 5.11 Settings / Administration (Prisma-lite)

- Keep real controls (DLQ, sessions, halt/transition, config, stress test). Add: density toggle, saved-view management, notification preferences (localStorage), operator identity display.

### 5.12 Search (Defender entity search)

- Cmd+K palette = **navigation + actions + search** in one: typing filters nav items + recent engagements + findings + agents; `>` prefix = command actions (new mission, halt, approve, refresh); `/` prefix = deep search. Fuzzy, in-memory index built from hydrated stores + a lightweight fetch of searchable entities.

### 5.13 Notifications (Defender bell)

- Typed list from WS: `approval.pending`, `task.failed`, `task.completed`, `phase.changed`, `finding.verified`, `finding.submitted`. Unread count badge; click → navigate + mark read; "mark all read".

### 5.14 AI assistant (the differentiator)

- Right-dock copilot panel: NL questions over the engagement — "what critical findings are unverified?", "show the path from this endpoint to admin", "summarize what the swarm did in the last hour", "why did hypothesis X get refuted?".
- Backend wiring: reuse `/engagements/{id}/reasoning-trace`, `/cognition-summary`, `/hypotheses`, `/graph`, `/findings`; a `POST /engagements/{id}/assistant/query` endpoint composes these + LLM. Streaming responses (WS or SSE).
- Every answer cites its source (finding id / trace id) — transparency, Elastic-Inspect-style.

### 5.15 Keyboard shortcuts (GitHub grammar + Linear craft)

| Keys | Action |
|---|---|
| `Cmd/Ctrl+K` | Command palette / search |
| `/` | Focus global search |
| `g o/m/f/v/k/…` | Existing goto-chords (keep, document in `?`) |
| `a` | Approvals |
| `?` | Context-sensitive shortcut dialog (exists) |
| `Esc` | Back one level / close overlay (state machine) |
| `n` | New mission |

### 5.16 Mobile (Datadog 3-layout)

- <768px: stack queue cards → KPIs → feed; tables become cards; palette/notifications full-screen sheets; sidebar → bottom sheet.
- 768–1200px: condensed rail (icons + labels), 2-col grids.
- >1200px: full density, 3–4 col grids, dual-pane graph/table.

---

## Phase 6 — Visual Design System Specification

Most of this exists and is good. The spec codifies it and closes the gaps.

- **Color:** keep the dark-slate ramp + single cyan signal; severity semantics fixed: `critical=red, high=amber, medium/low=sky/grey` everywhere (badges, filters, charts, table sort). Light theme already tokenized.
- **Typography:** locked ramp (body-md/label-caps/label-xs/code-sm/base/lg/2xl). Rule: no `text-[px]` except the documented watermark. Small-caps labels only for metadata, never for primary actions.
- **Iconography:** lucide only (consistent stroke); icons accompany every primary nav item and inline action.
- **Spacing/grid:** 4px rhythm, 12-col grid, 16px gutter; density toggle adjusts base paddings (comfortable 16/24 → compact 8/12).
- **Elevation:** 3 shadow levels (already tokenized); overlays = themed scrims (already tokenized).
- **Motion:** 120–320ms, ease-out; only functional (reveal, flyout slide, live dot). `prefers-reduced-motion` already honored. No decorative loops.
- **Cards:** Panel/Card with optional glow (severity-coded shadow). Consistent padding rules.
- **Tables:** DataTable (sort/search/pagination) is the single table primitive; **add** inline row actions + clickable severity chips + sparkline column support.
- **Charts:** recharts; token-driven colors via `cssVar` (done); **add** sparklines, heat map component, dual-axis discipline (Grafana: normalize axes, right-axis for different units).
- **Forms/buttons:** extract `Button` and `Input`/`Select` primitives (today they are inline class strings) — single source for sizes, focus, disabled.
- **Empty/error/loading:** EmptyState + ErrorState + Skeleton exist; standardize copy voice ("no X yet — what to do next").
- **Toasts:** exist; keep 4 variants, add action toasts (e.g., "Approve?" with buttons).
- **Dialogs:** ModalShell exists (focus trap, Esc, aria-modal); make it the only modal path.
- **A11y rules:** AA contrast both themes (verified for core tokens), `:focus-visible` everywhere, aria-labels on icon-only, table `aria-sort`, live regions for feed/notifications, reduced-motion.

---

## Phase 7 — Implementation Roadmap (prioritized, engineer-practical)

Dependencies are internal; no new backend endpoints are required for P0 except the assistant query endpoint. All work is frontend unless noted.

### Wave 0 — Foundations (est. 4–6 h)
| # | Item | Effort | Deps | Acceptance criteria |
|---|------|--------|------|---------------------|
| 0.1 | Extract `Button` + `Input`/`Select` primitives | 3 h | none | All new UI uses them; typecheck/lint green |
| 0.2 | Density toggle (localStorage, token-driven) | 1 h | 0.1 | Toggle flips base padding vars; persists |
| 0.3 | Notification store (from WS events) | 1 h | none | WS events → typed notifications + unread count |
| 0.4 | Faceted filter bar component | 2 h | 0.1 | Reusable chips/select filters with serializable state |

### Wave 1 — The three P0s (est. 10–14 h)
| # | Item | Effort | Deps | Acceptance criteria |
|---|------|--------|------|---------------------|
| 1.1 | **Command palette + global search** (Cmd+K, fuzzy, entity search) | 6 h | 0.4 | Cmd+K opens ≤50ms; nav + findings + agents + actions searchable; `/` prefix deep search; Esc closes |
| 1.2 | **Notification center** (header bell) | 3 h | 0.3 | Typed notifications; click → navigate + mark read; unread badge live |
| 1.3 | **Queue-led Overview** | 4 h | 1.1 | Approvals/tasks/findings queue above KPIs; cards drill pre-filtered |
| 1.4 | **AI copilot panel + `POST /engagements/{id}/assistant/query`** | 5 h | 1.1 | NL questions answered with citations; streaming; backend endpoint wired |

### Wave 2 — Workflow depth (est. 10–12 h)
| # | Item | Effort | Deps | Acceptance criteria |
|---|------|--------|------|---------------------|
| 2.1 | Sidebar regroup into 5 job-titled sections + live badges | 3 h | 0.4 | Groups collapsible; badges from WS counts |
| 2.2 | Findings detail flyout (slide-over) + inline row actions | 5 h | 0.1, 0.4 | No page hop; actions fire backend endpoints; flyout shows evidence chain |
| 2.3 | Saved views (localStorage, per-list) | 3 h | 0.4 | Save/load/delete named filter sets on Findings/Approvals/DLQ |
| 2.4 | Timeline → event explorer (facets, time range, search) | 4 h | 0.4 | Same filter grammar as Findings |

### Wave 3 — Visualization & agents (est. 10–12 h)
| # | Item | Effort | Deps | Acceptance criteria |
|---|------|--------|------|---------------------|
| 3.1 | Graph pathfinding + scope overlay + dual graph/table toggle | 5 h | 2.1 | Pathfinding uses `/attack-paths`; scope tint from engagement; table mirrors graph |
| 3.2 | Agent control center (live grid + trace waterfall panel) | 4 h | 2.1 | Live heartbeat freshness; per-agent traces from observatory |
| 3.3 | Sparklines + severity heat map components | 3 h | none | Findings-by-severity heat by day; sparkline in table columns |

### Wave 4 — Enterprise polish (est. 8 h)
| # | Item | Effort | Deps | Acceptance criteria |
|---|------|--------|------|---------------------|
| 4.1 | Mobile: cards-on-mobile tables, sheet overlays | 4 h | 2.1 | <768px usable for triage |
| 4.2 | Attack-chain narrative view + MITRE mapping | 2 h | 2.2 | Chain stepper + narrative toggle |
| 4.3 | Action toasts + notification prefs | 1 h | 0.3 | Approval actions surface in toast with buttons |
| 4.4 | Storybook + token docs | 2 h | all | Component gallery documents the design system |

**Ordering rationale:** Wave 1 (palette, notifications, queue landing, copilot) attacks the four highest-scored gaps (nav, search, workflow, AI-first) with the least backend surface. Wave 2/3 deepen. Wave 4 is polish.

---

## Phase 8 — Final Evaluation

### Scores
- **Current dashboard:** 6.9/10 (Phase 3 table)
- **Best-dashboard benchmark:** 8.9/10
- **Gap:** ~22%
- **Estimated score after Waves 0–3:** 8.9–9.2/10
- **Estimated score after Wave 4:** 9.5/10 (remaining 0.5 = backend scale: i18n, org/RBAC admin, SSO, multi-tenant chrome)

### Top 20 highest-impact improvements (ranked)
1. Cmd+K command palette + global search (1.1)
2. Queue-led Overview landing (1.3)
3. AI copilot with citations (1.4)
4. Notification center from WS (1.2)
5. Sidebar regroup into job-titled sections (2.1)
6. Findings detail flyout + inline row actions (2.2)
7. Saved views (2.3)
8. Timeline event explorer (2.4)
9. Graph pathfinding + scope overlay + dual graph/table (3.1)
10. Agent control center (3.2)
11. Sparklines + severity heat map (3.3)
12. Density toggle (0.2)
13. Button/Input/Select primitives (0.1)
14. Faceted filter bars (0.4)
15. Mobile triage view (4.1)
16. Attack-chain narrative view (4.2)
17. Action toasts (4.3)
18. Notification preferences (4.3)
19. Storybook + token docs (4.4)
20. Operator identity chip in rail (with 2.1)

### Features that should be removed
- Nothing currently shipped is fake; **remove/demote** the client-only stress sim's "live" framing (label as simulation) — already partially honest.
- Do **not** add custom dashboards / workflow builder / session replay until backend APIs exist.

### Features that should be redesigned
- Overview (KPI-led → queue-led)
- Sidebar (flat 18 → 5 grouped sections)
- MissionTimeline (list → event explorer)
- KnowledgeGraphs (single lens → pathfinding + dual table/graph)
- Finding detail (page-embedded cards → slide-over flyout)

### Missing enterprise capabilities (backend-gated, not design)
- i18n scaffolding; org/RBAC admin UI; SSO/IdP wiring UI; multi-tenant org chrome; audit-log export UI; Playwright E2E suite; a11y axe CI gate.

### Roadmap to a true 10/10
1. **Waves 0–1** (2–3 days): palette, notifications, queue landing, copilot → score 8.4.
2. **Waves 2–3** (2–3 days): flyouts, saved views, explorer, graph/agents/heat → score 9.0.
3. **Wave 4** (1–2 days): mobile, narrative, toasts, Storybook → score 9.5.
4. **Backend partners** (eng backlog): E2E + axe CI, i18n, RBAC admin, SSO → score 10.

---

## Design Principles (the "why" — do not copy, extract)

1. **The queue is the landing page.** Analysts triage first; KPIs are summaries, not the work.
2. **Every surface is one keystroke or one click from any other.** Cmd+K + goto-chords + persistent global search.
3. **Context is a slide-over, never a page hop.** Flyouts keep the investigation anchored.
4. **Tables are the record of truth; graphs are the comprehension layer.** Same data, two lenses.
5. **Evidence is captured, replayable, and cited at every step.** No conclusion without a raw artifact and a "run it again" button.
6. **The operator knows exactly what ran and why.** Every action exposes params, inputs, output; AI answers cite their sources.
7. **Severity is a color, a filter, and a sort key — consistently, everywhere.**
8. **Real-time is quiet.** Stream in the background; surface the *delta* (new approval, failed task, verified finding), not the volume.
9. **Density is deliberate.** Provide comfortable/compact; never sacrifice greppability.
10. **Dark, restrained, one accent.** Signal color is earned by severity, not decoration.
11. **AI is the explainer, not the executor (yet).** Copilot summarizes, cites, and guides — automated response only when auditable.
12. **Scope is a visible, persistent primitive.** In-scope/out-of-scope is drawn, not remembered.
