# AI-OSOP ↔ PentAGI source-level parity inventory — 2026-10-16

**Verdict: NOT feature-parity certified; NOT production certified.** This is an
implementation inventory and acceptance contract, **not** a certificate of
tested functionality, vulnerability findings, target ownership, or permission
to run security tools. Scope: the **original shared, heavily dirty**
`/burp_mcp/ai-osop` tree, not a fork or a fresh checkout. No code, migrations,
live data, services, providers, containers, targets, or the continuation file
were modified for this audit.

## 1. Provenance and evidence discipline

- **Upstream released reference:** [PentAGI `v2.2.0`](https://github.com/vxcontrol/pentagi/tree/v2.2.0).
  **Moving-head comparison:** [PentAGI `main`](https://github.com/vxcontrol/pentagi/tree/main).
  Repository source was fetched at the named refs, rather than inferring behavior
  from screenshots, README feature tables or proposal documents.
- **Source-ref agreement observed on 2026-10-16:** Git blobs for
  `backend/pkg/controller/{flows,flow,task,subtask}.go`,
  `backend/pkg/tools/{registry,web_search,browser,memory}.go`,
  `backend/pkg/tools/searchers/searchers.go`,
  `backend/pkg/docker/worker_spec.go`,
  `backend/pkg/server/services/{knowledge,resources,flow_files}.go`,
  `backend/pkg/graph/subscriptions/controller.go`,
  `backend/pkg/providers/providers.go`,
  `frontend/src/lib/routes.ts` and
  `backend/docs/flow_execution.md` matched **between the pinned release and
  the fetched current `main`** by Git blob SHA. For example
  `controller/flows.go=f6b32a3a9fd9c589f0f74107abdd1606979ac29b`,
  `tools/web_search.go=6ee41f3cbc96e6bdd57667fb40100a6fcaa84da9`,
  `services/knowledge.go=4740be17f5881de216569d04fe6291cd49aebc59`,
  `services/resources.go=312aaabbc26f911365a37f9da79ac63fcb70fa38`,
  `subscriptions/controller.go=1909d5ddcc2375d2be554232261166cf3d9bed70`.
  **This is a sampled path comparison, not proof that the entire branches
  contain identical trees or that `main` will remain fixed.**
- **AI-OSOP reference:** actual working-tree Python, FastAPI and React files
  named below, read without changing them. The original worktree includes
  untracked modules and unrelated unresolved conflicts; do **not** infer that
  untracked code was deployed, packaged, migrated, or tested against a live DB.
- **Method:** `/reverse-engineer` static entrypoint → function → caller /
  cross-reference mapping. `/reverse-engineer-anything` explicitly says that
  complete source repositories should be analyzed with normal source tools;
  no compiled artifact behavior was needed or claimed. This is **static
  source evidence**, not runtime observation. Every “present” below means
  code/wiring observed, not successfully deployed or end-to-end qualified.
- **Grades:** **W** = real production registration/call path exists;
  **P** = narrow, non-equivalent counterpart exists; **G** = concrete missing
  production capability or boundary; **U** = cannot prove functionality from
  source alone; **S** = deliberate stricter safety boundary (not a parity
  regression). Evidence for a negative is scoped to the inspected entrypoints,
  not an assertion that no similarly named file exists anywhere.

## 2. Source-static runtime call graphs — not conceptual diagrams

**PentAGI, pinned v2.2.0 (current sampled `main` matches):**

```text
backend/cmd/pentagi/main.go
  -> backend/pkg/server/router.go:NewRouter
     -> REST services (flows, providers, knowledge, resources, flow_files)
     -> backend/pkg/graph/schema.graphqls + subscriptions/controller.go
  -> backend/pkg/controller/flows.go:NewFlowController
     -> CreateFlow / LoadFlows / StopFlow / FinishFlow / ReportFlow
     -> backend/pkg/controller/flow.go:buildFlowWorker / LoadFlowWorker
        -> flowWorker.worker -> processInput -> runTask/execTask
        -> backend/pkg/controller/task.go:NewTaskWorker / Run
           -> backend/pkg/controller/subtask.go:NewSubtaskWorker / Run
        -> backend/pkg/providers/providers.go:NewFlowProvider / NewAssistantProvider
        -> backend/pkg/tools/tools.go:flowToolsExecutor.Prepare
           -> backend/pkg/tools/registry.go (typed tool definitions)
           -> backend/pkg/tools/web_search.go:Handle -> searchers/*
           -> backend/pkg/tools/browser.go:Handle -> scraper / screenshot
           -> backend/pkg/tools/memory.go:Handle -> knowledge/vector queries
           -> backend/pkg/docker/worker_spec.go -> docker/client.go
  -> backend/pkg/graph/subscriptions/controller.go (per-flow and per-user events)
```

The source independently identifies the Flow→Task→Subtask hierarchy:
[flows.go](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flows.go),
[flow.go](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flow.go),
[task.go](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/task.go),
[subtask.go](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/subtask.go),
[tools.go](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/tools.go).
The separate Assistant worker is in
[controller/assistant.go](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/assistant.go);
do not silently equate it to any AI-OSOP “assistant” UI label.

**AI-OSOP, current dirty production Python/React wiring:**

```text
src/ai_osop/api/main.py:lifespan
  -> Orchestrator.initialize (src/ai_osop/orchestrator/orchestrator.py)
  -> instantiate + register 11 core and 9 experimental BaseAgent subclasses
     -> src/ai_osop/agents/base.py:BaseAgent.execute_task
  -> app.include_router(...flows, flow_artifacts, flow_artifact_reviews,
       supervision, provider_invoices, report_attestations, findings,
       target_authority, approvals, tasks, intelligence...)
  -> authenticated /ws/engagements/{engagement_id}
  -> src/ai_osop/api/routers/flows.py (Flow/Task/Subtask API)
     -> src/ai_osop/orchestrator/flow_refinement.py:BoundedFlowRefiner._propose
        -> orchestrator/planner_execution.py:PlannerExecutionStore.admit
        -> orchestrator/research_checkpoint.py:ResearchCheckpointStore
        -> core/llm_client.py -> memory/model_usage.py:ModelUsageLedger
     -> orchestrator/orchestrator.py:_execute_task_durable
        -> BaseAgent.execute_task -> MCP registry/tool adapter
           -> mcp/protocol.py + adapters/{browser,recon,burp,nuclei,...}_mcp.py
     -> orchestrator/terminal_dispatcher.py + memory/terminal_lifecycle.py
  -> memory/supervision_store.py (PG events/outbox) ->
       orchestrator/supervision_outbox.py -> coordination_bus.py
  -> ui/src/App.tsx:BrowserRouter -> pages/FlowOperations.tsx
       -> services/flows.ts and services/flowArtifacts.ts (FastAPI fetch)
```

The API registration above was read in `main.py` (`lifespan` near 180;
agent registration 307–375; routers 531–549; authenticated WS from 571).
Its existence does not establish that all experimental tools, optional
providers, backend migrations and external services are working. In particular
`BaseAgent.execute_task` can call separately supplied MCP services; a Python
adapter declaration is **not** an independently verified external service.

## 3. Actual subsystem comparison and acceptance contract

Each row identifies **upstream shipped source**, **AI-OSOP actual counterpart**,
**evidence-grade decision / gap**, and **minimum independent acceptance**.
Where present, upstream links are pinned to `v2.2.0`; the same relative path
under `main` is the corresponding current-main review target.

| Domain | PentAGI v2.2.0 pinned source | AI-OSOP real entrypoints | Finding / acceptance criterion |
|---|---|---|---|
| 1. Flow controller / restart | [`controller/flows.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flows.go) `LoadFlows`, `CreateFlow`, `StopFlow`, `ReportFlow`; [`controller/flow.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flow.go) `LoadFlowWorker`, `worker`, `processInput`, `execTask` | `api/routers/flows.py`, `orchestrator/{orchestrator,flow_refinement,recovery_service,planner_resume,temporal_worker}.py`, `memory/session_memory.py` | **W/P/U**: durable signed Flow/revision+planner/checkpoint paths exist; PentAGI worker parity and hard-kill recovery **unproven**. Accept: rehydrate an approved Flow/Task/Subtask across 2+ replicas with live PostgreSQL/Temporal, simultaneous CAS, revoked authorization, restart at every crash boundary; no duplicate physical side effects and UNKNOWN retained where unavoidable. |
| 2. Task/Subtask worker semantics | [`controller/task.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/task.go) `Run`, `writeResult`, `Finish`; [`controller/subtask.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/subtask.go) `Run`, `SetResult`, `Finish` | `orchestrator/orchestrator.py` `_execute_task_durable`, `generate_flow_subtasks`; `memory/{terminal_lifecycle,session_memory}.py`; `orchestrator/{terminal_dispatcher,planner_execution}.py` | **W/P**: explicit admission and callback fences, rather than PentAGI exact worker lifecycle. Accept: persisted parent/subtask/Task identity and signed scope remain bound for each tool dispatch; unfinished/ambiguous events never become `completed` by worker restart; source/target task lineage persists under concurrent workers. |
| 3. Specialized agents / roles | [`controller/flow.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flow.go) provider workers; [`controller/assistant.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/assistant.go) independent Assistant; [`templates/prompts/`](https://github.com/vxcontrol/pentagi/tree/v2.2.0/backend/pkg/templates/prompts) role instructions | `api/main.py` registers 20 agent classes: `agents/{recon,vuln,exploit,payload,reporting,workflow,context_manager,...}_agent.py` and `agents/experimental/*.py`; `agents/base.py` | **W/P/U**: a real registered agent fleet, different taxonomy and execution design. Accept: enumerate per-role production registration, authority, actual callable tool contracts, task types and cancellation outcomes; demonstrate at least one authorized complete Flow for each supported role before declaring role parity. No assertion that 20 names = 20 functional autonomous roles. |
| 4. Tool registry / terminal / files | [`tools/registry.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/registry.go) `GetRegistryDefinitions`; [`tools/tools.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/tools.go) `flowToolsExecutor.Prepare`; [`docker/worker_spec.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/docker/worker_spec.go) | `mcp/protocol.py`, `adapters/{recon,burp,nuclei,payload,browser,...}_mcp.py`, `agents/base.py`, `safety/scope.py:SandboxManager`, `memory/terminal_lifecycle.py` | **P/S/U**: real MCP and sandbox entrypoints, **not** the same integrated terminal/file worker API; sandbox policy is stricter by intent. Accept: registry lists backed-by-running-service tools; mock/live command lifecycle audited and halted, with no host socket/privileged mounts, no command after revocation, and reported UNKNOWN on lost callback. No blanket terminal/files parity. |
| 5. Unified intent web search | [`tools/web_search.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/web_search.go) `Handle`, `normalizeMode`, engine selection; [`tools/searchers/searchers.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/searchers/searchers.go) provider interface; [`searchers/`](https://github.com/vxcontrol/pentagi/tree/v2.2.0/backend/pkg/tools/searchers) engines | `core/trusted_search.py:discover_trusted_search`; `adapters/recon_mcp.py` `historical_urls`, `osint_lookup`; `adapters/threat_intel_mcp.py` | **P/G**: AI-OSOP **does** have a bounded authorized `web_search` MCP path, but presently only opts into a SearXNG-described free index and Wayback, with **`mode='links'` only** (confirmed `trusted_search.py` 178–397). It is **not PentAGI's unified `links/answer/research/exploit` intent router or its engine fallback**. Accept: distinct opt-in query intent contract, bounded per-engine adapter/output, paid provider off by default, signed ROE, normalized provenance, SSRF/redirect/DNS rebinding checks, deterministic no-call-on-denial tests, and independent live engine checks. |
| 6. Long-term memory / graph search | [`tools/memory.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/memory.go) `Handle` search of memory/guide/answer/code; [`graph/schema.graphqls`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/graph/schema.graphqls) vector types | `memory/{vector_memory,graph_memory,graph_research_context,reviewed_flow_knowledge}.py`; `agents/base.py` verified-context integration | **W/P/S**: tenant/Task/Flow-fenced semantic and graph context are real but purpose-built, not PentAGI's shared CRUD knowledge search catalog. Reviewed sources remain inert and untrusted as instructions. Accept: bounded matching per engagement/Task; no other-tenant leak, source SHA/review revocation recheck, prompt-injection non-promotion, bad graph/vector data fails closed; run with disposable PG/pgvector+Neo4j. |
| 7. Independent user Knowledge Base | [`server/services/knowledge.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/server/services/knowledge.go) `ListDocuments`, `GetDocument`, `SearchDocuments`, `CreateDocument`, `UpdateDocument`, `DeleteDocument`; [`frontend/pages/knowledges/knowledges.tsx`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/frontend/src/pages/knowledges/knowledges.tsx) | `memory/reviewed_flow_knowledge.py` reads *explicitly reviewed Flow artifacts*; `memory/vector_memory.py` task-scoped semantic knowledge; `api/main.py` registered routers; `ui/src/App.tsx` registered pages | **G (with partial knowledge technology)**: no counterpart for **independent operator-owned Knowledge Document CRUD/search** in the inspected registered FastAPI routers and React routes. A graph visualization or Flow review is not a user KB CRUD surface. Accept: new authenticated owner/admin CRUD+semantic search, source/revision/tenant isolation, versioned delete propagation, embedding budget and ingestion bounds, matching React forms/routes, real PG/pgvector tests; never bypass independent review before agent inference. |
| 8. Resource library / files | [`server/services/resources.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/server/services/resources.go) `ListResources`, `UploadResources`, `MkdirResource`, `MoveResource`, `CopyResource`, `DeleteResource`, `DownloadResource`; [`server/services/flow_files.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/server/services/flow_files.go); [`controller/flow.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flow.go) `PutResources` / `pushResourcesToContainer` | `api/routers/flow_artifacts.py`; `memory/{flow_artifacts,flow_resource_exports,flow_artifact_reviews}.py`; `ui/src/services/flowArtifacts.ts`; `ui/src/components/flows/FlowArtifactsPanel.tsx` | **W/P/G/S**: immutable signed-Flow upload/list/download and bounded inert resource manifest/ZIP **are real**; `flow_resource_exports.py` explicitly says **no host files created**. **Not** independent user folder CRUD, mutable file move/copy, or container resource synchronization. Accept: only if needed, implement policy-gated per-user library and separately approved read-only worker mount/sync with content hashes, path-traversal/symlink/Windows reparse+TOCTOU tests, authorization/revocation, retry/cleanup; never equate inert ZIP export to a live worker resource mount. |
| 9. Browser / screenshot | [`tools/browser.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/browser.go) `Handle`, `ContentMD`, `ContentHTML`, `Links`, screenshot paths, scraper transport; [`tools/web_search.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/tools/web_search.go) optional browser-backed analytic | `adapters/browser_mcp.py:execute_action` (`navigate`, `capture_session`, `screenshot`, `dom_snapshot`, `flush_har`); `agents/workflow_agent.py:PlaywrightAgent`; `memory/terminal_lifecycle.py`; `core/diff_auth_engine.py` | **W/P/U**: stateful Playwright MCP exists, including authenticated session import; **not** PentAGI's same stateless scraper/markdown/links response contract. Accept: explicitly authorized browser identity, destination and method scope; signed durable per-step task effect; HAR/screenshot source hashes, bounded export, redirect/DNS/host protections, kill/restart UNKNOWN handling; real isolated browser-service proof without cross-session leakage. |
| 10. Provider models / configuration | [`providers/providers.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/providers/providers.go) `NewProviderController`, `NewFlowProvider`, `NewAssistantProvider`, `CreateProvider`, `UpdateProvider`, `DeleteProvider`, `TestProvider`; [`providers/catalog.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/providers/catalog.go) | `core/llm_client.py`, `core/provider_routing.py`, `core/embedding_bounds.py`; `memory/model_usage.py` and `flow_model_analytics.py`; `api/routers/provider_invoices.py`; `ui/src/components/flows/FlowModelAnalyticsPanel.tsx` | **W/P/G/U**: real LiteLLM route, optional bounded allowlist and signed PG reservation/UNKNOWN ledger. `provider_routing.py` explicitly says opt-in environment config **does not remotely verify a served model**. No comparable operator-facing PentAGI multi-provider CRUD/test/readiness lifecycle proven in AI-OSOP registered routes. Accept: per-role model capabilities/config/test gates if required, budget reserve→call→settle and no duplicate UNKNOWN, limits on embeddings; verify provider-native project totals separately; never claim call-level invoices from provider totals. |
| 11. Notification / event subscriptions | [`graph/subscriptions/controller.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/graph/subscriptions/controller.go) per-user, per-Flow channels for Flow/Task/Assistant/files/messages/searches/screenshots/tool calls; [`server/router.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/server/router.go) GraphQL setup | `memory/supervision_store.py` PG events/outbox; `orchestrator/{supervision_outbox,coordination_bus}.py`; `api/routers/supervision.py` `/events/stream`; `api/main.py` authenticated engagement WebSocket | **W/P/U**: durable PG outbox + bounded local fanout and authenticated SSE/WS, not PentAGI's exact GraphQL subscription topics/schema or user-resource events. `supervision_outbox.py` distinguishes callback and durable dedupe; callback timeout is **not** proof of third-party delivery. Accept: per-tenant authenticated cursor/replay and revocation, subscriber pressure/drops, multi-replica producer/consumer dedupe, partition+late-subscriber behavior; any email/push/third-party receipt must have its own explicit delivery contract. |
| 12. Reporting / release | [`controller/flow.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flow.go) `Report`, `runReport`, `reportWriteUpFailure`; [`controller/flows.go`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/controller/flows.go) `ReportFlow`; [`templates/prompts/reporter.tmpl`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/backend/pkg/templates/prompts/reporter.tmpl) | `agents/reporting_agent.py`; `api/routers/report_attestations.py`; `api/routers/findings.py`; `ui/src/pages/MissionReport.tsx`; `ui/src/services/signedReports.ts` | **W/P/S, target-proof G**: bounded report generation and signed artifact attestations exist; independent senior release currently **fails closed** when target-side authority cannot be proved. `report_attestations.py:_independent_target_authority_available` explicitly returns `False` (around lines 132–142); graph/provider flags are not proof. Browser-printable PDF in MissionReport is explicitly **not a signed report**. Accept: independently authenticated target-side ownership/effect proof, immutable source lineage and comparison UNKNOWN fence, concurrent-safe senior release, readback signature and cross-tenant revocation; only then label findings independently verified. |
| 13. React operator application | [`frontend/src/lib/routes.ts`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/frontend/src/lib/routes.ts), [`frontend/src/pages/flows/flows.tsx`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/frontend/src/pages/flows/flows.tsx), [`frontend/src/pages/knowledges/knowledges.tsx`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/frontend/src/pages/knowledges/knowledges.tsx), [`frontend/src/pages/resources/resources.tsx`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/frontend/src/pages/resources/resources.tsx), [`frontend/src/features/flows/files/flow-files.tsx`](https://github.com/vxcontrol/pentagi/blob/v2.2.0/frontend/src/features/flows/files/flow-files.tsx) | `ui/src/App.tsx` routes; `ui/src/pages/{FlowOperations,KnowledgeGraphs,ResearchIntelligence,MissionReport,FindingsVerification}.tsx`; `ui/src/components/flows/*`; `ui/src/services/{flows,flowArtifacts,flowArtifactReviews,signedReports}.ts` | **W/P/G**: React/Vite Flow operations with auth, revision-fenced REST, review and analytics are present; no upstream-equivalent `/knowledges` or `/resources` operator CRUD route in `App.tsx`. PentAGI uses GraphQL/Apollo; AI-OSOP uses FastAPI REST+SSE/WS, **not equivalent UI API semantics**. Accept: test each UI action against an actual authenticated backend, stale Flow/ROE revocation, list pagination, multi-tenant denial, error/loading/pending, no dangerous defaults; confirm backend response matches typed client and deploy built assets. |

## 4. Subsystem-specific verified negatives and boundary clarifications

1. **Do not call a service-level screenshot/path adapter a complete browser
   research system.** PentAGI `browser.go` calls a scraper and has
   `ContentMD/ContentHTML/Links`; AI-OSOP `BrowserMCPAdapter` forwards
   commands to a separate MCP process whose remote success is not independent
   verification. The path `mcp/protocol.py` is part of execution, but does
   not establish deployed browser health.
2. **The AI-OSOP search gap is narrower than “no search.”** Actual
   `core/trusted_search.py` advertises an optional `web_search` MCP tool,
   requires scope/approval and restricts accepted `engine` to `searxng`,
   `mode='links'`; Wayback is a secondary index; findings are labeled
   `verified=False`, `reportable=False`, `UNKNOWN`. PentAGI
   `tools/web_search.go` dispatches multiple analytic/link/research search
   modes to `tools/searchers/*`. Engine count or strings are **not** parity.
3. **Reviewed artifacts are not a user-maintained KB.**
   `memory/reviewed_flow_knowledge.py` intentionally permits only
   independently senior-reviewed, inert, scoped fact entries; upstream
   `KnowledgeService` exposes create/update/delete. No bypass of review is
   acceptable simply to copy a user knowledge-management UI.
4. **Read-only Flow resource export is not execution filesystem sync.**
   `memory/flow_resource_exports.py` explicitly reports
   `host_files_created=False`, while PentAGI `flow.go` copies resources
   into the Flow container and `server/services/flow_files.go` handles
   file pull/promote. These workflows have different trust and side-effect
   models. Mounting Docker host sockets or arbitrary folders is not justified.
5. **Model route validation ≠ provider verification or billing certification.**
   AI-OSOP `core/provider_routing.py` is opt-in and validates configured
   deployment credentials; `model_usage.py` records provider-reported
   facts and UNKNOWN outcomes. `api/routers/provider_invoices.py` explicitly
   refuses individual provider-call verification from aggregate cost
   evidence. Provider costs cannot silently become audited target results.
6. **Notifications ≠ remote delivery ACK.** PentAGI GraphQL channels and
   AI-OSOP SSE/WS/PG outbox are both genuine but different contracts. Neither
   a publish callback nor a timeout establishes that a human received an
   email, that a client consumed the event, or that a remote action stopped.
7. **Target verification is a deliberate release blocker.**
   `report_attestations.py` explicitly lacks an independently trusted
   target-authority source. “Verified vulnerability”, automatically exploitable
   finding, signed comparison candidate, graph `validated=true`, and
   provider-response success must not be conflated. Do not downgrade this
   fence to achieve benchmark or screenshot parity.
8. **PentAGI role and UI differences should not be copied blindly.**
   Its Flow/Task/Subtask/Assistant workers, provider-specific role models,
   persistent user resource library and GraphQL frontend are cohesive with its
   Go backend; AI-OSOP has separate signed approvals, task ledgers, MCP
   execution and React/FastAPI contracts. Parity means reproducing safe user
   outcomes with independent evidence, not mirroring unsafe privilege or
   internal types.

## 5. Priority order for follow-on implementation (not work performed here)

| Rank | Implement only after exact entrypoint confirmation | Acceptance / non-negotiable fence |
|---|---|---|
| **P0** | Independently authenticated target-authority evidence and report promotion | Real authorized controlled target; source/target task+identity+method+ROE, immutable signed proof and negative cross-tenant/revocation/replay tests; no provider testimony promotion. Until then reports remain UNKNOWN/blocked. |
| **P0** | Full multiprocess crash/replay qualification for Flow→Task→Subtask, model admission and tool callbacks | Disposable live PG/Redis/Neo4j/Temporal/browser/MCP; simultaneous agents, producer loss, cancel, lease steal, DB restart; no duplicate external action after UNKNOWN; signed scope current at every resumed effect. |
| **P1** | Operator user Knowledge Base CRUD/search separate from reviewed Flow facts | User resource identity and ACL, bounded ingestion/embedding, edit/delete invalidation, React service/page, exact signed-task retrieval versus inert prompt data tests. |
| **P1** | Unified authorized web search intent routing | Read-only first; opt-in engines with explicit provider costs and fallback behavior, typed `links/answer/research` results; no automatic exploit intent or out-of-scope browser/tool activity. Verify real tools and engine responses. |
| **P1** | Resource library and safe worker file synchronization if operationally required | No mutable filesystem side effects before approved admission; pathname/symlink/reparse and hardlink race tests; separate sandbox mount policy; readback content hash, no host socket. |
| **P1** | Notification event contract across React and backend | Authenticate/authorize per topic and event, replay cursor vs live gap, durable subscriber ACK semantics only when independently persisted, overload and partition/revoke tests. |
| **P2** | Operator provider configuration/capability tester, role model controls | Strict model/credential allowlist, optional server-side test without paid auto-probe, signed precharge, UNKNOWN cost surfaced, operator ownership/secret masking; UI never prints credentials. |
| **P2** | Browser-backed research and React parity polish | Source-checked scraper response and screenshots, authorized task/target lineage, safe preview and tool budget. Complete UI CRUD only for backends actually supported. |

## 6. Reproducibility and release decision

**Source evidence inspected** (not exhaustive): PentAGI pinned/current
`backend/pkg/controller/{flows,flow,task,subtask,assistant}.go`,
`backend/pkg/tools/{registry,tools,web_search,browser,memory}.go`,
`backend/pkg/tools/searchers/searchers.go`,
`backend/pkg/server/services/{knowledge,resources,flow_files}.go`,
`backend/pkg/providers/{providers,catalog}.go`,
`backend/pkg/graph/{schema.graphqls,subscriptions/controller.go}`,
`backend/pkg/docker/worker_spec.go`,
`frontend/src/lib/routes.ts`,
`frontend/src/pages/{flows/flows,knowledges/knowledges,resources/resources}.tsx`,
`frontend/src/features/flows/files/flow-files.tsx`, and
`backend/docs/flow_execution.md`. Exact pinned source hyperlinks
appear in the matrix. Current main path links use the same relative paths
under [`main`](https://github.com/vxcontrol/pentagi/tree/main).
Not all referenced source files were byte-compared between refs; no
unobserved upstream delta is asserted.

**AI-OSOP inspected:** registration under `src/ai_osop/api/main.py`;
routers `flows,flow_artifacts,flow_artifact_reviews,supervision,
report_attestations,provider_invoices,intelligence`; orchestrator
`orchestrator,flow_refinement,planner_execution,research_checkpoint,
supervision_outbox,coordination_bus`; `agents/base.py` and specialized
agent files; `mcp/protocol.py` and selected adapters;
`core/trusted_search.py`, `core/provider_routing.py`; memory
`vector_memory,graph_memory,graph_research_context,
reviewed_flow_knowledge,flow_resource_exports,model_usage,
supervision_store`; `ui/src/App.tsx`, real pages and
`services/{flows,flowArtifacts}.ts`. Where no direct read was needed,
cross-references were confirmed through `rg` or imports; this is
**not** a full semantic review of every file.

**No live qualification for this inventory:** no Docker, external model,
search engine, MCP browser, simulated victim, protected target, live
PostgreSQL/pgvector/Neo4j/Redis/Temporal, staging React application,
GraphQL subscription or reporting signoff was started or mutated.
Live operational availability, real user behavior, and genuinely
independent target verification remain **UNQUALIFIED**. Git dirty state
and the existing continuation document, including its true EOF, are
untouched. This standalone inventory should inform a prioritized
implementation and separate qualification plan; **do not declare PentAGI
parity on the basis of this file**.

## 2026-10-21 current repository corrections (additive)

This historical inventory evaluated the pinned PentAGI v2.2.0 and a main snapshot sampled 2026-10-16. NO freshly verified current upstream main comparison is asserted. The following corrects the outdated local AI-OSOP counterpart references without rewriting the original audit:

- **Operator knowledge CRUD/search actually exists.** Migration `0019_operator_knowledge_documents.py` defines Flow/tenant/owner-scoped PostgreSQL guide/answer/code documents, CAS revision and tombstone metadata. `src/ai_osop/memory/operator_knowledge.py` contains authenticated Flow-owner fencing, bounded title/content/size and SHA readback, soft deletion, paginated list and search. `src/ai_osop/api/routers/operator_knowledge.py` exposes registered `/flows/{flow_id}/operator-knowledge` POST/GET, scoped search and document GET/PUT/DELETE, and `src/ai_osop/api/main.py` includes that router. `ui/src/components/flows/OperatorKnowledgePanel.tsx` and `ui/src/services/operatorKnowledge.ts` are wired into `FlowOperations.tsx`. Prime directly reran `tests/test_operator_knowledge_20261016.py` and `tests/test_operator_knowledge_agent_isolation_20261016.py`: **10 passed** (local mocked/store tests, not real PostgreSQL). Documents explicitly remain inert `untrusted_operator_text`, `approved_for_agent_context=false`; they are NOT independent free-standing user-global KB, reviewed agent RAG, semantic multi-engine search or verified target evidence. This corrects row 7's old statement that no registered CRUD surface existed, and row 13's incomplete UI counterpart listing.
- **Provider intent and nonsecret credential-reference review also exist**, via registered `provider_route_policy_reviews` and `provider_credential_profile_refs` routers/stores and React Flow panels. These are operator intent/review and symbolic reference metadata, NOT live provider credential vault provisioning, rotation, remote model served verification, readiness or paid provider test calls. Thus row 10's original no complete active PentAGI provider CRUD/TestProvider-equivalent conclusion STILL stands, but the local counterpart is more than an environment-only route declaration.
- **Supervision SSE cursor safety advanced** on 2026-10-21: `src/ai_osop/api/routers/supervision.py` caps query and `Last-Event-ID` to PostgreSQL signed BIGINT, denies malformed/oversized values; prime observed **29 focused combined API tests**. This is not full PentAGI GraphQL event subscription parity or live multi-replica delivery.
- **Original native SourceMap** has new signed current DB, process and read-only pre-0035 original bootstrap witnesses plus schema-only `0036` finite paired grant CHECK and real isolated PostgreSQL/Alembic minimal-schema qualification. Production issuer, native process PID binding, first-use post-proof coordinator join, least-privilege positive mount access, genuine 0033 SourceMap running worker and owner-of-record effects are STILL unqualified. These components do not establish full tool/worker parity.
- **Release path corrected**: `scripts/qualification/generate_release_certificate.py` previously emitted hard-coded fictitious certification/approvals. It now emits only `RELEASE_READINESS_DRAFT.md`, never generates a certificate and exits 2; focused tests passed. Senior-signed target-authoritative release remains absent.

**Corrected parity assessment:** Meaningful but narrowly scoped owner/Flow knowledge, provider intent metadata and authenticated SSE surfaces exist; full PentAGI v2.2.0 provider administration, independent user KB/resources, unified search and subscriptions, 11 native provider effects, target-owned evidence and senior production release remain **UNQUALIFIED**. The original main snapshot remains HISTORICAL, not freshly checked.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**

## 2026-10-21 follow-up: bounded search intent is present (corrected)

The original row 5's ``mode='links' only`` statement describes the **provider dispatch**, not the whole currently implemented request/response contract. Current `src/ai_osop/core/trusted_search.py` accepts exact opt-in operator intents `links`, `answer`, and `research` (rejecting `exploit` and unknown values), rechecks the active signed original Recon Task/authorization/Flow and can invoke only bounded `web_search` or `wayback_urls` link-index calls **if an authorized provider actually exposes them**. The configured native Go `recon-mcp` currently exposes only inert `authority_status`, so these indexed search calls are **not** qualified as callable against the configured native fleet. `answer`/`research` produce a typed, citation-hash-bound **unverified research handoff** when index leads exist, with excerpts explicitly labelled `untrusted_index_excerpt`, `finding_verified=false`, `reportable=false` and `not_an_answer=true`; they do **not** synthesize or authenticate answers, fetch arbitrary pages, or enable paid-provider/exploit behavior. Prime directly ran `tests/test_trusted_search_intent_20261016.py` and `tests/test_trusted_search_intent_handoff_20261018.py`: **19 passed** locally on 2026-10-21. No live search index or independent content/owner-of-record effect was contacted. PentAGI v2.2.0's diverse search-engine selection, actual synthesized modes and browser-rich result equivalence remain **unqualified**; the historical sampled upstream `main` was not rechecked.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**

## 2026-10-21 verified operator-knowledge integrity and Browser original readback correction

The 0019 Flow-owned operator knowledge document store now has additive 0038 database guarantees absent from the 2026-10-16 parity snapshot: a transactional precheck, composite `(flow_id, engagement_id)` Flow foreign key, and exact PostgreSQL UTF-8 content SHA-256 CHECK. Worker32 ran actual checked-in 0019/0038 Alembic Operations against a disposable nonroot Unix-socket PostgreSQL16 (2 passed, synthetic minimal predecessor tables). This is *not* a user-global, independently owned PentAGI knowledge library or live RAG integration. `mcp-servers/python/browser_mcp.py` now provides a bounded original PNG/DOM/HAR current byte-hash readback against a durable one-use provider-signed sidecar after a real offline Chromium capture; the new genuine isolated Chromium regression passed. It is only provider-local evidence integrity: current central signed authorization, independent owner-of-record target effect and multi-replica durable readback are **not** verified. Pinned PentAGI v2.2.0 and historically sampled 2026-10-16 upstream `main` remain the comparison references; no fresh upstream inspection or production parity is claimed.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**

### 2026-10-21 genuine 0039 user-owned library and bounded MCP control-response continuation

- **Original dirty checkout and release guard:** Added new `0039_operator_global_library.py` after verified `0038`; the prior Flow-local `0019/0038` store remains unchanged. The three protected `AM` paths were not edited. No stage, commit, reset, Docker, app database, paid provider, authorized-target scanner or deployment occurred.
- **Substantive user-level knowledge implementation:** `src/ai_osop/memory/operator_global_library.py` with `src/ai_osop/api/routers/operator_global_library.py` actually registered in `api/main.py` provides signed-human, stable issuer/owner scoped CRUD and bounded text search across Flows; it cannot be impersonated by caller-supplied owner IDs. New `0039` PostgreSQL schema has independent user document owner, append-only original revisions, a deferred FK pinning current revision, exact UTF-8 SHA-256 CHECK, immutable-history triggers, CAS revisions, permanent tombstones, and refuses destructive downgrade while any original row survives. Knowledge remains inert **untrusted_user_text**, not trustworthy instructions, original vulnerability evidence, vector synthesis or human target-owner proof.
- **Actual independent disposable PostgreSQL16 qualification:** `tests/qualification/test_operator_global_library_0039_real_pg_20261021.py` with explicit `OSOP_DISPOSABLE_OPERATOR_GLOBAL_LIBRARY_0039_PG=1` returned **2 passed** using an isolated nonroot Ubuntu/WSL PostgreSQL16 0700 Unix socket, no TCP listener. It executed the actual 0039 Alembic online upgrade/downgrade, real SHA-256 constraints, revision immutability, cross-owner and tombstone rejection, populated downgrade denial, and ran actual async library store SQL against that same real database using a small psycopg adapter. The test exposed and drove a real fix to PostgreSQL-invalid NUL in the advisory-lock label, now SHA-256 hashed. The Linux SQLAlchemy async driver itself was **not** exercised because this existing Windows virtualenv has no Linux `greenlet` binary; do not claim full production SQLAlchemy/replica validation. Original private PG process and files were torn down.
- **MCP shared client control paths hardened:** Existing bounded 2 MiB strict streaming, duplicate-key/NaN/Infinity/depth/collection checks now apply to `/mcp/initialize`, `/mcp/state`, `/mcp/cancel`, `/mcp/request/status` and post-restart read-only status/stop HTTP. Original execution body forensic behavior remains separate. `tests/test_mcp_control_bounded_wire_20261021.py` exercises real in-process localhost HTTP hostile entities and confirms no forged terminal admission. Related protocol/cancellation suites returned **83 passed**; subsequent combined focused API+MCP suites **108 passed**. This is provider-boundary hardening, not target-effect authentication.
- **Configured fleet truth:** Safe scoped run over seven MCP qualification/inventory/readiness/local-loopback/API test modules returned **112 passed, 4 warnings**, with no consequential target operations. Fixed a stale inventory test expecting SourceMap `localhost` to recognize security-pinned numeric `127.0.0.1`, preserving the actual bearer transport restriction. Six native Go servers still expose inert builtins only; Burp external endpoint is unavailable; Cloud/Turbo remain disabled HTTP 503; Browser independently owner-authenticated effects remain absent; SourceMap still DENIES native consequential execution without genuine current 0033 signed PID/nonroot readonly mount witness, 0029 authorized grant, and 0030 original reviewed byte offer. An isolated local HTTP response never counts as target-owner testimony.
- **Open PentAGI v2.2.0/release gaps:** User-owned library now has real CRUD, but verified unified answer synthesis/owner-controlled resource synchronization, production vault and provider credential rotation/budget trust, multi-replica durable subscriptions/recovery, separately signed current SourceMap supervisor, real all-11 owner effects, and independently authenticated senior final release approval remain unqualified. Historical upstream `main` reference is the 2026-10-16 sample, not a fresh `main` comparison. Six attempted browser worker spawns failed before execution; none was credited with work. Current release remains denied.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**

#### 0039 two-client concurrency correction

A subsequent **actual independent PostgreSQL16** opt-in `0039` qualification added simultaneous async psycopg client sessions racing the same user-owned immutable revision. The initial test exposed a READ COMMITTED joined `SELECT ... FOR UPDATE` stale-join snapshot: the losing CAS writer could receive spurious 404 instead of 409. Production `OperatorGlobalLibrary._current()` now first locks the exact owner document row, then reads its SHA-checked pinned version in that transaction. Separate-client competing CAS confirmed exactly one winner and an explicit stale-revision 409 loser; cross-owner read/delete and permanent tombstones remain denied. Final isolated PG run: **2 passed in 30.93s**; follow-up API/matrix and black checks: **35 passed**, clean formatting. This is genuine private PostgreSQL contention, not independently verified target effects or multi-replica distributed runtime approval.

#### 2026-10-21 verified partial UI, current authority and durable supervision changes

- **User-owned KB + operator screen:** Actual mounted `0039` CRUD and metadata search remains strictly user-owned, and `ui/src/pages/UserLibrary.tsx` now mounts `OperatorGlobalLibraryPanel`. The new mounted `/operator/search/knowledge` joins two independently authorization-fenced source *result sets* (`0039` user-global and `0019/0038` Flow-local) with source labels, revision/SHA metadata, no content excerpt, no semantic synthesis, no RAG ingestion and no cross-source atomic snapshot. TypeScript typecheck and five operator UI tests pass. This is meaningful but partial PentAGI Knowledge/Resources/Search parity, not agent-safe KB retrieval/synthesis.
- **Durable notifications:** Additive sole-head `0040` migration and worker42 transactional lease/cursor/revoke store support named subscriber state across independent PostgreSQL sessions; real disposable PostgreSQL16 constraints and two-connection CAS race passed 2 tests. Main mounts a new six-operation signed `durable_supervision_subscriptions` API. Its per-Task admission now requires exact Task `_authorization_sha256` in addition to version, and duplicate JSON keys are rejected. Full ASGI in-process qualification and actual PG schema tests are distinct evidence; live cross-replica SSE handoff, revocation race with independent writer, OIDC and production recovery are unqualified. Existing ordinary SSE and at-least-once semantics are not claimed as exactly-once delivery.
- **Provider rotation parity remains blocked:** Symbolic `0028` profile references/rotation exist, but source-backed runtime qualification confirmed that independently signed host-vault material and revocation evidence are *not wired into LiteLLM dispatch*. An unverified reference cannot activate a verified credential, and the standalone verifier is advisory only. No external vault or provider transaction was performed.
- **MCP/release parity remains bounded:** Browser current independently signed central readback is a 5-second read-only proof with fake-PG ASGI qualification; provider-original bytes are distinct. Source Map requires genuine separately enrolled `0033` PID/process/mount and original Source Map resources; missing evidence DENIES. Actual isolated `payload-mcp` Go process denial on localhost passed, not consequential scanner readiness. Production release still requires independent target-owner proofs, multi-replica deployment and separately authenticated senior approval. Historical upstream `main` was sampled on 2026-10-16, not reverified here.

#### Actual mounted unified search with real isolated PostgreSQL16 (final follow-on)

Worker36 completed a materially stronger, **opt-in genuine PostgreSQL16 + real mounted FastAPI** qualification: `tests/qualification/test_unified_knowledge_mounted_pg_integration_20261021.py` returned **2 passed in 30.64s**. An independently initialized nonroot WSL PostgreSQL16 accepted Unix sockets only (no TCP or application database); a constrained parameterized stdio SQL bridge let Windows `ai_osop.api.main.app` execute the actual `OperatorGlobalLibrary.search`, `OperatorKnowledgeStore.search`, Flow resource fencing, signed `guard_sql` and JWT checks against the same disposable SQL state. Real Alembic `0009`, `0014`, `0019`, `0038`, `0039` upgrades ran against minimal parent tables. The fixture minted ephemeral test Ed25519 signed ROE/JWT; no production keys or external targets were used.

Positive verified scope: exact current global+Flow original-revision SHA metadata, no content bodies; global-only operation. Negative verified scope: cross-owner Flow 403 without misleading partial success; stale Flow revision 409, wrong authorization version 403, forged JWT 401, unenrolled ROE trust root 403, current ROE revoke 403 while independently owned global search remains 200, current token revoke 401, subject disable 401/re-enable 200, actual 0038 wrong-SHA SQLSTATE 23514 and tenant FK SQLSTATE 23503, immutable 0039 revision and permanent tombstone. Cross-source atomicity, agent-context permission and independent target effects remained false. Combined default test returned 15 passed and 2 opt-in skipped; Black/Ruff/compile passed.

One initial opt-in run failed only because the test seed committed global document and version 1 separately despite `0039`'s correct deferred current-version FK; the fixture was fixed to create both within one transaction and the follow-up genuine opt-in test passed. LIMITS: minimal parent schema and test signers, custom Windows↔WSL SQL adapter instead of production async SQLAlchemy deployment, no application lifespan/live replica cluster, no production identity provider, no external owner effect, no signed senior release. **No claim of production certification follows.**

#### 2026-10-21 verified incremental `0040` durable supervision and operator UI parity (not production parity)

- **Materially implemented:** The originally mounted six authenticated `0040` subscription API operations now have a newly mounted human-facing named subscriber panel inside Supervision. Manual current-PG lease, committed event read, explicit single-event ACK CAS, renewal, release, and permanent revocation are wired through a new signed bearer client with original HTTP byte bound, identity invalidation, no tokens in URLs, no automatic replay. Seven new UI tests, TypeScript typecheck and Vite production build passed. Ordinary SSE polling remains distinct; the panel does not imply GraphQL live subscription parity, exactly-once delivery, target effects, or a deployed replica cluster.
- **Stronger persistence/integration proof:** Distinct real opt-in PostgreSQL16 qualifications exercised actual mounted FastAPI+real 0014/0040 SQL signed Task/ROE check (4 passed) and unmodified store SQL via separately connected real PostgreSQL client sessions, race/producer locks/rollback/lease fencing (2 passed). Original `0040` DDL qualification from the previous continuation still stands. These use separately initialized Unix-socket-only nonroot ephemeral PG, minimal parent schema and test-signed principals; not full application schema/lifespan, real OIDC or multi-host production deployment.
- **Revocation safety correction:** Bound real PostgreSQL READ COMMITTED plus transaction-end SHARE NOWAIT lock on 0014 token/subject tables closes the missing-row FOR SHARE phantom insert window through subscription transaction commit; missing DB binding now DENIES. Actual two-session PG lock conflicts and post-update rollback have been qualified; revocation after commit and later SSE publication is not atomically covered. The table-wide lock is a deliberate availability/contestion tradeoff.
- **Other PentAGI v2.2.0 gaps remained:** No separately reviewed user-global KB note-to-agent RAG/vector synthesis, no real protected provider vault material/version binding at LiteLLM pre-send, no independently enrolled Browser target-owner effects, genuine Source Map signed worker nonroot mount witness, all-11 live provider effects or separately signed current senior release ledger. New fail-closed standalone provider dispatch and report custody tests are not production-mounted parity. The upstream `main` reference remains a **historically sampled 2026-10-16 snapshot** and is not claimed freshly verified.

#### 2026-10-21 now-reachable provider reference administration and original library readback

The existing Administration React route now actually mounts `ProviderCredentialAdministrationPanel` with a bearer-bound, signed Flow/revision/ROE readback, nonsecret current provider-profile/reference listing, exact expected-revision CAS rotation **intent**, and signed senior approval/revocation of symbolic metadata. Eleven focused admin tests passed; combined frontend suites **23 passed**, TypeScript check and Vite production build passed. This is **material partial operator configuration/management UI parity**, but is **not** PentAGI's live credential create/rotate/test: no secret bytes or provider call, no independent current vault version observed. The actual `LiteLLMClient` pre-send now includes a strict host-only opt-in eleven-root guard; source inspection shows production `api/main.py` still constructs it with the default unguarded mode, and no enrolled signed host vault/key-to-runtime/ledger factory. Guard tests qualify rejection only; no real provider or paid request was sent.

The mounted `0039` global user library mutation UI now independently GETs and SHA-checks committed original content/revision/title/kind after a create/update, refuses ambiguous/lost readbacks without retry, and its registered POST/PUT/DELETE pre-Pydantic route caps original wire JSON at 65,536 bytes and rejects duplicate/nonfinite/invalid input. Focused **18 Python API passes** plus **12 two-library UI passes** confirm reachable scoped behavior; mocked store/test HTTP responses are not real PostgreSQL in these *new* cases. This improves actual operator resource CRUD custody, **not** separately reviewed agent RAG or target-effect verification. See `docs/USER_GLOBAL_ORIGINAL_WRITE_READBACK_20261021.md`. The earlier user-global/Flow original private PG qualifications remain valid distinct evidence. Source-only Cloud capability is now optional operator-gated local Terraform/Checkov static IaC rather than a perpetual no-op; configured Checkov execution and any live cloud account/IAM effect are not qualified. Turbo Intruder stays disabled.

#### 2026-10-21 independently exercised late MCP enrollment and durable ACK-cursor readback

- **Material partial MCP operator parity:** One strict senior-only mounted `POST /system/mcp/{server_id}/reconcile-local` now negotiates health + manifests against an application-configured numeric-loopback service started after API bootstrap, preserving original `MCPConnection` request IDs and disallowing duplicate registry-ID replacement, in-flight Action reconnect, and UNKNOWN replay. The existing 11-entry Administration UI mounts the separate explicit action. Authentic disposable localhost HTTP+mounted signed *test* JWT and frontend build qualified this production callpath. This does not authorize or execute tools, nor prove any independently signed target effect or live provider fleet.
- **Material partial PentAGI subscription-recovery parity:** The actual 0040 signed owner/Task/ROE/PG lease check now supports a nonmutating committed cursor readback via mounted POST after an ambiguous ACK. The Flow human subscriber UI exposes it separately, never silently retries an ACK. Fresh disposable nonroot WSL PostgreSQL16 with genuine 0009/0014/0040 migrations + original store SQL, mounted FastAPI, synthetic Ed25519 ROE signed-policy keys confirmed persisted cursor after discarded ACK and revocation/foreign lease denial; latest post-final-revocation check passed 1/1. Node UI 8/8 and TypeScript/Vite build passed. Unlike PentAGI v2.2.0's per-user/Flow GraphQL event subscriptions, AI-OSOP still has REST/SSE, partial batch/event coverage, no deployed multi-host replica or client-visible exactly-once proof.
- **Limit of source/reference comparison:** existing pinned PentAGI v2.2.0 source links/inventory remain the reference; `main` sample dated October 16, 2026 is historical. Standalone Go inert supervisor + local Cloud Checkov authentication do not establish PentAGI scanner/agent execution parity. Independently enrolled Browser custody, original reviewed global-to-Flow knowledge import, dynamic provider host vault roots and separately signed senior release remain unavailable; fail-closed is correct, not a completed feature claim.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**

## 2026-10-22 mounted original operator, Cloud, and durable subscription parity delta

- **0039 independently user-owned knowledge to Flow:** signed owner-specific global library, Flow-local resources and exact SHA/revision metadata now have a real mounted reviewed-library preflight and operator Flow panel. An additional current signed ROE status request can populate version/policy digest for the selected engagement. However independently enrolled separate principal/reviewer/Flow/Task roots and a single-PG atomic reviewed import writer are absent, so PENDING source citation is the only safe output, not trusted agent content or equivalent PentAGI knowledge ingestion.
- **0040 real committed cursor and replica read semantics:** beyond the previously qualified non-mutating cursor readback after lost ACK, actual store `read_batch` now rejects a stale lease cursor after another committed ACK instead of projecting later events under an older cursor. Mounted `/read` and `/cursor-readback` revalidate the exact lease, signed current ROE and cursor before publication, and observe a final ASGI disconnect. A genuine nonroot disposable PostgreSQL16 test passed, but no actual physical multi-host deployment or atomic HTTP client ACK is established. Thus this is material REST/SSE correctness progress, not full PentAGI GraphQL subscription parity.
- **Configured Cloud local original-byte static IaC:** an operator-pinned Checkov static-only path uses private exact-byte Terraform staging with rechecked immutable digests, bounded subprocess and no cloud-account mutation. Worker genuine localhost MCPRegistry and local installed Checkov 3.3.30 tests confirmed discovery while unsigned Task/ROE execution failed closed; five Cloud modules returned 32 passes and one Windows privileged-symlink skip. This is not PentAGI live provider/cloud worker or target-effect parity.
- **Mounted 11-MCP transport and original host-custody diagnostics:** the existing Administration fleet card now distinguishes exact configured registry/HTTP/schema telemetry from signed Action and target effect evidence, and separately mounts inert six-Go process status, pending independent provider vault and Browser host original-byte custody readback. A senior SourceMap 0033 host-witness endpoint can only corroborate separately enrolled original-process/PID/nonroot readonly mount + one-use signed status and action chain; it defaults to 503 without real independent host roots. Combined source witness, eleven transport, native, ping and reconciliation backend tests passed 47, but all configured provider ports remained unobserved earlier in this continuation. These are guarded operator workflow and observability gains, not a real all-eleven execution fleet.

Pinned v2.2.0 source and the historical October 16 main sample remain the only upstream comparison references used here. No asserted whole-tree identity, independent target-owner effects, live provider credentials or senior signed release.

## 2026-10-22 material 0041/0042 user-global → Flow Knowledge/Resources parity delta

The earlier **2026-10-16 historical static** inventory entries and 2026-10-21
PENDING-only remarks above describe the code at those checkpoints. They must
not be used as current assertions that all reviewed Flow original storage is
missing. The source-level implementation now has these additional **partial**
features, qualified only within the bounds below:

- **0041:** Independently host-enrolled four-signature reviewed global source
  original + current Flow/Task/ROE PostgreSQL-lock admission can atomically
  record a durable, immutable 0039 source version/SHA/owner citation on the
  selected Flow. Mounted signed-owner recording and readback API and explicit
  operator choice. It never copies source into an agent prompt.
- **0042:** Separate deliberate operator choice can atomically INSERT the
  exact reviewed source original UTF-8 bytes into a permanent **inert**
  Flow-scoped resource row and the 0041 immutable citation in **one** actual
  PostgreSQL transaction. The SQL schema enforces original content SHA,
  source+Flow/tenant+owner composite FK, immutability and immutable false
  agent-context/effect-promotion flags. Mounted fresh signed-current original
  readback is separate and cannot replay a lost write. No agent or filesystem
  worker reads this new inert table by default.
- **Qualification:** Current joined 0039+0041+0042 signed-fixture backend tests
  **56 passed**; operator UI (existing preflight + 0041 metadata + 0042 exact
  original + independent readbacks) **12 passed**; TypeScript and Vite build
  (2,669 modules) passed. Actual opt-in fresh nonroot PostgreSQL16 private Unix
  socket online 0039→0041→0042 migration/joint commit/forced original digest
  failure rolling back metadata/immutability/tenant FK test **1 passed**.
  Another distinct real private 0041 schema qualification passed. Synthetic
  independently signed fixture public roots and minimal predecessor SQL do
  not certify deployed external signers or production app SQLAlchemy startup.
- **Parity grade:** Domain 7 user KB/review import and Domain 8 Flow resources
  have a **material new W/P/S counterpart** for *immutable, inert* original
  provenance/resource materialization—not full PentAGI knowledge CRUD/vector
  synthesis, independent reviewer service deployment, mutable user resource
  file system, trusted AI-agent ingestion, or worker mount parity. PentAGI
  `v2.2.0` remains pinned source; no fresh upstream-main sample was obtained.
  Complete eleven-provider process/target-effect/source custody/physical
  multireplica/senior release acceptance remains unmet.

### 2026-10-22 original disabled Python Turbo process-owner parity delta

- **Material local process-operation improvement, not PentAGI execution parity:** The selected original Python `turbo-intruder-mcp` service now has an opt-in host-reviewed fixed-source/venv/base Python SHA process supervisor, exact Windows parent/owned-child PID/socket observation, sanitizer for inherited cloud/provider/OSOP credentials, current process teardown/cancellation, and mounted senior-only start/status/stop lifecycle with read-only Administration frontend. Genuine private ephemeral loopback subprocess `/health` and `/mcp/execute` both deny 503, and the original `MCPRegistry` refuses registration; actual scanner/race execution remains disabled. This covers a narrow host lifecycle/readback gap relative to pinned PentAGI v2.2.0's supervised worker patterns, but does NOT match its live worker execution, target effects, provider authorization or current real eleven fleet startup. The implementation does not derive runtime identity from source declarations or permit client-installed roots.
- Existing pinned PentAGI v2.2.0 and historical sample evidence remain unchanged; no new upstream whole-tree claim. The independent host signer/approved external target effect, physical 0040 multi-replica and signed senior release gates remain unsatisfied.

### 2026-10-22 actual bounded 0040 leased SSE operator-workflow delta

- A distinct mounted 0040 signed-operator, lease-fenced bounded POST leased-stream publishes original committed supervision rows as SSE, with current signed owner/Task/ROE/revocation/PG lease checked again per frame. The Flow human reader can explicitly stream via a secure memory-only bearer; ACK and UNKNOWN committed-cursor readback remain separate manual paths. This is a narrow supervised operator live-update improvement relative to pinned PentAGI v2.2.0, not full feature parity or GraphQL subscription equivalence.
- Disposable nonroot PostgreSQL16 opt-in mounted signed test-fixture SSE: 1 passed. Default adverse backend: 6 passed. New UI stream parser: 4 passed; TypeScript/Vite build passed (2,672 modules). No physical client receipt, deployed independent trust roots, multi-replica/reverse proxy qualification, eleven authorized provider tool executions/target-owner effects, or signed senior release. No new comparison against moving PentAGI main.

### 2026-10-22 mounted Browser four-original and 0042 response-secrecy parity deltas

- Added main-mounted default-503 signed-senior Browser ORIGINAL host reader join with trusted-only one-shot enrollment: source host HTTP/PNG/DOM/HAR exact bytes, SHA/size, native signed three-file custody and repeated independent CURRENT owner/Flow/Task/ROE. Browser join 23 passed; joined Browser/SourceMap/11 roster 55 passed, 2 skipped. Narrow host-original reconciliation improvement, not independently enrolled production keys/WORM originals/target-owned effects or full pinned PentAGI v2.2.0 parity.
- Reviewed-library scoped Pydantic 422 error redaction prevents reflection of forbidden client original content. Mounted 0039->0041->0042 private nonroot PostgreSQL16 test 4 passed with separately controlled test-only Ed25519 roots and test signed ROE. Actual atomic immutable inert Flow original persisted without API echo; wrong owner/reviewer/ROE/Task denied, no prompt promotion. This narrows operator knowledge and original custody gaps, not actual production reviewed agent knowledge ingestion or full upstream equivalence.

### 2026-10-22 actual two-connection durable subscription and four-original operator UI parity

- A real nonroot disposable PG16 two-backend-PID qualification now supports bounded 0040 lease ownership, cursor CAS, revocation NOWAIT lock and disconnect rollback statements (2 opt-in passed), rather than in-memory-only simulations. A mounted bounded leased SSE API/Flow operator client now gates completion on a final non-ACK current lease marker and handles UNKNOWN ACK by separate readback; a genuine private PG opt-in verified stream/ACK/stale cursor/revoke, 1 passed. This narrows supervisory at-least-once event behavior compared with pinned PentAGI v2.2.0, not long-lived GraphQL, a two-machine deployment, independent physical client receipt or exactly-once delivery.
- Signed-senior Administration now also offers four-original Browser HTTP/PNG/DOM/HAR host digest readback with exact-metadata shape, no raw originals or signer key request, no scanner invoke and explicit NOT READY. Five focused Node tests passed; Browser combined 13 passed, Vite 2674 modules. Backend defaults to 503 until separately enrolled independently signed host originals/custody/current ROE. This is not verified autonomous browser execution nor signed target-owner effects; complete 11 MCP parity and production signoff remain open.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
