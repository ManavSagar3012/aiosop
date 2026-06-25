# Engagement Telemetry Lifecycle Map

1.  **Mission Creation (UI)**
    *   Trigger: `NewMissionModal.tsx` submits domain info.
    *   API call: `POST /engagements` (via `useSwarmStore` / `api.ts`).
    *   Backend Handler: `src/ai_osop/api/routers/engagements.py:create_engagement`.
    *   Orchestration: `EngagementManager.create_engagement` -> `SessionMemory` (Postgres/Redis).
    *   Response: Returns `SessionState` JSON (containing new `session_id`).

2.  **Frontend State Hydration**
    *   UI Update: `useSwarmStore` updates active mission with the returned `session_id`.
    *   Persistence: `useSwarmStore` persists active session to `localStorage` (implied/potential).

3.  **WebSocket Connection Initiation**
    *   Trigger: `NetworkHealth.tsx` detects active engagement ID (or defaults to `current-session`).
    *   Network Service: `NetworkService.connect(engagement_id)`.
    *   WS URL: `WS_BASE + "/ws/engagements/" + engagement_id + "?token=dev-token"`.

4.  **Backend Connection Validation**
    *   Handler: `src/ai_osop/api/main.py:websocket_engagement`.
    *   Auth: `verify_token(token)`.
    *   Authorization: `assert_engagement_access(operator, engagement_id)` checks `SessionMemory` for `session_id`.
    *   Result: `websocket.accept()` or `websocket.close(code=1008)`.

5.  **Telemetry Event Stream**
    *   Orchestrator: Emits events via `AgentCoordinationBus` / `SessionMemory` updates.
    *   WS Handler: Loops and streams events as JSON to frontend.
    *   UI Store: `useSwarmStore` / `useIntelligenceStore` consumes events and updates UI state.
