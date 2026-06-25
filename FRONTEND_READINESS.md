# FRONTEND READINESS

## 1. Client Configuration
- **Host / Port**: Vite dev server on port `5173`.
- **API Base**: Standardized to `http://127.0.0.1:8090` (configured in `ui/.env`).
- **WS Base**: Standardized to `ws://127.0.0.1:8090` (configured in `ui/.env`).
- **Auth Token**: Handled via `Bearer dev-token` matching backend `OSOP_API_TOKEN`.

## 2. Telemetry Integration
- **WebSocket State**:
  - Automatically resolves connection via `NetworkService.connect(session_id)`.
  - Removed `current-session` fallback to prevent loop fatigue.
  - Successfully streams `latency` and `throughput` values when an active mission is selected.
- **Mission Creation**:
  - Uses the `NewMissionModal` to request target domain information.
  - Returns the session state to the frontend which triggers a page reload and initiates active telemetry connection.
