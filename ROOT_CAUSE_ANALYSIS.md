# Root Cause Analysis

## Failure Category
- **Category**: A. Frontend state bug & G. Session persistence bug

## Description
The primary driver of the infinite WebSocket connection loop was that the frontend was attempting to open a WebSocket connection with the hardcoded fallback ID `current-session` when no engagement ID was stored or selected. The backend API correctly returned a `404 Not Found` (or closed the socket) since no session with that ID exists. 

## Code Path
1. `ui/src/components/shared/NetworkHealth.tsx` fetched `/engagements`.
2. If no engagements existed or the fetch failed, it fell back to:
   ```typescript
   const latestId = activeSessions.length > 0 ? activeSessions[0].session_id : "current-session";
   net.connect(latestId);
   ```
3. `NetworkService.connect` then attempted to open a WebSocket connection to `ws://127.0.0.1:8090/ws/engagements/current-session?token=dev-token`.
4. The backend WebSocket handler rejected it with a close code.
5. `NetworkService` immediately attempted reconnection with the same invalid ID, looping indefinitely.
