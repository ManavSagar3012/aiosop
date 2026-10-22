/**
 * V5 Network Service
 * Handles WebSocket lifecycle, API hydration, and event routing to Zustand.
 */

import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { SwarmEvent } from './types';
import { API_BASE, WS_BASE, authHeaders, getRuntimeToken, subscribeOperator } from './api';

export type ConnectionStatus = 'connected' | 'disconnected' | 'reconnecting' | 'error';

/** Never transmit a bearer over a plaintext WS to a non-loopback server. */
export function isSafeWebSocketBase(base: string): boolean {
  try {
    const url = new URL(base);
    if (url.username || url.password || url.search || url.hash) return false;
    return url.protocol === 'wss:' || (
      url.protocol === 'ws:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    );
  } catch {
    return false;
  }
}

export class NetworkService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000; // Start with 1s
  private status: ConnectionStatus = 'disconnected';
  private onStatusChange: (status: ConnectionStatus) => void;
  private eventCount = 0;
  private lastLatency = 0;
  private eventThroughput = 0;
  private throughputTimer: ReturnType<typeof setInterval> | null = null;
  private authTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private socketGeneration = 0;
  private authenticated = false;
  private intentionallyDisconnected = false;
  private unsubscribeAuth: (() => void) | null = null;

  constructor(onStatusChange: (status: ConnectionStatus) => void) {
    this.onStatusChange = onStatusChange;
    this.unsubscribeAuth = subscribeOperator((identity) => {
      if (!identity) this.disconnect();
    });
    this.startThroughputMonitor();
  }

  /**
   * Initial Data Hydration from REST API
   */
  async hydrate(sessionId: string) {
    const credential = getRuntimeToken();
    if (!credential || !/^[a-zA-Z0-9_-]{1,64}$/.test(sessionId)) return;
    const stillAuthorized = () => getRuntimeToken() === credential;
    useIntelligenceStore.getState().setSessionId(sessionId);
    const headers = authHeaders();
    try {
      // 1. Session Info
      const sessionRes = await fetch(`${API_BASE}/engagements/${sessionId}`, { headers });
      if (sessionRes.ok) {
         const sessionData = await sessionRes.json();
         if (!stillAuthorized()) return;
         useSwarmStore.getState().setPhase(sessionData.phase || 'INITIALIZING');
         useSwarmStore.getState().setObjective(sessionData.scope?.domains?.[0] || 'ACTIVE MISSION');
      }

      // 2. Agents
      const agentsRes = await fetch(`${API_BASE}/agents`, { headers });
      if (!stillAuthorized()) return;
      if (agentsRes.ok) {
        const agents = await agentsRes.json();
        if (!stillAuthorized()) return;
        useSwarmStore.getState().setAgents(agents);
      }

      // 3. Findings
      const findingsRes = await fetch(`${API_BASE}/engagements/${sessionId}/findings`, { headers });
      if (!stillAuthorized()) return;
      if (findingsRes.ok) {
        const findings = await findingsRes.json();
        if (!stillAuthorized()) return;
        useIntelligenceStore.getState().setFindings(findings);
      }
      
      // 4. Skill Stats
      const skillsRes = await fetch(`${API_BASE}/system/skills/stats`, { headers });
      if (!stillAuthorized()) return;
      if (skillsRes.ok) {
        const skills = await skillsRes.json();
        if (!stillAuthorized()) return;
        useIntelligenceStore.getState().setSkillStats(skills);
      }

      // 5. Audit Log
      const auditRes = await fetch(`${API_BASE}/engagements/${sessionId}/audit-log`, { headers });
      if (!stillAuthorized()) return;
      if (auditRes.ok) {
        const audit = await auditRes.json();
        if (!stillAuthorized()) return;
        useIntelligenceStore.getState().setAuditLog(audit);
      }

      // 6. Diff Auth
      const diffRes = await fetch(`${API_BASE}/engagements/${sessionId}/diff-auth`, { headers });
      if (!stillAuthorized()) return;
      if (diffRes.ok) {
        const findings = await diffRes.json();
        if (!stillAuthorized()) return;
        useIntelligenceStore.getState().setDiffAuthFindings(findings);
      }

      // 7. Uncertainty
      const uncRes = await fetch(`${API_BASE}/engagements/${sessionId}/uncertainty`, { headers });
      if (!stillAuthorized()) return;
      if (uncRes.ok) {
        const uncertainties = await uncRes.json();
        if (!stillAuthorized()) return;
        useIntelligenceStore.getState().setUncertainties(uncertainties);
      }

      // 8. Graph Data
      const graphRes = await fetch(`${API_BASE}/engagements/${sessionId}/graph`, { headers });
      if (!stillAuthorized()) return;
      if (graphRes.ok) {
        const graph = await graphRes.json();
        if (!stillAuthorized()) return;
        useIntelligenceStore.getState().setGraphData(graph);
      }
    } catch {
      // Do not log transport exceptions: some libraries echo credentials.
    }
  }

  /**
   * Establish WebSocket Connection
   */
  connect(sessionId: string) {
    if (!this.unsubscribeAuth) {
      this.unsubscribeAuth = subscribeOperator((identity) => {
        if (!identity) this.disconnect();
      });
    }
    // Fetch the current, server-verified bearer at every connection attempt.
    // It is intentionally never captured at module initialization.
    const credential = getRuntimeToken();
    if (
      !/^[a-zA-Z0-9_-]{1,64}$/.test(sessionId)
      || !credential || credential.length > 4096
      || !isSafeWebSocketBase(WS_BASE)
    ) {
      this.disconnect();
      this.updateStatus('error');
      return;
    }
    if (!this.throughputTimer) this.startThroughputMonitor();
    this.intentionallyDisconnected = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.authTimer) {
      clearTimeout(this.authTimer);
      this.authTimer = null;
    }
    this.authenticated = false;
    const generation = ++this.socketGeneration;
    const old = this.ws;
    this.ws = null;
    if (old && (old.readyState === WebSocket.OPEN || old.readyState === WebSocket.CONNECTING)) {
      old.close();
    }
    this.updateStatus('reconnecting');
    
    try {
      // Authentication is carried in a private first WS data frame, not the
      // URL, request logs, browser history, or Sec-WebSocket-Protocol header.
      const socket = new WebSocket(
        `${WS_BASE}/ws/engagements/${encodeURIComponent(sessionId)}`
      );
      this.ws = socket;

      socket.onopen = () => {
        if (generation !== this.socketGeneration || this.intentionallyDisconnected) return;
        if (!getRuntimeToken() || getRuntimeToken() !== credential) {
          socket.close(1008);
          return;
        }
        try {
          socket.send(JSON.stringify({ type: 'auth', token: credential }));
        } catch {
          this.updateStatus('error');
          socket.close(1008);
          return;
        }
        this.authTimer = setTimeout(() => {
          if (generation !== this.socketGeneration || this.authenticated) return;
          this.updateStatus('error');
          socket.close(1008);
        }, 5000);
      };

      socket.onmessage = (event) => {
        if (generation !== this.socketGeneration || this.intentionallyDisconnected) return;
        try {
          const data: unknown = JSON.parse(event.data);
          if (!data || typeof data !== 'object' || Array.isArray(data)) {
            socket.close(1008);
            return;
          }
          const frame = data as Record<string, unknown>;
          if (!this.authenticated) {
            if (frame.type !== 'auth_ready' || frame.session_id !== sessionId) {
              this.updateStatus('error');
              socket.close(1008);
              return;
            }
            this.authenticated = true;
            if (this.authTimer) clearTimeout(this.authTimer);
            this.authTimer = null;
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000;
            this.updateStatus('connected');
            return;
          }
          if (frame.type === 'auth_ready') return; // Duplicate ack is inert.
          if (typeof frame.event_type !== 'string' || frame.engagement_id !== sessionId) {
            // The service also carries pong/status control replies; neither
            // is an audit event or a source of fabricated state.
            if (frame.type === 'pong' || frame.type === 'status' || frame.type === 'halt_requested') return;
            socket.close(1008);
            return;
          }
          this.eventCount++;
          this.handleEvent(data as SwarmEvent);
        } catch {
          // Avoid logging potentially sensitive report/event frame content.
          this.updateStatus('error');
          socket.close(1008);
        }
      };

      socket.onclose = (event) => {
        if (generation !== this.socketGeneration) return;
        if (this.authTimer) clearTimeout(this.authTimer);
        this.authTimer = null;
        this.authenticated = false;
        this.ws = null;
        this.updateStatus('disconnected');
        // 1008/1009: policy violation/invalid authentication/oversized frame.
        // Retrying with the same credential indefinitely cannot fix this.
        if (!this.intentionallyDisconnected && event.code !== 1008 && event.code !== 1009) {
          this.attemptReconnect(sessionId);
        }
      };

      socket.onerror = () => {
        if (generation !== this.socketGeneration) return;
        this.updateStatus('error');
      };

    } catch {
      this.updateStatus('error');
      this.attemptReconnect(sessionId);
    }
  }

  /** Enqueue nothing until the server has acknowledged identity and ownership. */
  sendCommand(action: 'ping' | 'status' | 'halt', reason?: string): boolean {
    if (
      !this.authenticated || this.intentionallyDisconnected
      || !this.ws || this.ws.readyState !== WebSocket.OPEN
    ) return false;
    if (action === 'halt' && reason !== undefined &&
        (!reason || reason.length > 128 || /[\u0000-\u001f\u007f]/.test(reason))) {
      return false;
    }
    this.ws.send(JSON.stringify(
      action === 'halt' && reason !== undefined ? { action, reason } : { action }
    ));
    return true;
  }

  private handleEvent(event: SwarmEvent) {
    const swarm = useSwarmStore.getState();
    const intel = useIntelligenceStore.getState();

    // V5: Append everything to audit log for live timeline (excluding heartbeats for noise reduction)
    if (event.event_type !== 'heartbeat') {
       const normalizedEntry = {
          id: `ws-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          timestamp: event.timestamp || new Date().toISOString(),
          event_type: event.event_type,
          actor_id: (event as any).data?.source_agent_id || 'SWARM_ORCHESTRATOR',
          severity: (event as any).data?.severity || 'info',
          action: (event as any).data?.observation_data || (event as any).data?.details || event.data
       };
       intel.appendAuditEntry(normalizedEntry);
    }

    switch (event.event_type) {
      case 'budget_update':
        swarm.setBudget(event.data);
        break;
      case 'finding_update':
        intel.appendFinding(event.data);
        break;
      case 'mission_update':
        if (event.data.objective) swarm.setObjective(event.data.objective);
        if (event.data.phase) swarm.setPhase(event.data.phase);
        break;
      case 'phase_transition':
        swarm.setPhase(event.data.new_phase || event.data.phase);
        break;
      case 'graph_update':
        // Re-fetch graph data on update signal
        const credential = getRuntimeToken();
        if (!credential) break;
        fetch(`${API_BASE}/engagements/${event.engagement_id}/graph`, {
            headers: authHeaders()
        })
        .then(res => res.json())
        .then(data => {
          if (getRuntimeToken() === credential) intel.setGraphData(data);
        })
        .catch(() => {});
        break;
      case 'agent_observation':
        // Update specific stores based on observation type
        break;
      case 'heartbeat':
        this.lastLatency = event.data.latency_ms;
        break;
    }
  }

  private attemptReconnect(sessionId: string) {
    if (this.intentionallyDisconnected || this.reconnectTimer) return;
    if (!getRuntimeToken()) {
      this.disconnect();
      return;
    }
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.updateStatus('error');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay;
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000);
    this.updateStatus('reconnecting');
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.intentionallyDisconnected) return;
      this.connect(sessionId);
    }, delay);
  }

  private updateStatus(status: ConnectionStatus) {
    this.status = status;
    this.onStatusChange(status);
  }

  private startThroughputMonitor() {
    this.throughputTimer = setInterval(() => {
      this.eventThroughput = this.eventCount;
      this.eventCount = 0;
    }, 1000);
  }

  getMetrics() {
    return {
      status: this.status,
      latency: this.lastLatency,
      throughput: this.eventThroughput
    };
  }

  disconnect() {
    this.unsubscribeAuth?.();
    this.unsubscribeAuth = null;
    this.intentionallyDisconnected = true;
    this.authenticated = false;
    ++this.socketGeneration;
    if (this.authTimer) clearTimeout(this.authTimer);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.authTimer = null;
    this.reconnectTimer = null;
    const socket = this.ws;
    this.ws = null;
    if (socket && socket.readyState !== WebSocket.CLOSED) socket.close();
    if (this.throughputTimer) clearInterval(this.throughputTimer);
    this.throughputTimer = null;
    this.updateStatus('disconnected');
  }
}
