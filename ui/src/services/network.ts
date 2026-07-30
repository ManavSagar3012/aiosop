/**
 * V5 Network Service
 * Handles WebSocket lifecycle, API hydration, and event routing to Zustand.
 */

import { useSwarmStore } from '../store/useSwarmStore';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { SwarmEvent } from './types';
import { API_BASE, WS_BASE, AUTH_TOKEN, authHeaders } from './api';

export type ConnectionStatus = 'connected' | 'disconnected' | 'reconnecting' | 'error';

export class NetworkService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;
  private status: ConnectionStatus = 'disconnected';
  private onStatusChange: (status: ConnectionStatus) => void;
  private lastEventId: number = 0;
  private eventBuffer: SwarmEvent[] = [];
  private lastLatency = 0;
  private eventThroughput = 0;
  private eventCount = 0;
  private throughputTimer: ReturnType<typeof setInterval> | null = null;
  private lastEventAt: Date | null = null;

  constructor(onStatusChange: (status: ConnectionStatus) => void) {
    this.onStatusChange = onStatusChange;
    this.startThroughputMonitor();
  }

  /**
   * Initial Data Hydration from REST API
   */
  async hydrate(sessionId: string) {
    useIntelligenceStore.getState().setSessionId(sessionId);
    const headers = authHeaders();
    const intel = useIntelligenceStore.getState;

    // Helper: fetch one endpoint, return parsed JSON or null on failure
    const j = (path: string) =>
      fetch(`${API_BASE}${path}`, { headers })
        .then(r => (r.ok ? r.json() : null))
        .catch(() => null);

    try {
      const [
        session, agents, findings, skills, audit, diffs,
        unc, graph, trace, cog, critic, inv, payouts
      ] = await Promise.all([
        j(`/engagements/${sessionId}`),
        j(`/agents`),
        j(`/engagements/${sessionId}/findings`),
        j(`/system/skills/stats`),
        j(`/engagements/${sessionId}/audit-log`),
        j(`/engagements/${sessionId}/diff-auth`),
        j(`/engagements/${sessionId}/uncertainty`),
        j(`/engagements/${sessionId}/graph`),
        j(`/engagements/${sessionId}/reasoning-trace`),
        j(`/engagements/${sessionId}/cognition-summary`),
        j(`/engagements/${sessionId}/critic-review`),
        j(`/engagements/${sessionId}/invariants`),
        j(`/engagements/${sessionId}/payouts`),
      ]);

      const s = useSwarmStore.getState();
      const i = intel();

      if (session) {
        s.setPhase(session.phase || 'INITIALIZING');
        s.setObjective(session.scope?.domains?.[0] || 'ACTIVE MISSION');
      }
      if (agents) s.setAgents(agents);
      if (findings) i.setFindings(findings);
      if (skills) i.setSkillStats(skills);
      if (audit) i.setAuditLog(audit);
      if (diffs) i.setDiffAuthFindings(diffs);
      if (unc) i.setUncertainties(unc);
      if (graph) i.setGraphData(graph);
      if (trace) i.setReasoningTrace(trace.trace || []);
      if (cog) i.setCognitionSummary(cog);
      if (critic) i.setCriticReview(critic.critiques || []);
      if (inv) i.setInvariants(inv);
      if (payouts) i.setPayouts(payouts);

      this.lastEventAt = new Date();
    } catch (e) {
      console.error("[Network] Hydration failed", e);
    }
  }

  /**
   * Establish WebSocket Connection
   */
  connect(sessionId: string) {
    this.updateStatus('reconnecting');
    
    try {
      // Pass the bearer token via Sec-WebSocket-Protocol subprotocol (osop/token pair)
      // instead of a ?token= URL query param, which would leak into proxy logs and
      // browser history. Backend reads it from the subprotocol header.
      this.ws = new WebSocket(`${WS_BASE}/ws/engagements/${sessionId}`, [
        'osop',
        `bearer.${AUTH_TOKEN}`
      ]);

      this.ws.onopen = () => {
        this.updateStatus('connected');
        this.reconnectAttempts = 0;
        this.reconnectDelay = 1000;
      };

      this.ws.onmessage = (event) => {
        this.eventCount++;
        try {
          const data: SwarmEvent = JSON.parse(event.data);
          this.handleEvent(data);
        } catch (e) {
          console.error("[Network] Failed to parse event", e);
        }
      };

      this.ws.onclose = () => {
        this.updateStatus('disconnected');
        this.attemptReconnect(sessionId);
      };

      this.ws.onerror = () => {
        this.updateStatus('error');
      };

    } catch (e) {
      this.updateStatus('error');
      this.attemptReconnect(sessionId);
    }
  }

  private handleEvent(event: SwarmEvent) {
    this.lastEventId = event.id || this.lastEventId;
    this.eventBuffer.push(event);
    if (this.eventBuffer.length > 100) this.eventBuffer.shift();
    const swarm = useSwarmStore.getState();
    const intel = useIntelligenceStore.getState();
    // Track data freshness for the header "data as of" indicator
    if (event.event_type !== 'heartbeat') intel.setLastEventAt(new Date());

    // Append to audit log for live timeline (excluding heartbeats for noise reduction)
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
        intel.appendFinding(event.data as any);
        break;
      case 'mission_update':
        if (event.data.objective) swarm.setObjective(event.data.objective);
        if (event.data.phase) swarm.setPhase(event.data.phase);
        break;
      case 'phase_transition':
        swarm.setPhase(event.data.new_phase || event.data.phase);
        break;
      case 'graph_update':
        fetch(`${API_BASE}/engagements/${event.engagement_id}/graph`, {
            headers: authHeaders()
        })
        .then(res => res.json())
        .then(data => intel.setGraphData(data))
        .catch(e => console.error("Failed to sync graph on update", e));
        break;
      case 'agent_observation':
        break;
      case 'verification_update':
        intel.appendVerification(event.data as any);
        break;
      case 'learning_update':
        break;
      case 'heartbeat':
        this.lastLatency = (event as any).data?.latency_ms || 0;
        break;
    }
  }

  private attemptReconnect(sessionId: string) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error("[Network] Max reconnect attempts reached");
      return;
    }

    this.reconnectAttempts++;
    
    setTimeout(() => {
      this.reconnectDelay *= 2;
      this.connect(sessionId);
    }, this.reconnectDelay);
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
      throughput: this.eventThroughput,
      lastEventAt: this.lastEventAt,
    };
  }

  disconnect() {
    if (this.ws) this.ws.close();
    if (this.throughputTimer) clearInterval(this.throughputTimer);
  }
}
