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
    try {
      // 1. Session Info
      const sessionRes = await fetch(`${API_BASE}/engagements/${sessionId}`, { headers });
      if (sessionRes.ok) {
         const sessionData = await sessionRes.json();
         useSwarmStore.getState().setPhase(sessionData.phase || 'INITIALIZING');
         useSwarmStore.getState().setObjective(sessionData.scope?.domains?.[0] || 'ACTIVE MISSION');
      }

      // 2. Agents
      const agentsRes = await fetch(`${API_BASE}/agents`, { headers });
      if (agentsRes.ok) useSwarmStore.getState().setAgents(await agentsRes.json());

      // 3. Findings
      const findingsRes = await fetch(`${API_BASE}/engagements/${sessionId}/findings`, { headers });
      if (findingsRes.ok) useIntelligenceStore.getState().setFindings(await findingsRes.json());
      
      // 4. Skill Stats
      const skillsRes = await fetch(`${API_BASE}/system/skills/stats`, { headers });
      if (skillsRes.ok) useIntelligenceStore.getState().setSkillStats(await skillsRes.json());

      // 5. Audit Log
      const auditRes = await fetch(`${API_BASE}/engagements/${sessionId}/audit-log`, { headers });
      if (auditRes.ok) useIntelligenceStore.getState().setAuditLog(await auditRes.json());

      // 6. Diff Auth
      const diffRes = await fetch(`${API_BASE}/engagements/${sessionId}/diff-auth`, { headers });
      if (diffRes.ok) useIntelligenceStore.getState().setDiffAuthFindings(await diffRes.json());

      // 7. Uncertainty
      const uncRes = await fetch(`${API_BASE}/engagements/${sessionId}/uncertainty`, { headers });
      if (uncRes.ok) useIntelligenceStore.getState().setUncertainties(await uncRes.json());

      // 8. Graph Data
      const graphRes = await fetch(`${API_BASE}/engagements/${sessionId}/graph`, { headers });
      if (graphRes.ok) useIntelligenceStore.getState().setGraphData(await graphRes.json());
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
      this.ws = new WebSocket(`${WS_BASE}/ws/engagements/${sessionId}?token=${AUTH_TOKEN}`);

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
      throughput: this.eventThroughput
    };
  }

  disconnect() {
    if (this.ws) this.ws.close();
    if (this.throughputTimer) clearInterval(this.throughputTimer);
  }
}
