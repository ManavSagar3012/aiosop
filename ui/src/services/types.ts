/**
 * V5 Network Event Schemas
 * Strict TypeScript definitions for all backend-to-frontend messages.
 */

export type EventType = 
  | 'agent_observation' 
  | 'budget_update' 
  | 'finding_update' 
  | 'mission_update' 
  | 'verification_update' 
  | 'learning_update'
  | 'phase_transition'
  | 'graph_update'
  | 'heartbeat';

export interface BaseEvent {
  id?: number
  event_type: EventType;
  timestamp: string;
  engagement_id: string;
}

export interface AgentObservationEvent extends BaseEvent {
  event_type: 'agent_observation';
  data: {
    id: string;
    type: string;
    source_agent_id: string;
    target_id: string;
    observation_data: Record<string, any>;
    confidence: number;
  };
}

export interface BudgetUpdateEvent extends BaseEvent {
  event_type: 'budget_update';
  data: {
    total: number;
    spent: number;
    system1Requests: number;
    system2Requests: number;
  };
}

export interface FindingUpdateEvent extends BaseEvent {
  event_type: 'finding_update';
  data: {
    id: string;
    title: string;
    category: string;
    severity: string;
    status: string;
    evScore: number;
    confidence: number;
  };
}

export interface MissionUpdateEvent extends BaseEvent {
  event_type: 'mission_update';
  data: {
    status: string;
    phase: string;
    objective: string;
    new_phase?: string;
  };
}

export interface PhaseTransitionEvent extends BaseEvent {
  event_type: 'phase_transition';
  data: {
    phase: string;
    new_phase: string;
  };
}

export interface GraphUpdateEvent extends BaseEvent {
  event_type: 'graph_update';
  data: Record<string, any>;
}

export interface VerificationUpdateEvent extends BaseEvent {
  event_type: 'verification_update';
  data: {
    id: string;
    findingId: string;
    title: string;
    evidenceSources: string[];
    agreedAgents: string[];
    requiredSources: number;
  };
}

export interface LearningUpdateEvent extends BaseEvent {
  event_type: 'learning_update';
  data: {
    accuracy: number;
    cost_per_finding: number;
    precision: number;
  };
}

export interface HeartbeatEvent extends BaseEvent {
  event_type: 'heartbeat';
  data: {
    latency_ms: number;
    server_uptime: number;
  };
}

export type SwarmEvent = 
  | AgentObservationEvent 
  | BudgetUpdateEvent 
  | FindingUpdateEvent 
  | MissionUpdateEvent 
  | PhaseTransitionEvent
  | GraphUpdateEvent
  | VerificationUpdateEvent 
  | LearningUpdateEvent
  | HeartbeatEvent;
