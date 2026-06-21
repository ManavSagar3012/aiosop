/**
 * V5 Network Event Schemas
 * Strict TypeScript definitions for all backend-to-frontend messages.
 */

import { Finding, VerificationRequest, Uncertainty } from '../store/useIntelligenceStore';
import { Agent, SwarmBudget } from '../store/useSwarmStore';

export type EventType = 
  | 'agent_observation' 
  | 'budget_update' 
  | 'finding_update' 
  | 'mission_update' 
  | 'verification_update' 
  | 'learning_update'
  | 'heartbeat';

export interface BaseEvent {
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
  data: SwarmBudget;
}

export interface FindingUpdateEvent extends BaseEvent {
  event_type: 'finding_update';
  data: Finding;
}

export interface MissionUpdateEvent extends BaseEvent {
  event_type: 'mission_update';
  data: {
    status: string;
    phase: string;
    objective: string;
  };
}

export interface VerificationUpdateEvent extends BaseEvent {
  event_type: 'verification_update';
  data: VerificationRequest;
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
  | VerificationUpdateEvent 
  | LearningUpdateEvent
  | HeartbeatEvent;
