/** Typed flow and execution-diagnostics API.
 * All requests use the existing API origin and bearer authentication.
 */
import { API_BASE, authHeaders, currentOperator } from './api';

export interface Engagement {
  session_id: string;
  phase: string;
  scope: {
    authorization_ref?: string | null;
    domains?: string[];
    ips?: string[];
  };
}

export interface FlowRecord {
  id: string;
  engagement_id: string;
  objective: string;
  status: string;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface FlowObjective {
  id: string;
  type: string;
  status: string;
  flow_id?: string | null;
  engagement_id: string;
  payload: { title?: string };
  created_at: string;
}

export interface FlowSubtask {
  id: string;
  flow_id: string;
  task_id: string;
  title: string;
  description: string;
  task_type: string;
  agent_type: string;
  approval_required: boolean;
  order: number;
  dependencies: string[];
  status: string;
  refinement_count: number;
  execution_task_id?: string | null;
  created_at: string;
  updated_at: string;
}

/** Result of a bounded plan proposal; the API never dispatches these steps. */
export interface FlowProposalResult {
  status: 'proposed' | 'unchanged' | 'blocked' | 'ignored' | 'conflict' | 'limit_reached' | 'awaiting_planner_approval';
  reason?: string;
  provenance?: 'llm' | 'deterministic' | 'budget';
  flow_id?: string;
  revision?: number;
  steps_total?: number;
  added_subtask_ids?: string[];
  refinement_count?: number;
  approval_id?: string;
  task_id?: string;
  flow_revision?: number;
}

/** Planning lifecycle only: pause/cancel do not terminate active execution. */
export interface FlowPlanningControlResult {
  flow_id: string;
  status: string;
  execution_stopped?: boolean;
}

export interface PendingFlowApproval {
  id: string;
  task_id: string;
  engagement_id: string;
  agent_id: string;
  action_type: string;
  target: string;
  risk_assessment: string;
  status: string;
  requested_at: string;
  operator_id?: string | null;
  operator_notes?: string | null;
  // Server-authoritative, signed/Flow-fenced internal planner review context.
  flow_id?: string | null;
  flow_revision?: number | null;
  authorization_version?: number | null;
  // Safe persisted lineage for explicit resume after approval; never a token.
  flow_revision_current?: boolean;
  planner_purpose?: 'flow_generation' | 'flow_refinement' | 'adaptive_planning';
  parent_task_id?: string;
  source_subtask_id?: string | null;
}

export interface ApprovalResolution {
  id: string;
  task_id: string;
  engagement_id: string;
  status: string;
  operator_id?: string | null;
  responded_at?: string | null;
}

/** A single, settled *proposal*. No agent task was scheduled. */
export interface AdaptivePlannerProposal {
  status: 'proposal_ready';
  approval_id: string;
  /** Read from durable current signer, not a client attestation. */
  authorization_version?: number;
  flow_id: string;
  flow_revision: number;
  planner_task_id: string;
  review_required: true;
  execution_started: false;
  proposal: {
    action: 'stop' | 'create_hypothesis' | 'request_sub_recon' | 'blocked';
    parameters: { statement?: string; target?: string };
    reason?: string;
    provenance?: string;
  };
}

/** Atomic Flow plan admission. No external agent/target execution was started. */
export interface AdaptiveFollowupAdmission {
  status: 'pending_dispatch_review';
  flow_id: string;
  flow_revision: number;
  objective_task_id: string;
  subtask_id: string;
  approval_required: true;
  execution_started: false;
  dispatch_required: true;
  target: string;
}

export interface FlowDetail {
  flow: FlowRecord;
  subtasks: FlowSubtask[];
  /** The backend includes persisted objective tasks in recent versions. */
  tasks?: FlowObjective[];
}

export interface FlowAction {
  id: string;
  engagement_id: string;
  flow_id?: string | null;
  task_id?: string | null;
  subtask_id?: string | null;
  tool_name: string;
  outcome: string;
  duration_ms?: number | null;
  created_at: string;
  safe_metadata: Record<string, string | number | boolean | null>;
}

/** Verified tenant+TaskORM Flow attribution, NOT independently verified billing. */
export interface FlowModelAnalytics {
  engagement_id: string;
  flow_id: string;
  source: 'postgresql_task_attributed_model_ledger';
  attribution: 'same_tenant_task_flow_join_only';
  unattributed_model_calls_included: false;
  groups: {
    model: string;
    operation: 'completion' | 'embedding';
    agent_type: string;
    calls: number;
    settled_calls: number;
    unknown_outcome_calls: number;
    unpriced_calls: number;
    input_tokens: number | null;
    output_tokens: number | null;
    known_ledger_cost_usd: string;
    total_cost_complete: boolean;
  }[];
  group_count: number;
  calls: number;
  unknown_outcome_calls: number;
  unpriced_calls: number;
  complete_for_attributed_calls: true;
  provider_native_cost_verified: false;
  provider_native_hard_cap_verified: false;
  external_execution_outcome_verified: false;
}

export interface TaskDiagnostic {
  task_id: string;
  task_type: string;
  agent_type: string;
  assigned_agent_id?: string | null;
  status: string;
  retry_count: number;
  max_retries: number;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  running_seconds?: number | null;
  overdue: boolean;
}

export interface AuditDiagnostic {
  event_id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  actor_type: string;
  actor_id: string;
  task_id?: string | null;
  integrity_hash?: string | null;
}

export interface EngagementDiagnostics {
  engagement_id: string;
  phase: string;
  captured_at: string;
  tasks: {
    source: string;
    total: number;
    status_counts: Record<string, number>;
    retried: number;
    overdue_running: number;
    items: TaskDiagnostic[];
    truncated: boolean;
  };
  audit: {
    source: string;
    available: boolean;
    limit: number;
    events_returned: number;
    events: AuditDiagnostic[];
  };
}

function apiPath(value: string): string {
  return encodeURIComponent(value);
}

function messageFromDetail(detail: unknown): string | null {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((entry) => typeof entry?.msg === 'string' ? entry.msg : null)
      .filter(Boolean)
      .join('; ') || null;
  }
  if (detail && typeof detail === 'object') {
    const object = detail as { message?: unknown; status?: unknown };
    if (typeof object.message === 'string') return object.message;
    if (typeof object.status === 'string') return object.status;
  }
  return null;
}

export class FlowApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'FlowApiError';
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: authHeaders(init.body ? { 'Content-Type': 'application/json' } : {}),
  });

  const contentType = response.headers.get('content-type') || '';
  const payload: unknown = contentType.includes('application/json')
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const detail = (payload && typeof payload === 'object' && 'detail' in payload)
      ? (payload as { detail: unknown }).detail
      : payload;
    throw new FlowApiError(response.status, messageFromDetail(detail) || `Request failed (HTTP ${response.status})`);
  }
  return payload as T;
}

export const flowApi = {
  listEngagements: () => request<Engagement[]>('/engagements'),
  listFlows: (engagementId: string) =>
    request<FlowRecord[]>(`/flows?engagement_id=${apiPath(engagementId)}`),
  getFlow: (flowId: string) => request<FlowDetail>(`/flows/${apiPath(flowId)}`),
  getModelAnalytics: (flowId: string) =>
    request<FlowModelAnalytics>(`/flows/${apiPath(flowId)}/model-analytics`, {
      method: 'GET', cache: 'no-store', credentials: 'omit',
      redirect: 'error', referrerPolicy: 'no-referrer',
    }),
  pauseFlow: (flowId: string, expectedRevision: number) =>
    request<FlowPlanningControlResult>(`/flows/${apiPath(flowId)}/pause`, {
      method: 'POST',
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  resumeFlow: (flowId: string, expectedRevision: number) =>
    request<FlowPlanningControlResult>(`/flows/${apiPath(flowId)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  cancelFlow: (flowId: string, expectedRevision: number) =>
    request<FlowPlanningControlResult>(`/flows/${apiPath(flowId)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  createFlow: (engagementId: string, objective: string) =>
    request<FlowRecord>('/flows', {
      method: 'POST',
      body: JSON.stringify({ engagement_id: engagementId, objective }),
    }),
  createObjective: (flowId: string, title: string) =>
    request<FlowObjective>(`/flows/${apiPath(flowId)}/tasks`, {
      method: 'POST',
      body: JSON.stringify({ title }),
    }),
  generateProposals: (flowId: string, taskId: string) =>
    request<FlowProposalResult>(
      `/flows/${apiPath(flowId)}/tasks/${apiPath(taskId)}/generate`,
      { method: 'POST' },
    ),
  refineProposals: (flowId: string, subtaskId: string) =>
    request<FlowProposalResult>(
      `/flows/${apiPath(flowId)}/subtasks/${apiPath(subtaskId)}/refine`,
      { method: 'POST' },
    ),
  createSubtask: (
    flowId: string,
    input: {
      task_id: string;
      title: string;
      description: string;
      task_type: string;
      agent_type: string;
      approval_required: boolean;
      dependencies: string[];
    },
  ) => request<FlowSubtask>(`/flows/${apiPath(flowId)}/subtasks`, {
    method: 'POST',
    body: JSON.stringify(input),
  }),
  reviseSubtask: (
    flowId: string,
    subtaskId: string,
    input: { title: string; description: string; expected_revision: number },
  ) => request<FlowSubtask>(`/flows/${apiPath(flowId)}/subtasks/${apiPath(subtaskId)}`, {
    method: 'PATCH',
    body: JSON.stringify(input),
  }),
  dispatchSubtask: (
    flowId: string,
    subtaskId: string,
    input: { payload: { target?: string }; priority: number },
  ) => request<{ subtask_id: string; task_id: string; status: string }>(
    `/flows/${apiPath(flowId)}/subtasks/${apiPath(subtaskId)}/dispatch`,
    { method: 'POST', body: JSON.stringify(input) },
  ),
  listPendingApprovals: () =>
    request<PendingFlowApproval[]>('/approvals/pending'),
  listApprovedPlannerApprovals: (engagementId: string) =>
    request<PendingFlowApproval[]>(`/approvals/planner-ready?engagement_id=${apiPath(engagementId)}`),
  continueApprovedAdaptivePlanner: (
    approvalId: string,
    expectedAuthorizationVersion: number,
    expectedFlowRevision: number,
  ) => request<AdaptivePlannerProposal>(
    `/approvals/${apiPath(approvalId)}/adaptive/continue`, {
      method: 'POST',
      body: JSON.stringify({
        request_id: approvalId,
        expected_authorization_version: expectedAuthorizationVersion,
        expected_flow_revision: expectedFlowRevision,
      }),
    },
  ),
  listAdaptivePlannerProposals: (engagementId: string) =>
    request<AdaptivePlannerProposal[]>(
      `/approvals/adaptive/proposals?engagement_id=${apiPath(engagementId)}`,
    ),
  getAdaptivePlannerProposal: (approvalId: string) =>
    request<AdaptivePlannerProposal>(`/approvals/${apiPath(approvalId)}/adaptive/proposal`),
  prepareConfirmedAdaptiveFollowup: (
    approvalId: string,
    expectedAuthorizationVersion: number,
    expectedFlowRevision: number,
    confirmedTarget: string,
  ) => request<AdaptiveFollowupAdmission>(
    `/approvals/${apiPath(approvalId)}/adaptive/prepare-followup`, {
      method: 'POST',
      body: JSON.stringify({
        request_id: approvalId,
        expected_authorization_version: expectedAuthorizationVersion,
        expected_flow_revision: expectedFlowRevision,
        confirmed_target: confirmedTarget,
        confirm_execution: true,
      }),
    },
  ),
  resolveApproval: (
    approvalId: string,
    decision: 'approved' | 'rejected',
    notes: string,
    plannerRevision?: {
      expected_authorization_version: number;
      expected_flow_revision: number;
    },
  ) => request<ApprovalResolution>(`/approvals/${apiPath(approvalId)}/resolve`, {
    method: 'POST',
    body: JSON.stringify({ request_id: approvalId, decision, notes, ...plannerRevision }),
  }),
  haltEngagement: (engagementId: string, reason: string) =>
    request<{ status: string; session_id: string; reason: string }>(
      `/engagements/${apiPath(engagementId)}/halt?${new URLSearchParams({ reason }).toString()}`,
      { method: 'POST' },
    ),
  listActions: (flowId: string) =>
    request<{ flow_id: string; actions: FlowAction[] }>(`/flows/${apiPath(flowId)}/actions?limit=100`),
  getDiagnostics: (engagementId: string) =>
    request<EngagementDiagnostics>(`/engagements/${apiPath(engagementId)}/diagnostics?limit=50`),
  getTask: (taskId: string) => request<FlowObjective>(`/tasks/${apiPath(taskId)}`),
  haltFlow: (flowId: string) =>
    request<{ flow_id: string; status: string; engagement_halted: boolean }>(
      `/flows/${apiPath(flowId)}/halt`, { method: 'POST' },
    ),
};

/** Display-only hint from the server-verified /auth/me identity. */
export function operatorRoleHint(): string | null {
  return currentOperator()?.role ?? null;
}
