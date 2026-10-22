/** Explicit review-only bridge from the live MCP declaration catalog to a native Flow step. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const FLOW = /^flow-[A-Za-z0-9._-]{1,90}$/;
const OBJECTIVE = /^task-[A-Za-z0-9._:-]{1,85}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/;
const STEP = /^subtask-[A-Za-z0-9._-]{1,80}$/;
const FIELDS = [
  'status', 'flow_id', 'engagement_id', 'subtask_id', 'flow_revision', 'authorization_version',
  'execution_started', 'human_approval_still_required', 'runtime_health_verified',
  'target_effect_verified', 'safe_to_automatically_retry',
] as const;

export interface ProposedToolReview {
  status: 'proposal_recorded_pending_review';
  flow_id: string;
  engagement_id: string;
  subtask_id: string;
  flow_revision: number;
  authorization_version: number;
  execution_started: false;
  human_approval_still_required: true;
  runtime_health_verified: false;
  target_effect_verified: false;
  safe_to_automatically_retry: false;
}

const attemptedKeys = new Set<string>();

/** A lost acknowledgment may have committed a subtask: do not auto POST twice. */
export function priorToolProposalAttempt(key: string): boolean {
  return attemptedKeys.has(key);
}

export async function proposeDeclaredToolReview(input: {
  flowId: string;
  engagementId: string;
  objectiveTaskId: string;
  serverId: string;
  toolName: string;
  expectedFlowRevision: number;
  expectedAuthorizationVersion: number;
  explicitHumanConfirmation: boolean;
}): Promise<ProposedToolReview> {
  const operator = currentOperator();
  const { flowId, engagementId, objectiveTaskId, serverId, toolName,
    expectedFlowRevision, expectedAuthorizationVersion, explicitHumanConfirmation } = input;
  if (!operator || !operator.sub || !['operator', 'senior_operator'].includes(operator.role)
    || !FLOW.test(flowId) || !/^eng-[A-Za-z0-9._-]{1,60}$/.test(engagementId)
    || !OBJECTIVE.test(objectiveTaskId) || !NAME.test(serverId) || !NAME.test(toolName)
    || !Number.isSafeInteger(expectedFlowRevision) || expectedFlowRevision < 0
    || !Number.isSafeInteger(expectedAuthorizationVersion) || expectedAuthorizationVersion < 1
    || explicitHumanConfirmation !== true
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('An explicit current signed Flow and human-confirmed declaration are required.');
  }
  const headers = authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' });
  const bearer = headers.Authorization;
  if (typeof bearer !== 'string' || !/^Bearer \S+$/.test(bearer)) throw new Error('Signed operator bearer required.');
  const key = JSON.stringify([operator.sub, flowId, expectedFlowRevision, objectiveTaskId, serverId, toolName]);
  if (attemptedKeys.has(key)) throw new Error('This association was already attempted. Manually refresh the current Flow; never repeat POST after an UNKNOWN acknowledgment.');
  // Conservatively mark before the network call, including ambiguous errors.
  attemptedKeys.add(key);
  const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/tool-proposals`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      objective_task_id: objectiveTaskId,
      server_id: serverId,
      tool_name: toolName,
      expected_flow_revision: expectedFlowRevision,
      expected_authorization_version: expectedAuthorizationVersion,
      explicit_human_confirmation: true,
    }),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (response.status !== 201) throw new Error('Tool review proposal outcome UNKNOWN or rejected. Manually read current Flow; do not retry.');
  const raw: unknown = await response.json();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Proposal outcome UNKNOWN; manually refresh Flow.');
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).length !== FIELDS.length || FIELDS.some(name => !Object.prototype.hasOwnProperty.call(value, name))
    || value.status !== 'proposal_recorded_pending_review'
    || value.flow_id !== flowId || value.engagement_id !== engagementId
    || typeof value.subtask_id !== 'string' || !STEP.test(value.subtask_id)
    || value.flow_revision !== expectedFlowRevision + 1
    || value.authorization_version !== expectedAuthorizationVersion
    || value.execution_started !== false || value.human_approval_still_required !== true
    || value.runtime_health_verified !== false || value.target_effect_verified !== false
    || value.safe_to_automatically_retry !== false) {
    throw new Error('Proposal response malformed or unsafe; manually inspect Flow; do not retry.');
  }
  const current = currentOperator();
  if (!current || current.sub !== operator.sub || current.role !== operator.role
    || current.exp !== operator.exp || authHeaders().Authorization !== bearer) {
    throw new Error('Operator changed during ambiguous proposal; manually inspect Flow.');
  }
  const readResponse = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}`, {
    method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (readResponse.status !== 200)
    throw new Error('Signed Flow readback unavailable; proposal outcome UNKNOWN. Do not retry.');
  const readRaw: unknown = await readResponse.json();
  if (!readRaw || typeof readRaw !== 'object' || Array.isArray(readRaw))
    throw new Error('Signed Flow readback malformed; outcome UNKNOWN.');
  const readback = readRaw as {
    flow?: { id?: unknown; engagement_id?: unknown; revision?: unknown };
    subtasks?: unknown;
  };
  if (!readback.flow || !Array.isArray(readback.subtasks) || readback.subtasks.length > 100)
    throw new Error('Signed Flow readback incomplete; outcome UNKNOWN.');
  if (readback.flow.id !== flowId || readback.flow.engagement_id !== engagementId
    || readback.flow.revision !== expectedFlowRevision + 1
    || !readback.subtasks.some((raw: unknown) =>
      raw !== null && typeof raw === 'object' && !Array.isArray(raw)
      && (raw as Record<string, unknown>).id === value.subtask_id
      && (raw as Record<string, unknown>).flow_id === flowId
      && (raw as Record<string, unknown>).task_id === objectiveTaskId
      && (raw as Record<string, unknown>).status === 'pending'
      && (raw as Record<string, unknown>).task_type === 'operator_mcp_capability_review'
      && (raw as Record<string, unknown>).agent_type === 'human_oversight'
      && (raw as Record<string, unknown>).approval_required === true
    )) throw new Error('Durable proposal readback is missing/stale; outcome UNKNOWN. Do not retry.');
  const finalActor = currentOperator();
  if (!finalActor || finalActor.sub !== operator.sub || finalActor.role !== operator.role
    || authHeaders().Authorization !== bearer) throw new Error('Operator switched during readback; outcome UNKNOWN.');
  return {
    status: 'proposal_recorded_pending_review',
    flow_id: flowId, engagement_id: engagementId, subtask_id: value.subtask_id,
    flow_revision: expectedFlowRevision + 1, authorization_version: expectedAuthorizationVersion,
    execution_started: false, human_approval_still_required: true,
    runtime_health_verified: false, target_effect_verified: false,
    safe_to_automatically_retry: false,
  };
}
