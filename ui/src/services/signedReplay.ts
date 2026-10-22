/** Signed differential replay proposal. This endpoint stages a task for review;
 * it does not approve, navigate, validate a finding, or settle remote effects.
 */
import { API_BASE, authHeaders, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin } from './api';
import { flowApi, type Engagement, type FlowRecord } from './flows';
import { supervisionApi } from './supervision';

export interface WorkflowReplayInput {
  engagementId: string;
  workflowId: string;
  flowId: string;
  sourceTaskId: string;
  sourceUserLabel: string;
  targetUserLabel: string;
  expectedAuthorizationVersion: number;
  expectedFlowRevision: number;
}

export interface WorkflowReplayReceipt {
  status: 'awaiting_execution_approval';
  task_id: string;
  workflow_id: string;
  execution_started: false;
}

export interface WorkflowReplaySource {
  source_task_id: string;
  workflow_id: string;
  source_user_label: string;
}

export interface WorkflowReplaySourceCatalog {
  flow_id: string;
  flow_revision: number;
  authorization_version: number;
  sources: WorkflowReplaySource[];
  identities: string[];
}

export interface SignedReplayComparison {
  flow_id: string;
  replay_task_id: string;
  step_id: string;
  status: 'inconclusive' | 'expected_denial_observed' | 'candidate_needs_independent_review';
  reason: string;
  source_observed: boolean;
  target_observed: boolean;
  provider_testimony_only: true;
  source_authenticity_verified: false;
  target_effect_verified: false;
  authorization_violation_verified: false;
  findings_count: 0;
  comparison_sha256?: string;
}

interface PersistedMapTask {
  id?: unknown;
  type?: unknown;
  status?: unknown;
  flow_id?: unknown;
  engagement_id?: unknown;
  payload?: { user_label?: unknown; _authorization_version?: unknown; url?: unknown };
  result?: { workflow_id?: unknown; status?: unknown };
}

const ENGAGEMENT = /^eng-[A-Za-z0-9._-]{1,80}$/;
const WORKFLOW = /^wf-[A-Za-z0-9._-]{1,80}$/;
const FLOW = /^flow-[A-Za-z0-9._-]{1,80}$/;
const TASK = /^task-[A-Za-z0-9._-]{1,78}$/;
const IDENTITY = /^[A-Za-z0-9_.-]{1,64}$/;
const STEP = /^step-[A-Za-z0-9._-]{1,80}$/;

function bounded(value: unknown, pattern: RegExp, max: number): value is string {
  return typeof value === 'string' && value.length <= max && pattern.test(value);
}

function activeSenior(): boolean {
  return currentOperator()?.role === 'senior_operator'
    && Boolean(getRuntimeToken())
    && isSecureApiBase(API_BASE)
    && isSecureBrowserOrigin();
}

export function validateReplayInput(input: WorkflowReplayInput): string | null {
  if (!bounded(input.engagementId, ENGAGEMENT, 84)
      || !bounded(input.workflowId, WORKFLOW, 83)
      || !bounded(input.flowId, FLOW, 96)
      || !bounded(input.sourceTaskId, TASK, 96)) {
    return 'Explicit bounded engagement, workflow, Flow and original source task IDs are required.';
  }
  if (!bounded(input.sourceUserLabel, IDENTITY, 64)
      || !bounded(input.targetUserLabel, IDENTITY, 64)
      || ['anonymous', 'guest'].includes(input.sourceUserLabel)
      || ['anonymous', 'guest'].includes(input.targetUserLabel)
      || input.sourceUserLabel === input.targetUserLabel) {
    return 'Provide two distinct, named, bounded authenticated identities.';
  }
  if (!Number.isSafeInteger(input.expectedAuthorizationVersion)
      || input.expectedAuthorizationVersion < 1
      || !Number.isSafeInteger(input.expectedFlowRevision)
      || input.expectedFlowRevision < 0) {
    return 'Verified signed authorization version and current Flow revision are required.';
  }
  return null;
}

function assertActiveSenior(): void {
  if (!activeSenior()) {
    throw new Error('A currently verified senior_operator session is required.');
  }
}

/** Lists only PostgreSQL-qualified completed map sources and session labels.
 * Server is owner-scoped and senior-only. Catalog is verified again before POST.
 */
export async function loadWorkflowReplaySources(
  engagementId: string,
  flowId: string,
): Promise<WorkflowReplaySourceCatalog> {
  assertActiveSenior();
  if (!bounded(engagementId, ENGAGEMENT, 84) || !bounded(flowId, FLOW, 96)) {
    throw new Error('Explicit engagement and Flow identifiers are unavailable.');
  }
  const response = await fetch(
    `${API_BASE}/engagements/${encodeURIComponent(engagementId)}/workflows/replay-sources?flow_id=${encodeURIComponent(flowId)}`,
    {
      method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
      cache: 'no-store', credentials: 'omit',
      redirect: 'error', referrerPolicy: 'no-referrer',
    },
  );
  if (!response.ok) throw new Error(`Authoritative workflow source catalog unavailable (HTTP ${response.status}).`);
  const raw: unknown = await response.json();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Workflow source catalog is malformed.');
  }
  const value = raw as Partial<WorkflowReplaySourceCatalog>;
  if (value.flow_id !== flowId
      || !Number.isSafeInteger(value.flow_revision)
      || (value.flow_revision ?? -1) < 0
      || !Number.isSafeInteger(value.authorization_version)
      || (value.authorization_version ?? 0) < 1
      || !Array.isArray(value.sources) || value.sources.length > 100
      || !Array.isArray(value.identities) || value.identities.length > 100
      || !value.identities.every(label => bounded(label, IDENTITY, 64))
      || !value.sources.every(row => row
        && bounded(row.source_task_id, TASK, 96)
        && bounded(row.workflow_id, WORKFLOW, 83)
        && bounded(row.source_user_label, IDENTITY, 64))) {
    throw new Error('Workflow source catalog lacks bounded signed evidence.');
  }
  assertActiveSenior();
  return value as WorkflowReplaySourceCatalog;
}

async function readSourceTask(taskId: string): Promise<PersistedMapTask> {
  if (!bounded(taskId, TASK, 96)) throw new Error('Valid original map_workflow task ID is required.');
  const response = await fetch(`${API_BASE}/tasks/${encodeURIComponent(taskId)}`, {
    method: 'GET',
    headers: authHeaders({ Accept: 'application/json' }),
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error(`Original map_workflow source unavailable (HTTP ${response.status}).`);
  const task: unknown = await response.json();
  if (!task || typeof task !== 'object' || Array.isArray(task)) {
    throw new Error('Original workflow source was not verified.');
  }
  return task as PersistedMapTask;
}

function assertSource(task: PersistedMapTask, input: WorkflowReplayInput): void {
  if (task.id !== input.sourceTaskId
      || task.type !== 'map_workflow'
      || task.status !== 'completed'
      || task.engagement_id !== input.engagementId
      || (task.flow_id !== input.flowId && task.flow_id != null)
      || task.payload?.user_label !== input.sourceUserLabel
      || task.payload?._authorization_version !== input.expectedAuthorizationVersion
      || task.result?.workflow_id !== input.workflowId
      || !['success', 'workflow_recorded'].includes(String(task.result?.status))
      || typeof task.payload?.url !== 'string'
      || !/^https?:\/\/[^\s]+$/.test(task.payload.url)) {
    throw new Error('Original signed completed workflow source does not match the reviewed request.');
  }
}

async function assertAuthoritativeSnapshot(input: WorkflowReplayInput, engagement: Engagement): Promise<void> {
  assertActiveSenior();
  const problem = validateReplayInput(input);
  if (problem) throw new Error(problem);
  if (engagement.session_id !== input.engagementId
      || ['halted', 'completed'].includes(engagement.phase)
      || !engagement.scope.authorization_ref
      || !(engagement.scope.domains?.length || engagement.scope.ips?.length)) {
    throw new Error('Engagement and authorized target scope are not confirmed.');
  }
  const [policy, detail, source, catalog] = await Promise.all([
    supervisionApi.authorizationStatus(input.engagementId),
    flowApi.getFlow(input.flowId),
    readSourceTask(input.sourceTaskId),
    loadWorkflowReplaySources(input.engagementId, input.flowId),
  ]);
  assertActiveSenior();
  if (policy.status !== 'active' || policy.version !== input.expectedAuthorizationVersion) {
    throw new Error('Current signed authorization was revoked, changed, expired or could not be verified.');
  }
  if (catalog.flow_revision !== input.expectedFlowRevision
      || catalog.authorization_version !== input.expectedAuthorizationVersion
      || !catalog.sources.some(row => row.source_task_id === input.sourceTaskId
        && row.workflow_id === input.workflowId && row.source_user_label === input.sourceUserLabel)
      || !catalog.identities.includes(input.sourceUserLabel)
      || !catalog.identities.includes(input.targetUserLabel)) {
    throw new Error('Original workflow source or authenticated identity is absent from the current PostgreSQL catalog.');
  }
  if (!detail?.flow
      || detail.flow.id !== input.flowId
      || detail.flow.engagement_id !== input.engagementId
      || !['pending', 'running'].includes(detail.flow.status)
      || detail.flow.revision !== input.expectedFlowRevision
      || !Array.isArray(detail.tasks)
      || !detail.tasks.some(task => task.type === 'flow_objective'
        && task.flow_id === input.flowId && task.engagement_id === input.engagementId)) {
    throw new Error('Confirmed Flow/objective or exact Flow revision is unavailable. Refresh the Flow.');
  }
  assertSource(source, input);
}

/** Fetch current authoritative Flow, signer and map_workflow source before
 * enabling any proposal. Caller must explicitly supply IDs and both identities.
 */
export async function verifyReplayProposal(
  engagement: Engagement,
  flow: FlowRecord,
  fields: Pick<WorkflowReplayInput, 'workflowId' | 'sourceTaskId' | 'sourceUserLabel' | 'targetUserLabel'>,
): Promise<WorkflowReplayInput> {
  if (!flow || flow.engagement_id !== engagement?.session_id
      || !Number.isSafeInteger(flow.revision) || flow.revision < 0
      || !['pending', 'running'].includes(flow.status)) {
    throw new Error('A current confirmed, active Flow is required.');
  }
  assertActiveSenior();
  // Status is a PostgreSQL-backed signed authority read, never a local guess.
  const [policy, catalog] = await Promise.all([
    supervisionApi.authorizationStatus(engagement.session_id),
    loadWorkflowReplaySources(engagement.session_id, flow.id),
  ]);
  if (policy.status !== 'active' || !Number.isSafeInteger(policy.version)
      || policy.version === null || policy.version < 1
      || policy.version !== catalog.authorization_version
      || flow.revision !== catalog.flow_revision) {
    throw new Error('A current signed authorization version could not be verified.');
  }
  const input: WorkflowReplayInput = {
    engagementId: engagement.session_id,
    flowId: flow.id,
    expectedFlowRevision: flow.revision,
    expectedAuthorizationVersion: policy.version,
    workflowId: fields.workflowId,
    sourceTaskId: fields.sourceTaskId,
    sourceUserLabel: fields.sourceUserLabel,
    targetUserLabel: fields.targetUserLabel,
  };
  await assertAuthoritativeSnapshot(input, engagement);
  return input;
}

/** A second read before POST fences stale signer/Flow/source evidence. If HTTP
 * fails after delivery, the outcome is UNKNOWN and the caller must not retry.
 */
export async function submitWorkflowReplay(
  engagement: Engagement,
  input: WorkflowReplayInput,
): Promise<WorkflowReplayReceipt> {
  await assertAuthoritativeSnapshot(input, engagement);
  assertActiveSenior();
  const response = await fetch(
    `${API_BASE}/engagements/${encodeURIComponent(input.engagementId)}/workflows/${encodeURIComponent(input.workflowId)}/replay`,
    {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
      body: JSON.stringify({
        source_user_label: input.sourceUserLabel,
        target_user_label: input.targetUserLabel,
        expected_authorization_version: input.expectedAuthorizationVersion,
        flow_id: input.flowId,
        source_task_id: input.sourceTaskId,
        expected_flow_revision: input.expectedFlowRevision,
      }),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    },
  );
  if (!response.ok) {
    throw new Error(`Workflow replay proposal not confirmed (HTTP ${response.status}). Review persisted approvals/tasks before any new submission.`);
  }
  const raw: unknown = await response.json();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Workflow replay proposal outcome UNKNOWN: malformed server receipt.');
  }
  const receipt = raw as Partial<WorkflowReplayReceipt>;
  if (receipt.status !== 'awaiting_execution_approval'
      || !bounded(receipt.task_id, TASK, 96)
      || receipt.workflow_id !== input.workflowId
      || receipt.execution_started !== false) {
    throw new Error('Workflow replay proposal outcome UNKNOWN: no verified approval-stage receipt.');
  }
  return receipt as WorkflowReplayReceipt;
}

/** Inert review of two separately approved terminal observations.
 * The server rechecks both PG Tasks, current ROE/Flow, and original signed MCP
 * receipts. Neither a matching response nor a 200 establishes an IDOR.
 */
export async function loadSignedReplayComparison(
  engagementId: string,
  workflowId: string,
  flowId: string,
  replayTaskId: string,
  stepId: string,
): Promise<SignedReplayComparison> {
  assertActiveSenior();
  if (!bounded(engagementId, ENGAGEMENT, 84)
      || !bounded(workflowId, WORKFLOW, 83)
      || !bounded(flowId, FLOW, 96)
      || !bounded(replayTaskId, TASK, 96)
      || !bounded(stepId, STEP, 96)) {
    throw new Error('Explicit confirmed Flow, parent replay Task and workflow Step IDs are required.');
  }
  const query = new URLSearchParams({
    flow_id: flowId, replay_task_id: replayTaskId, step_id: stepId,
  });
  const response = await fetch(
    `${API_BASE}/engagements/${encodeURIComponent(engagementId)}/workflows/${encodeURIComponent(workflowId)}/signed-comparisons?${query}`,
    {
      method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
      cache: 'no-store', credentials: 'omit', redirect: 'error',
      referrerPolicy: 'no-referrer',
    },
  );
  if (!response.ok) {
    throw new Error(`Signed comparison unavailable (HTTP ${response.status}); no verified finding can be claimed.`);
  }
  const raw: unknown = await response.json();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Signed comparison evidence unavailable.');
  }
  const row = raw as Partial<SignedReplayComparison>;
  if (row.flow_id !== flowId || row.replay_task_id !== replayTaskId
      || row.step_id !== stepId
      || !['inconclusive', 'expected_denial_observed', 'candidate_needs_independent_review'].includes(String(row.status))
      || row.provider_testimony_only !== true
      || row.source_authenticity_verified !== false
      || row.target_effect_verified !== false
      || row.authorization_violation_verified !== false
      || row.findings_count !== 0
      || typeof row.reason !== 'string'
      || !/^[a-z0-9_]{1,90}$/.test(row.reason)
      || typeof row.source_observed !== 'boolean'
      || typeof row.target_observed !== 'boolean'
      || (row.comparison_sha256 !== undefined
          && (typeof row.comparison_sha256 !== 'string'
              || !/^[0-9a-f]{64}$/.test(row.comparison_sha256)))) {
    throw new Error('Comparison response cannot independently establish vulnerability or target effect.');
  }
  assertActiveSenior();
  return row as SignedReplayComparison;
}
