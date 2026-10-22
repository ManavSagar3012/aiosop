/**
 * Read-only independent signed Flow MCP Action eligibility preflight.
 * A positive result describes current persisted authority only. It does not
 * authorize, reserve, dispatch, contact a provider or guarantee future work.
 */
import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';
import {
  listFlowMcpActions, readFlowMcpAction, type FlowMcpAction, type McpActionScope,
} from './flowMcpActions';
import { supervisionApi } from './supervision';

const FLOW = /^flow-[A-Za-z0-9._-]{1,90}$/;
const ENG = /^eng-[A-Za-z0-9._-]{1,60}$/;
const ACTION = /^action-[0-9a-f]{32}$/;
const TASK = /^task-[A-Za-z0-9._:-]{1,85}$/;
const SUBTASK = /^subtask-[A-Za-z0-9._-]{1,90}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/;
const SHA = /^[0-9a-f]{64}$/;
const AUTH = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const MAX_RESPONSE_BYTES = 4096;

const denials = {
  invalid_request: 'Complete bounded signed Action identity is required',
  signed_flow_denied: 'Current signed owner, Flow or rules of engagement unavailable',
  action_unavailable: 'Exact prepared Action is unavailable or no longer eligible',
  approval_denied: 'Current independently approved Task, Subtask or lease unavailable',
  declaration_denied: 'Initialized scope-checked READ_ONLY tool declaration unavailable',
  parameters_denied: 'Prepared immutable tool parameters or approved digest differ',
  scope_denied: 'Prepared target differs from approved in-scope Task target',
  resource_denied: 'Current immutable resource assignment or senior review unavailable',
  source_unavailable: 'Authoritative preflight data unavailable',
} as const;
export type McpPreflightDenialCode = keyof typeof denials;

interface InertFacts {
  read_only: true;
  provider_contacted: false;
  approval_issued: false;
  dispatch_performed: false;
  reservation_performed: false;
  guarantees_future_dispatch: false;
}

export interface McpPreflightEligible extends InertFacts {
  allowed: true;
  code: 'preflight_eligible';
  reason: 'Existing prepared Action passes current read-only authority checks';
  flow_id: string;
  action_id: string;
  task_id: string;
  subtask_id: string;
  action_status: 'prepared';
  declaration_sha256: string;
  parameters_sha256: string;
  resource_bound: boolean;
  resource_artifact_sha256: string | null;
}

export interface McpPreflightDenied extends InertFacts {
  allowed: false;
  code: McpPreflightDenialCode;
  reason: (typeof denials)[McpPreflightDenialCode];
}

export type McpActionPreflight = McpPreflightEligible | McpPreflightDenied;

type OperatorSnapshot = {
  sub: string;
  role: string;
  exp: number;
  bearer: string;
};

function snapshot(s: McpActionScope): OperatorSnapshot {
  const operator = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!operator || !['operator', 'senior_operator'].includes(operator.role)
    || typeof operator.sub !== 'string' || !operator.sub
    || !Number.isSafeInteger(operator.exp) || (operator.exp ?? 0) * 1000 <= Date.now()
    || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
    || !FLOW.test(s.flowId) || !ENG.test(s.engagementId)
    || !Number.isSafeInteger(s.flowRevision) || s.flowRevision < 0
    || !Number.isSafeInteger(s.authorizationVersion) || s.authorizationVersion < 1
    || !AUTH.test(s.authorizationId) || !SHA.test(s.authorizationSha256)) {
    throw new Error('Current signed Flow/ROE and verified operator bearer are required.');
  }
  return { sub: operator.sub, role: operator.role, exp: operator.exp!, bearer };
}

function sameOperator(original: OperatorSnapshot): void {
  const current = currentOperator();
  if (!current || current.sub !== original.sub || current.role !== original.role
    || current.exp !== original.exp || authHeaders().Authorization !== original.bearer
    || current.exp * 1000 <= Date.now()) {
    throw new Error('Verified operator identity changed during read-only preflight.');
  }
}

async function assertAuthorization(
  s: McpActionScope, original: OperatorSnapshot,
): Promise<void> {
  sameOperator(original);
  const signed = await supervisionApi.authorizationStatus(s.engagementId);
  sameOperator(original);
  if (signed.status !== 'active'
    || signed.version !== s.authorizationVersion
    || signed.policy_sha256 !== s.authorizationSha256
    || !SHA.test(signed.policy_sha256 ?? '')) {
    throw new Error('Signed ROE changed or became unavailable during preflight.');
  }
}

/** Uses only server-verified authorization status and caller's Flow authorization ID. */
export async function currentMcpPreflightScope(
  flowId: string, engagementId: string, revision: number, authorizationId: string,
): Promise<McpActionScope> {
  const candidate: McpActionScope = {
    flowId, engagementId, flowRevision: revision,
    authorizationVersion: 1, authorizationId, authorizationSha256: '0'.repeat(64),
  };
  const actor = snapshot(candidate);
  const signed = await supervisionApi.authorizationStatus(engagementId);
  sameOperator(actor);
  if (signed.status !== 'active'
    || !Number.isSafeInteger(signed.version) || (signed.version ?? 0) < 1
    || !SHA.test(signed.policy_sha256 ?? '')) {
    throw new Error('Active independently signed engagement authorization unavailable.');
  }
  return {
    ...candidate,
    authorizationVersion: signed.version!,
    authorizationSha256: signed.policy_sha256!,
  };
}

function validatePreparedAction(action: FlowMcpAction, scope: McpActionScope): void {
  if (!action || action.flow_id !== scope.flowId || action.engagement_id !== scope.engagementId
    || !ACTION.test(action.action_id) || !TASK.test(action.task_id)
    || !SUBTASK.test(action.subtask_id) || !NAME.test(action.server_id)
    || !NAME.test(action.tool_name) || !SHA.test(action.parameters_sha256)
    || action.status !== 'prepared' || action.execution_started !== false
    || action.target_effect_verified !== false || action.safe_to_automatically_retry !== false) {
    throw new Error('Only a current independently approved PREPARED Action may be checked.');
  }
}

function samePreparedAction(a: FlowMcpAction, b: FlowMcpAction): boolean {
  return a.action_id === b.action_id && a.task_id === b.task_id
    && a.subtask_id === b.subtask_id && a.server_id === b.server_id
    && a.tool_name === b.tool_name && a.parameters_sha256 === b.parameters_sha256
    && a.status === 'prepared' && b.status === 'prepared'
    && !a.execution_started && !b.execution_started;
}

export async function listPreparedMcpPreflightActions(
  scope: McpActionScope,
): Promise<FlowMcpAction[]> {
  const original = snapshot(scope);
  await assertAuthorization(scope, original);
  const actions = await listFlowMcpActions(scope);
  sameOperator(original);
  await assertAuthorization(scope, original);
  const prepared = actions.filter(action => action.status === 'prepared');
  for (const action of prepared) validatePreparedAction(action, scope);
  return prepared;
}

/** Reject duplicate JSON keys even when a normal JSON parser would keep the last one. */
function strictResponseJson(data: string): unknown {
  const objects: Array<Set<string>> = [];
  for (let i = 0; i < data.length;) {
    if (data[i] === '{') { objects.push(new Set()); i++; continue; }
    if (data[i] === '}') { if (!objects.pop()) throw new Error('Malformed preflight JSON.'); i++; continue; }
    if (data[i] === '"') {
      const start = i++;
      let closed = false;
      while (i < data.length) {
        if (data[i] === '\\') { i += 2; continue; }
        if (data[i++] === '"') { closed = true; break; }
      }
      if (!closed) throw new Error('Invalid preflight JSON string.');
      let next = i;
      while (next < data.length && /\s/.test(data[next])) next++;
      if (data[next] === ':' && objects.length) {
        const key = JSON.parse(data.slice(start, i)) as string;
        const current = objects[objects.length - 1];
        if (current.has(key)) throw new Error('Duplicate preflight metadata field.');
        current.add(key);
      }
      continue;
    }
    i++;
  }
  if (objects.length) throw new Error('Malformed preflight metadata.');
  return JSON.parse(data) as unknown;
}

const inertFields = [
  'read_only', 'provider_contacted', 'approval_issued', 'dispatch_performed',
  'reservation_performed', 'guarantees_future_dispatch',
] as const;
const baseFields = ['allowed', 'code', 'reason', ...inertFields];
const positiveFields = [
  'flow_id', 'action_id', 'task_id', 'subtask_id', 'action_status',
  'declaration_sha256', 'parameters_sha256', 'resource_bound',
  'resource_artifact_sha256',
];

function exactShape(raw: Record<string, unknown>, fields: string[]): boolean {
  const names = Object.keys(raw);
  return names.length === fields.length
    && names.every(field => fields.includes(field))
    && fields.every(field => Object.prototype.hasOwnProperty.call(raw, field));
}

function preflightReply(
  value: unknown, s: McpActionScope, action: FlowMcpAction,
): McpActionPreflight {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Preflight metadata has an invalid shape.');
  }
  const item = value as Record<string, unknown>;
  if (item.read_only !== true || inertFields.slice(1).some(field => item[field] !== false)) {
    throw new Error('Preflight returned an unsafe provider or execution claim.');
  }
  if (item.allowed === false) {
    const code = item.code;
    if (!exactShape(item, baseFields) || typeof code !== 'string'
      || !Object.prototype.hasOwnProperty.call(denials, code)
      || item.reason !== denials[code as McpPreflightDenialCode]) {
      throw new Error('Forged or unbounded preflight denial metadata.');
    }
    return item as unknown as McpPreflightDenied;
  }
  if (item.allowed !== true || !exactShape(item, [...baseFields, ...positiveFields])
    || item.code !== 'preflight_eligible'
    || item.reason !== 'Existing prepared Action passes current read-only authority checks'
    || item.flow_id !== s.flowId || item.action_id !== action.action_id
    || item.task_id !== action.task_id || item.subtask_id !== action.subtask_id
    || item.action_status !== 'prepared' || item.parameters_sha256 !== action.parameters_sha256
    || typeof item.declaration_sha256 !== 'string' || !SHA.test(item.declaration_sha256)
    || typeof item.resource_bound !== 'boolean'
    || (item.resource_bound === true
      ? typeof item.resource_artifact_sha256 !== 'string'
        || !SHA.test(item.resource_artifact_sha256)
      : item.resource_artifact_sha256 !== null)) {
    throw new Error('Untrusted preflight eligibility or mismatched Action metadata.');
  }
  return item as unknown as McpPreflightEligible;
}

/** No raw params, targets, approval fields, headers or credentials enter the URL. */
export async function checkFlowMcpActionPreflight(
  s: McpActionScope, actionId: string, expectedManifestSha256?: string,
): Promise<McpActionPreflight> {
  const original = snapshot(s);
  if (!ACTION.test(actionId) || (expectedManifestSha256 !== undefined
    && !SHA.test(expectedManifestSha256))) {
    throw new Error('Exact prepared Action and optional signed resource manifest SHA required.');
  }
  await assertAuthorization(s, original);
  const catalog = await listFlowMcpActions(s);
  sameOperator(original);
  const matches = catalog.filter(action => action.action_id === actionId);
  if (matches.length !== 1) throw new Error('Prepared Action is missing from signed Flow catalog.');
  const action = matches[0];
  validatePreparedAction(action, s);
  const durable = await readFlowMcpAction(s, actionId);
  sameOperator(original);
  if (!samePreparedAction(action, durable)) {
    throw new Error('Prepared Action changed before eligibility preflight.');
  }
  await assertAuthorization(s, original);
  const query = new URLSearchParams({
    expected_engagement_id: s.engagementId,
    expected_revision: String(s.flowRevision),
    expected_authorization_version: String(s.authorizationVersion),
    task_id: action.task_id,
    subtask_id: action.subtask_id,
    server_id: action.server_id,
    tool_name: action.tool_name,
    expected_parameters_sha256: action.parameters_sha256,
  });
  if (expectedManifestSha256) query.set('expected_manifest_sha256', expectedManifestSha256);
  sameOperator(original);
  const url = `${API_BASE}/flows/${encodeURIComponent(s.flowId)}/mcp-actions/${encodeURIComponent(actionId)}/preflight?${query}`;
  const reply = await fetch(url, {
    method: 'GET',
    headers: { Authorization: original.bearer, Accept: 'application/json' },
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  sameOperator(original);
  if (reply.status !== 200
    || !/^application\/json(?:;|$)/i.test(reply.headers.get('content-type') ?? '')) {
    throw new Error('Read-only MCP Action preflight unavailable. No eligibility established.');
  }
  const declaredSize = reply.headers.get('content-length');
  if (declaredSize && (!/^\d+$/.test(declaredSize) || Number(declaredSize) > MAX_RESPONSE_BYTES)) {
    throw new Error('Preflight response exceeds safe metadata bounds.');
  }
  const data = await reply.text();
  sameOperator(original);
  if (new TextEncoder().encode(data).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error('Preflight metadata exceeds safe size limit.');
  }
  const verified = preflightReply(strictResponseJson(data), s, action);
  await assertAuthorization(s, original);
  const after = await readFlowMcpAction(s, actionId);
  sameOperator(original);
  if (!samePreparedAction(action, after)) {
    throw new Error('Prepared Action changed during read-only eligibility preflight.');
  }
  await assertAuthorization(s, original);
  return verified;
}
