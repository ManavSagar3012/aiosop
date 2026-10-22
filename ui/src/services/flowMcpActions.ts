/** Independently approved signed Task MCP action controls, NEVER a review-marker dispatch.
 *
 * An operator click cannot approve an Action; the server must independently
 * check original PostgreSQL Task/Subtask/Action, current signed ROE, human
 * approval, lease, MCP declaration and quota before reserving a remote call.
 * Provider success is NOT proof of independently verified target effect.
 */
import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

const FLOW = /^flow-[A-Za-z0-9._-]{1,90}$/;
const ENG = /^eng-[A-Za-z0-9._-]{1,60}$/;
const TASK = /^task-[A-Za-z0-9._:-]{1,85}$/;
const STEP = /^subtask-[A-Za-z0-9._-]{1,90}$/;
const ACTION = /^action-[0-9a-f]{32}$/;
const REQUEST = /^req-[0-9a-f]{32,64}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/;
const SHA = /^[0-9a-f]{64}$/;
const AUTH = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const BAD = /token|authorization|cookie|password|secret|credential|api[_-]?key|private[_-]?key|payload|script|shell|command|raw_request/i;
const statuses = ['prepared', 'reserved', 'unknown', 'finished', 'cancelled'];
// Public metadata is produced by flow_mcp_actions._public_record. In particular,
// authorization_version and receipt_sha256 are legitimate signed-ledger fields;
// a broad secret-name regex must not reject those while accepting arbitrary keys.
const PUBLIC_ACTION_FIELDS = new Set([
  'action_id', 'flow_id', 'engagement_id', 'task_id', 'subtask_id',
  'server_id', 'tool_name', 'status', 'parameters_sha256', 'request_id',
  'execution_started', 'target_effect_verified', 'safe_to_automatically_retry',
  'flow_revision', 'authorization_version', 'declaration_sha256',
  'receipt_sha256', 'side_effect_class', 'intent_sha256', 'cancel_requested',
]);
const attempts = new Set<string>();

export interface McpActionScope {
  flowId: string;
  engagementId: string;
  flowRevision: number;
  authorizationVersion: number;
  authorizationId: string;
  authorizationSha256: string;
}

export interface FlowMcpAction {
  action_id: string;
  flow_id: string;
  engagement_id: string;
  task_id: string;
  subtask_id: string;
  server_id: string;
  tool_name: string;
  status: 'prepared'|'reserved'|'unknown'|'finished'|'cancelled';
  parameters_sha256: string;
  request_id?: string;
  flow_revision?: number;
  authorization_version?: number;
  declaration_sha256?: string;
  receipt_sha256?: string | null;
  intent_sha256?: string;
  side_effect_class?: 'READ_ONLY' | 'RECON_ACTIVE' | 'INVASIVE_EXPLOIT';
  cancel_requested?: boolean;
  execution_started: boolean;
  target_effect_verified: false;
  safe_to_automatically_retry: false;
}

export interface McpActionPreparation {
  taskId: string;
  subtaskId: string;
  serverId: string;
  toolName: string;
  parameters: Record<string, string | number | boolean>;
  confirmed: true;
}

function scope(s: McpActionScope) {
  const actor = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!actor || !['operator','senior_operator'].includes(actor.role) || !actor.sub
    || actor.exp === null || actor.exp * 1000 <= Date.now()
    || !FLOW.test(s.flowId) || !ENG.test(s.engagementId)
    || !Number.isSafeInteger(s.flowRevision) || s.flowRevision < 0
    || !Number.isSafeInteger(s.authorizationVersion) || s.authorizationVersion < 1
    || !AUTH.test(s.authorizationId) || !SHA.test(s.authorizationSha256)
    || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin())
    throw new Error('Current signed human operator and Flow scope required.');
  return { actor, bearer };
}

function fresh(original: ReturnType<typeof scope>) {
  const actor = currentOperator();
  if (!actor || actor.sub !== original.actor.sub || actor.role !== original.actor.role
    || actor.exp !== original.actor.exp || authHeaders().Authorization !== original.bearer)
    throw new Error('Signed operator changed: action outcome UNKNOWN.');
}

function url(s: McpActionScope, actionId?: string): string {
  const query = new URLSearchParams({
    expected_engagement_id: s.engagementId,
    expected_revision: String(s.flowRevision),
    expected_authorization_version: String(s.authorizationVersion),
  });
  return `${API_BASE}/flows/${encodeURIComponent(s.flowId)}/mcp-actions${actionId ? `/${encodeURIComponent(actionId)}` : ''}?${query}`;
}

async function body(response: Response): Promise<unknown> {
  const size = response.headers?.get('content-length');
  if (size && (!/^\d+$/.test(size) || Number(size) > 32768))
    throw new Error('MCP Action readback exceeds safe metadata bounds.');
  const data = await response.text();
  if (data.length > 32768) throw new Error('MCP action response too large.');
  // Duplicate keys anywhere in a JSON object are ambiguous. Count *within
  // each object*, not globally: an actions array correctly repeats keys on
  // different records. This scanner does not parse values or trust strings.
  const objects:Array<Set<string>>=[];
  for(let i=0;i<data.length;){
    if(data[i]==='{'){objects.push(new Set());i++;continue;}
    if(data[i]==='}'){objects.pop();i++;continue;}
    if(data[i]==='"'){
      const start=i++;
      while(i<data.length){
        if(data[i]==='\\'){i+=2;continue;}
        if(data[i++]==='"')break;
      }
      let next=i;
      while(/\s/.test(data[next]??''))next++;
      if(data[next]===':' && objects.length){
        const key=JSON.parse(data.slice(start,i)) as string;
        const current=objects[objects.length-1];
        if(current.has(key))throw new Error('Ambiguous signed MCP action response.');
        current.add(key);
      }
      continue;
    }
    i++;
  }
  return JSON.parse(data) as unknown;
}

function record(raw: unknown, s: McpActionScope): FlowMcpAction {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error('Invalid MCP Action metadata.');
  const r = raw as Record<string, unknown>;
  if (r.flow_id !== s.flowId || r.engagement_id !== s.engagementId
    || typeof r.action_id !== 'string' || !ACTION.test(r.action_id)
    || typeof r.task_id !== 'string' || !TASK.test(r.task_id)
    || typeof r.subtask_id !== 'string' || !STEP.test(r.subtask_id)
    || typeof r.server_id !== 'string' || !NAME.test(r.server_id)
    || typeof r.tool_name !== 'string' || !NAME.test(r.tool_name)
    || !statuses.includes(String(r.status))
    || typeof r.parameters_sha256 !== 'string' || !SHA.test(r.parameters_sha256)
    || (r.request_id !== undefined && (typeof r.request_id !== 'string' || !REQUEST.test(r.request_id)))
    || (r.flow_revision !== undefined && r.flow_revision !== s.flowRevision)
    || (r.authorization_version !== undefined && r.authorization_version !== s.authorizationVersion)
    || (r.declaration_sha256 !== undefined && (typeof r.declaration_sha256 !== 'string' || !SHA.test(r.declaration_sha256)))
    || (r.intent_sha256 !== undefined && (typeof r.intent_sha256 !== 'string' || !SHA.test(r.intent_sha256)))
    || (r.receipt_sha256 !== undefined && r.receipt_sha256 !== null
      && (typeof r.receipt_sha256 !== 'string' || !SHA.test(r.receipt_sha256)))
    || (r.side_effect_class !== undefined
      && !['READ_ONLY', 'RECON_ACTIVE', 'INVASIVE_EXPLOIT'].includes(String(r.side_effect_class)))
    || (r.cancel_requested !== undefined && typeof r.cancel_requested !== 'boolean')
    || typeof r.execution_started !== 'boolean'
    || r.target_effect_verified !== false || r.safe_to_automatically_retry !== false
    || Object.keys(r).some(k => !PUBLIC_ACTION_FIELDS.has(k)))
    throw new Error('Forged, private or unverified MCP action response.');
  return r as unknown as FlowMcpAction;
}

async function get(s: McpActionScope, actor: ReturnType<typeof scope>, id?: string): Promise<unknown> {
  const response = await fetch(url(s,id), {
    method:'GET', headers: authHeaders({Accept:'application/json'}),
    credentials:'omit', cache:'no-store', redirect:'error', referrerPolicy:'no-referrer',
  });
  if (response.status !== 200) throw new Error('Current signed MCP action unavailable.');
  const value = await body(response);
  fresh(actor);
  return value;
}

export async function listFlowMcpActions(s: McpActionScope): Promise<FlowMcpAction[]> {
  const actor = scope(s);
  const value = await get(s,actor);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid action listing.');
  const r = value as Record<string, unknown>;
  if (r.flow_id !== s.flowId || r.engagement_id !== s.engagementId
    || r.flow_revision !== s.flowRevision || r.authorization_version !== s.authorizationVersion
    || Object.keys(r).length !== 5 || !Array.isArray(r.actions) || r.actions.length > 100)
    throw new Error('Stale, unbounded or foreign signed MCP action listing.');
  const actions = r.actions.map(item => record(item,s));
  if (new Set(actions.map(item=>item.action_id)).size !== actions.length)
    throw new Error('Duplicate action identity in durable listing.');
  return actions;
}

export async function readFlowMcpAction(s: McpActionScope, actionId: string): Promise<FlowMcpAction> {
  const actor = scope(s);
  if (!ACTION.test(actionId)) throw new Error('Exact approved Action ID required.');
  const value = record(await get(s,actor,actionId),s);
  if (value.action_id !== actionId) throw new Error('Wrong Action readback.');
  return value;
}

function validateParams(value: Record<string, string|number|boolean>) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length > 8) throw new Error('Bounded non-secret MCP tool parameters required.');
  for (const [key, entry] of Object.entries(value)) {
    if (!NAME.test(key) || BAD.test(key)
      || !(typeof entry === 'boolean'
        || (typeof entry === 'number' && Number.isSafeInteger(entry) && Math.abs(entry) <= 1000000)
        || (typeof entry === 'string' && entry.length <= 400 && !/[\r\n\x00-\x1f]/.test(entry))))
      throw new Error('MCP parameters contain forbidden executable or secret metadata.');
    if (typeof entry === 'string' && /^(?:https?:\/\/)/i.test(entry)) {
      const parsed = new URL(entry);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash)
        throw new Error('Only explicit HTTPS destination without credentials is allowed.');
    }
  }
}

function once(s: McpActionScope, original: ReturnType<typeof scope>, kind:string, payload:unknown):void {
  // Never retain the raw bearer in a per-tab anti-replay key. A new token does
  // not make an uncertain external Action safe to resubmit.
  const key = JSON.stringify([original.actor.sub,original.actor.exp,s,kind,payload]);
  if (attempts.has(key)) throw new Error('Action already attempted. Resolve UNKNOWN through signed GET; never replay POST.');
  attempts.add(key); // reserve before any network I/O or exception
}

async function post(s: McpActionScope, actor: ReturnType<typeof scope>, path:string, payload:unknown, expected:number) {
  const response = await fetch(path,{
    method:'POST',
    headers:authHeaders({'Content-Type':'application/json',Accept:'application/json'}),
    body:JSON.stringify(payload),
    credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
  });
  if (response.status !== expected) throw new Error('Signed MCP action mutation denied or outcome UNKNOWN. No automatic retry.');
  const answer = record(await body(response),s);
  fresh(actor);
  return answer;
}

export async function prepareFlowMcpAction(s:McpActionScope, p:McpActionPreparation):Promise<FlowMcpAction> {
  const actor=scope(s);
  if (p.confirmed !== true || !TASK.test(p.taskId) || !STEP.test(p.subtaskId)
    || !NAME.test(p.serverId) || !NAME.test(p.toolName)) throw new Error('Exact approved Task/Subtask and confirmation required.');
  validateParams(p.parameters);
  once(s,actor,'prepare',p);
  const answer=await post(s,actor,url(s),{
    expected_engagement_id:s.engagementId,expected_revision:s.flowRevision,
    expected_authorization_version:s.authorizationVersion,
    task_id:p.taskId,subtask_id:p.subtaskId,
    server_id:p.serverId,tool_name:p.toolName,parameters:p.parameters,
    explicit_human_confirmation:true,
  },201);
  if (answer.status!=='prepared' || answer.task_id!==p.taskId || answer.subtask_id!==p.subtaskId
    || answer.server_id!==p.serverId || answer.tool_name!==p.toolName || answer.execution_started!==false)
    throw new Error('Prepared MCP action outcome UNKNOWN; signed readback required.');
  const current=await readFlowMcpAction(s,answer.action_id);
  if (current.status!=='prepared' || current.parameters_sha256!==answer.parameters_sha256)
    throw new Error('Prepared MCP action is not durably readable; outcome UNKNOWN.');
  return current;
}

export async function dispatchFlowMcpAction(s:McpActionScope, actionId:string, confirmed:true):Promise<FlowMcpAction> {
  const actor=scope(s);
  if (!ACTION.test(actionId) || confirmed!==true) throw new Error('Explicit approved Action and dispatch confirmation required.');
  once(s,actor,'dispatch',actionId);
  const result=await post(s,actor,`${url(s,actionId).replace('?', '/dispatch?')}`,{
    expected_engagement_id:s.engagementId,expected_revision:s.flowRevision,
    expected_authorization_version:s.authorizationVersion,explicit_human_confirmation:true,
  },200);
  if (result.action_id!==actionId || result.status==='prepared' || result.target_effect_verified!==false)
    throw new Error('Dispatch receipt cannot establish remote effect; outcome UNKNOWN.');
  const readback=await readFlowMcpAction(s,actionId);
  if (readback.parameters_sha256!==result.parameters_sha256 || readback.status!==result.status)
    throw new Error('Remote dispatch outcome UNKNOWN; do not automatically replay.');
  return readback;
}

/** Human-submitted *provider status evidence*, never remote replay or target proof. */
export async function reconcileSignedMcpAction(
  s:McpActionScope, action:FlowMcpAction, receiptJson:string, confirmed:true,
):Promise<FlowMcpAction> {
  const actor=scope(s);
  if(confirmed!==true || !ACTION.test(action.action_id) || action.status!=='unknown'
    || action.flow_id!==s.flowId || action.engagement_id!==s.engagementId
    || !action.request_id || !REQUEST.test(action.request_id)
    || typeof receiptJson!=='string' || receiptJson.length>4096 || receiptJson.length<50)
    throw new Error('Only an exact UNKNOWN Action with signed provider status may be reconciled.');
  let candidate:Record<string,unknown>;
  try {
    const parsed=JSON.parse(receiptJson) as unknown;
    if(!parsed || typeof parsed!=='object' || Array.isArray(parsed))throw new Error('Invalid receipt');
    candidate=parsed as Record<string,unknown>;
  } catch {throw new Error('Provider status must be bounded JSON.');}
  const fields=['request_id','engagement_id','task_id','server_id','status','verified','stopped','issued_at','attestation'];
  if(Object.keys(candidate).length!==fields.length || fields.some(key=>!Object.prototype.hasOwnProperty.call(candidate,key))
    || candidate.request_id!==action.request_id || candidate.engagement_id!==s.engagementId
    || candidate.task_id!==action.task_id || candidate.server_id!==action.server_id
    || !['finished','completed','succeeded','failed','cancelled','canceled','confirmed_stopped'].includes(String(candidate.status))
    || candidate.verified!==true || typeof candidate.stopped!=='boolean'
    || !Number.isSafeInteger(candidate.issued_at)
    || typeof candidate.attestation!=='object' || candidate.attestation===null || Array.isArray(candidate.attestation)
    || Object.keys(candidate.attestation as object).length!==2
    || typeof (candidate.attestation as Record<string,unknown>).kid!=='string'
    || typeof (candidate.attestation as Record<string,unknown>).signature!=='string')
    throw new Error('Unsigned, mismatched or unbounded provider receipt is not actionable.');
  // Reconciliation may have been committed after a lost response. Mark before
  // sending, and do not allow a second POST even with a new bearer in this tab.
  once(s,actor,'provider-reconcile',action.action_id);
  const receipt=await post(s,actor,url(s,action.action_id).replace('?', '/reconcile?'),{
    expected_engagement_id:s.engagementId,expected_revision:s.flowRevision,
    expected_authorization_version:s.authorizationVersion,explicit_human_confirmation:true,
    provider_receipt:candidate,
  },200);
  if(receipt.action_id!==action.action_id || !['finished','cancelled'].includes(receipt.status)
    || receipt.target_effect_verified!==false)
    throw new Error('Provider status outcome UNKNOWN; never invent target verification.');
  const readback=await readFlowMcpAction(s,action.action_id);
  if(readback.status!==receipt.status || readback.parameters_sha256!==action.parameters_sha256
    || readback.target_effect_verified!==false)
    throw new Error('Signed provider status readback UNKNOWN; manually inspect ledger.');
  return readback;
}
