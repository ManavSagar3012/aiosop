/** Signed, PostgreSQL-backed MCP Action + in-process provider inventory.
 * No health probes, initialization, approval, dispatch, target or credential I/O.
 */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';
import { supervisionApi } from './supervision';

const ENG = /^eng-[A-Za-z0-9._-]{1,60}$/;
const FLOW = /^flow-[A-Za-z0-9._-]{1,90}$/;
const NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/;
const AUTH = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SHA = /^[0-9a-f]{64}$/;
const EXPECTED_SERVERS = [
  'burp-mcp','recon-mcp','payload-mcp','nuclei-mcp','shodan-mcp',
  'threat-intel-mcp','security-bridge','browser-mcp','source-map-mcp',
  'cloud-mcp','turbo-intruder-mcp',
];
const TOP = ['engagement_id','flow_id','flow_revision','authorization_version','kind',
  'provider_contacted','execution_authorized','independent_target_effect_verified','servers'];
const ROW = ['server_id','registered_in_process','manifest_initialized','circuit_state',
  'declared_tool_count','prepared_actions','reserved_actions','unknown_actions',
  'finished_actions','cancelled_actions','stale_prepared_declarations',
  'runtime_health_verified','provider_side_signed_admission_verified',
  'execution_authorized','independent_target_effect_verified'];

export interface ProviderReadinessRow {
  server_id: string;
  registered_in_process: boolean;
  manifest_initialized: boolean;
  circuit_state: 'closed'|'open'|'half_open'|'unavailable';
  declared_tool_count: number;
  prepared_actions: number;
  reserved_actions: number;
  unknown_actions: number;
  finished_actions: number;
  cancelled_actions: number;
  stale_prepared_declarations: number;
  runtime_health_verified: false;
  provider_side_signed_admission_verified: false;
  execution_authorized: false;
  independent_target_effect_verified: false;
}
export interface SignedMcpProviderReadiness {
  engagement_id: string;
  flow_id: string;
  flow_revision: number;
  authorization_version: number;
  kind: 'signed_action_and_process_inventory_unverified';
  provider_contacted: false;
  execution_authorized: false;
  independent_target_effect_verified: false;
  servers: ProviderReadinessRow[];
}

function exact(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Unsupported MCP provider inventory.');
  const r = value as Record<string, unknown>;
  if (Object.keys(r).length !== keys.length || keys.some(key=> !Object.prototype.hasOwnProperty.call(r,key)))
    throw new Error('Untrusted/private MCP provider response.');
  return r;
}

function parseBoundedJson(raw: string): unknown {
  if (raw.length > 16000) throw new Error('MCP provider metadata over limit.');
  const objects: Array<Set<string>> = [];
  for (let i=0; i<raw.length;) {
    if(raw[i]==='{'){objects.push(new Set()); i++;continue;}
    if(raw[i]==='}'){if(!objects.length)throw new Error('Malformed JSON');objects.pop();i++;continue;}
    if(raw[i]==='"'){
      const start=i++;
      while(i<raw.length){if(raw[i]==='\\'){i+=2;continue;} if(raw[i++]==='"')break;}
      let k=i;while(/\s/.test(raw[k]??''))k++;
      if(raw[k]===':' && objects.length){
        const key=JSON.parse(raw.slice(start,i)) as string;
        const current=objects[objects.length-1];
        if(current.has(key))throw new Error('Duplicate MCP metadata key');current.add(key);
      }
      continue;
    }
    i++;
  }
  if(objects.length)throw new Error('Malformed MCP JSON');
  return JSON.parse(raw) as unknown;
}

function parseResult(input: unknown, engagementId:string, flowId:string,
  revision:number, version:number): SignedMcpProviderReadiness {
  const response=exact(input,TOP);
  if(response.engagement_id!==engagementId || response.flow_id!==flowId
    || response.flow_revision!==revision || response.authorization_version!==version
    || response.kind!=='signed_action_and_process_inventory_unverified'
    || response.provider_contacted!==false || response.execution_authorized!==false
    || response.independent_target_effect_verified!==false
    || !Array.isArray(response.servers) || response.servers.length!==EXPECTED_SERVERS.length)
    throw new Error('Stale, foreign or falsely authenticated MCP inventory.');
  const seen=new Set<string>();
  for (const item of response.servers) {
    const row=exact(item,ROW);
    if(typeof row.server_id!=='string' || !NAME.test(row.server_id)
      || !EXPECTED_SERVERS.includes(row.server_id) || seen.has(row.server_id)
      || typeof row.registered_in_process!=='boolean' || typeof row.manifest_initialized!=='boolean'
      || !['closed','open','half_open','unavailable'].includes(String(row.circuit_state))
      || (!row.registered_in_process && (row.manifest_initialized!==false || row.circuit_state!=='unavailable'))
      || row.runtime_health_verified!==false || row.provider_side_signed_admission_verified!==false
      || row.execution_authorized!==false || row.independent_target_effect_verified!==false
      || ['declared_tool_count','prepared_actions','reserved_actions','unknown_actions','finished_actions',
          'cancelled_actions','stale_prepared_declarations'].some(k=>!Number.isSafeInteger(row[k]) || (row[k] as number)<0 || (row[k] as number)>128)
      || (row.stale_prepared_declarations as number)>(row.prepared_actions as number))
      throw new Error('Forged MCP provider readiness/Action metadata.');
    seen.add(row.server_id);
  }
  if(seen.size!==EXPECTED_SERVERS.length)throw new Error('Incomplete MCP inventory.');
  return response as unknown as SignedMcpProviderReadiness;
}

export async function readSignedFlowMcpProviderReadiness(
  engagementId:string, flowId:string, revision:number, authorizationId:string,
):Promise<SignedMcpProviderReadiness> {
  const actor=currentOperator();
  if(!actor || !['operator','senior_operator'].includes(actor.role)
    || actor.exp===null || actor.exp*1000<=Date.now()
    || !ENG.test(engagementId) || !FLOW.test(flowId) || !AUTH.test(authorizationId)
    || !Number.isSafeInteger(revision) || revision<0
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin())
    throw new Error('Current signed Flow and operator required.');
  const bearer=authHeaders().Authorization;
  if(typeof bearer!=='string' || !/^Bearer \S{1,4096}$/.test(bearer))throw new Error('Signed bearer required.');
  const status=await supervisionApi.authorizationStatus(engagementId);
  if(status.status!=='active' || !Number.isSafeInteger(status.version) || (status.version??0)<1
    || !SHA.test(status.policy_sha256??''))throw new Error('Current signed ROE unavailable.');
  const version=status.version!;
  const signerSha=status.policy_sha256;
  const query=new URLSearchParams({expected_engagement_id:engagementId,
    expected_revision:String(revision),expected_authorization_version:String(version)});
  const response=await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/mcp-provider-readiness?${query}`,{
    method:'GET',headers:authHeaders({Accept:'application/json'}),
    credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
  });
  if(response.status!==200)throw new Error('Signed MCP provider inventory unavailable.');
  const length=response.headers?.get('content-length');
  if(length && (!/^\d+$/.test(length) || Number(length)>16000))throw new Error('Oversized MCP inventory.');
  const data=parseResult(parseBoundedJson(await response.text()),engagementId,flowId,revision,version);
  const after=await supervisionApi.authorizationStatus(engagementId);
  const now=currentOperator();
  if(after.status!=='active' || after.version!==version || after.policy_sha256!==signerSha
    || !now || now.sub!==actor.sub || now.role!==actor.role || now.exp!==actor.exp
    || authHeaders().Authorization!==bearer)throw new Error('Current signed MCP identity changed.');
  return data;
}
