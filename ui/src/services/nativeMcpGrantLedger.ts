/** Signed Flow's inert native-grant PostgreSQL readback. No grant/token/signature. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';
import { supervisionApi } from './supervision';

const ENG=/^eng-[A-Za-z0-9._-]{1,60}$/;
const FLOW=/^flow-[A-Za-z0-9._-]{1,90}$/;
const ID=/^(?:ngr|action)-[a-f0-9]{32}$/;
const REQUEST=/^req-[a-f0-9]{32,64}$/;
const SHA=/^[0-9a-f]{64}$/;
const AUTH=/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SERVERS=['recon-mcp','payload-mcp','nuclei-mcp','shodan-mcp','threat-intel-mcp','security-bridge'];
const TOP=['engagement_id','flow_id','flow_revision','authorization_version','source',
  'server_side_signed_authorization_verified','independent_target_effect_verified','grants'];
const ROW=['grant_id','action_id','request_id','server_id','tool_name','status','issued_at','expires_at',
  'reviewed_resource_bound','resource_bytes_checked_at_redemption',
  'original_resource_bytes_offered_once','approved_folder_staging_bound',
  'worker_stage_receipt_reported','supervisor_lifecycle_observed','supervisor_state',
  'supervisor_revision',
  'supervisor_cleanup_observed','supervisor_recovery_required',
  'supervisor_recovery_intent_pending'];

export interface NativeMcpGrantRow {
  grant_id:string;
  action_id:string;
  request_id:string;
  server_id:string;
  tool_name:'authority_status';
  status:'issued'|'redeemed'|'unknown'|'revoked';
  issued_at:number;
  expires_at:number;
  reviewed_resource_bound:boolean;
  resource_bytes_checked_at_redemption:boolean;
  original_resource_bytes_offered_once:boolean;
  approved_folder_staging_bound:boolean;
  worker_stage_receipt_reported:boolean;
  supervisor_lifecycle_observed:boolean;
  supervisor_state:null|'provisioned'|'running'|'terminating'|'terminated'|'unknown'|'reaped';
  supervisor_revision:null|number;
  supervisor_cleanup_observed:boolean;
  supervisor_recovery_required:boolean;
  supervisor_recovery_intent_pending:boolean;
}
export interface NativeMcpGrantLedger {
  engagement_id:string;
  flow_id:string;
  flow_revision:number;
  authorization_version:number;
  source:'durable_native_grants';
  server_side_signed_authorization_verified:false;
  independent_target_effect_verified:false;
  grants:NativeMcpGrantRow[];
}

function exact(raw:unknown,fields:string[]):Record<string,unknown>{
  if(!raw||typeof raw!=='object'||Array.isArray(raw))throw Error('Private native grant data rejected.');
  const r=raw as Record<string,unknown>;
  if(Object.keys(r).length!==fields.length||fields.some(k=>!Object.prototype.hasOwnProperty.call(r,k)))
    throw Error('Unexpected private or ambiguous grant fields.');
  return r;
}

function strictJson(text:string):unknown{
  if(text.length>24000)throw Error('Native grant metadata exceeds bounded size.');
  const objects:Array<Set<string>>=[];
  for(let i=0;i<text.length;){
    if(text[i]==='{'){objects.push(new Set());i++;continue;}
    if(text[i]==='}'){if(!objects.length)throw Error('Unbalanced grant JSON.');objects.pop();i++;continue;}
    if(text[i]==='"'){
      const start=i++;
      while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"')break;}
      let next=i;while(/\s/.test(text[next]??''))next++;
      if(text[next]===':'&&objects.length){
        const key=JSON.parse(text.slice(start,i)) as string;
        const keys=objects[objects.length-1];
        if(keys.has(key))throw Error('Duplicate native grant JSON field.');keys.add(key);
      }
      continue;
    }i++;
  }
  if(objects.length)throw Error('Incomplete native grant JSON.');
  return JSON.parse(text) as unknown;
}

function parse(value:unknown,engagementId:string,flowId:string,revision:number,version:number):NativeMcpGrantLedger{
  const r=exact(value,TOP);
  if(r.engagement_id!==engagementId||r.flow_id!==flowId||r.flow_revision!==revision
    ||r.authorization_version!==version||r.source!=='durable_native_grants'
    ||r.server_side_signed_authorization_verified!==false||r.independent_target_effect_verified!==false
    ||!Array.isArray(r.grants)||r.grants.length>100)throw Error('Stale or misleading native grant readback.');
  const unique=new Set<string>();
  for(const raw of r.grants){
    const row=exact(raw,ROW);
    if(typeof row.grant_id!=='string'||!ID.test(row.grant_id)||!row.grant_id.startsWith('ngr-')
      ||typeof row.action_id!=='string'||!ID.test(row.action_id)||!row.action_id.startsWith('action-')
      ||typeof row.request_id!=='string'||!REQUEST.test(row.request_id)
      ||typeof row.server_id!=='string'||!SERVERS.includes(row.server_id)
      ||row.tool_name!=='authority_status'||!['issued','redeemed','unknown','revoked'].includes(String(row.status))
      ||!Number.isSafeInteger(row.issued_at)||!Number.isSafeInteger(row.expires_at)
      ||typeof row.reviewed_resource_bound!=='boolean'
      ||typeof row.resource_bytes_checked_at_redemption!=='boolean'
      ||typeof row.original_resource_bytes_offered_once!=='boolean'
      ||typeof row.approved_folder_staging_bound!=='boolean'
      ||typeof row.worker_stage_receipt_reported!=='boolean'
      ||typeof row.supervisor_lifecycle_observed!=='boolean'
      ||typeof row.supervisor_cleanup_observed!=='boolean'
      ||typeof row.supervisor_recovery_required!=='boolean'
      ||typeof row.supervisor_recovery_intent_pending!=='boolean'
      ||(row.supervisor_state!==null&&!['provisioned','running','terminating','terminated','unknown','reaped'].includes(String(row.supervisor_state)))
      ||(row.supervisor_state===null&&row.supervisor_revision!==null)
      ||(row.supervisor_state!==null&&(!Number.isSafeInteger(row.supervisor_revision)
          ||(row.supervisor_revision as number)<1||(row.supervisor_revision as number)>2147483647))
      ||(row.supervisor_lifecycle_observed!==(row.supervisor_state!==null))
      ||(row.supervisor_cleanup_observed!==(row.supervisor_state==='reaped'))
      ||(row.supervisor_recovery_required!==(row.supervisor_state==='unknown'))
      ||(row.supervisor_recovery_intent_pending===true
         &&!['unknown','terminating'].includes(String(row.supervisor_state)))
      ||(row.supervisor_state==='running'&&row.status==='issued')
      ||(row.resource_bytes_checked_at_redemption===true &&
        (row.reviewed_resource_bound!==true || row.status!=='redeemed'))
      ||(row.original_resource_bytes_offered_once===true &&
        (row.reviewed_resource_bound!==true || row.status!=='redeemed'
          ||row.resource_bytes_checked_at_redemption!==true))
      ||(row.approved_folder_staging_bound===true
        &&row.original_resource_bytes_offered_once!==true)
      ||(row.worker_stage_receipt_reported===true
        &&(row.approved_folder_staging_bound!==true ||
          row.original_resource_bytes_offered_once!==true))
      ||(row.expires_at as number)-(row.issued_at as number)<1
      ||(row.expires_at as number)-(row.issued_at as number)>60
      ||unique.has(row.grant_id))throw Error('Untrusted or private native grant row.');
    unique.add(row.grant_id);
  }
  return r as unknown as NativeMcpGrantLedger;
}

export async function readNativeMcpGrantLedger(
  engagementId:string,flowId:string,revision:number,authorizationId:string,
):Promise<NativeMcpGrantLedger>{
  const actor=currentOperator();
  if(!actor||!['operator','senior_operator'].includes(actor.role)||actor.exp===null||actor.exp*1000<=Date.now()
    ||!ENG.test(engagementId)||!FLOW.test(flowId)||!AUTH.test(authorizationId)
    ||!Number.isSafeInteger(revision)||revision<0||!isSecureApiBase(API_BASE)||!isSecureBrowserOrigin())
    throw Error('Current signed native Flow and operator required.');
  const bearer=authHeaders().Authorization;
  if(typeof bearer!=='string'||!/^Bearer \S{1,4096}$/.test(bearer))throw Error('Current signed bearer required.');
  const before=await supervisionApi.authorizationStatus(engagementId);
  if(before.status!=='active'||!Number.isSafeInteger(before.version)||(before.version??0)<1
    ||!SHA.test(before.policy_sha256??''))throw Error('Current signed ROE unavailable.');
  const query=new URLSearchParams({expected_engagement_id:engagementId,
    expected_revision:String(revision),expected_authorization_version:String(before.version)});
  const response=await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/native-mcp-grants?${query}`,{
    method:'GET',headers:authHeaders({Accept:'application/json'}),credentials:'omit',cache:'no-store',
    redirect:'error',referrerPolicy:'no-referrer',
  });
  if(response.status!==200)throw Error('Durable native grant state unavailable.');
  const length=response.headers?.get('content-length');
  if(length&&(!/^\d+$/.test(length)||Number(length)>24000))throw Error('Native grant metadata over limit.');
  const ledger=parse(strictJson(await response.text()),engagementId,flowId,revision,before.version!);
  const after=await supervisionApi.authorizationStatus(engagementId);
  const now=currentOperator();
  if(after.status!=='active'||after.version!==before.version||after.policy_sha256!==before.policy_sha256
    ||!now||now.sub!==actor.sub||now.role!==actor.role||now.exp!==actor.exp
    ||authHeaders().Authorization!==bearer)throw Error('Native signed grant context changed during read.');
  return ledger;
}

/** Explicit owner intent ONLY: not a container kill, native call or UNKNOWN replay. */
export async function requestNativeWorkerRecoveryIntent(
  engagementId:string,flowId:string,revision:number,authorizationId:string,
  grantId:string,supervisorRevision:number,
):Promise<void>{
  const actor=currentOperator();
  if(!actor||!['operator','senior_operator'].includes(actor.role)||actor.exp===null||actor.exp*1000<=Date.now()
    ||!ENG.test(engagementId)||!FLOW.test(flowId)||!AUTH.test(authorizationId)
    ||!/^ngr-[a-f0-9]{32}$/.test(grantId)||!Number.isSafeInteger(revision)||revision<0
    ||!Number.isSafeInteger(supervisorRevision)||supervisorRevision<1
    ||!isSecureApiBase(API_BASE)||!isSecureBrowserOrigin())throw Error('Current signed Flow required.');
  const bearer=authHeaders().Authorization;
  if(typeof bearer!=='string'||!/^Bearer \S{1,4096}$/.test(bearer))throw Error('Current signed bearer required.');
  const before=await supervisionApi.authorizationStatus(engagementId);
  if(before.status!=='active'||!Number.isSafeInteger(before.version)
    ||(before.version??0)<1||!SHA.test(before.policy_sha256??''))throw Error('Signed ROE unavailable.');
  const response=await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/native-mcp-supervision/recovery`,{
    method:'POST',headers:authHeaders({'Content-Type':'application/json',Accept:'application/json'}),
    credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
    body:JSON.stringify({expected_engagement_id:engagementId,expected_revision:revision,
      expected_authorization_version:before.version,grant_id:grantId,
      expected_supervisor_revision:supervisorRevision,explicit_human_confirmation:true}),
  });
  if(response.status!==200)throw Error('Native worker recovery intent UNKNOWN. No automatic retry.');
  const data=exact(strictJson(await response.text()),[
    'grant_id','supervisor_revision','recovery_intent_recorded','worker_execution_replayed',
    'independent_target_effect_verified',
  ]);
  if(data.grant_id!==grantId||data.supervisor_revision!==supervisorRevision
    ||data.recovery_intent_recorded!==true||data.worker_execution_replayed!==false
    ||data.independent_target_effect_verified!==false)
    throw Error('Native recovery acknowledgment ambiguous; no replay.');
  const after=await supervisionApi.authorizationStatus(engagementId);
  const now=currentOperator();
  if(after.status!=='active'||after.version!==before.version||after.policy_sha256!==before.policy_sha256
    ||!now||now.sub!==actor.sub||now.role!==actor.role||now.exp!==actor.exp
    ||authHeaders().Authorization!==bearer)
    throw Error('Signed authority changed after recovery request; read back, never retry automatically.');
}

/** 0033 updated_at is NOT a heartbeat. This is a READ-ONLY suspected orphan list. */
export interface NativeMcpOrphanSuspect {
  ordinal:number;
  state:'provisioned'|'running'|'terminating'|'terminated'|'unknown';
  grant_status:'issued'|'redeemed'|'unknown'|'revoked';
  age_since_last_signed_transition_seconds:number;
  classification:'suspected_orphan_unverified'|'pending_independent_recovery';
  container_destroyed_verified:false;
  execution_replay_authorized:false;
}
export interface NativeMcpOrphanSuspects {
  source:'durable_0033_last_transition_not_heartbeat';
  classification:'READ_ONLY_SUSPECT_UNVERIFIED';
  count:number;
  candidates:NativeMcpOrphanSuspect[];
  independent_process_liveness_verified:false;
  automatic_reaping_enabled:false;
  worker_state_mutated:false;
  independent_target_effect_verified:false;
}
const SUSPECT_TOP=['source','classification','count','candidates',
  'independent_process_liveness_verified','automatic_reaping_enabled',
  'worker_state_mutated','independent_target_effect_verified'];
const SUSPECT_ROW=['ordinal','state','grant_status',
  'age_since_last_signed_transition_seconds','classification',
  'container_destroyed_verified','execution_replay_authorized'];
const SUSPECT_STATES=['provisioned','running','terminating','terminated','unknown'];

function parseSuspects(raw:unknown,limit:number,minimumAgeSeconds:number):NativeMcpOrphanSuspects{
  const value=exact(raw,SUSPECT_TOP);
  if(value.source!=='durable_0033_last_transition_not_heartbeat'
    ||value.classification!=='READ_ONLY_SUSPECT_UNVERIFIED'
    ||value.independent_process_liveness_verified!==false
    ||value.automatic_reaping_enabled!==false||value.worker_state_mutated!==false
    ||value.independent_target_effect_verified!==false
    ||!Array.isArray(value.candidates)||value.candidates.length>limit
    ||!Number.isSafeInteger(value.count)||value.count!==value.candidates.length)
    throw Error('Untrusted native orphan classification: no cleanup inferred.');
  for(let i=0;i<value.candidates.length;i++){
    const item=exact(value.candidates[i],SUSPECT_ROW);
    const unresolved=['unknown','terminating'].includes(String(item.state));
    if(item.ordinal!==i+1||!SUSPECT_STATES.includes(String(item.state))
      ||!['issued','redeemed','unknown','revoked'].includes(String(item.grant_status))
      ||!Number.isSafeInteger(item.age_since_last_signed_transition_seconds)
      ||(item.age_since_last_signed_transition_seconds as number)<minimumAgeSeconds
      ||(item.age_since_last_signed_transition_seconds as number)>10*366*86400
      ||item.classification!==(unresolved?'pending_independent_recovery':'suspected_orphan_unverified')
      ||item.container_destroyed_verified!==false||item.execution_replay_authorized!==false)
      throw Error('Untrusted native SUSPECT metadata or identity leak.');
  }
  return value as unknown as NativeMcpOrphanSuspects;
}

export async function readNativeMcpOrphanSuspects(
  engagementId:string,flowId:string,revision:number,authorizationId:string,
  minimumAgeSeconds=60,limit=20,
):Promise<NativeMcpOrphanSuspects>{
  const actor=currentOperator();
  if(!actor||!['operator','senior_operator'].includes(actor.role)
    ||actor.exp===null||actor.exp*1000<=Date.now()
    ||!ENG.test(engagementId)||!FLOW.test(flowId)||!AUTH.test(authorizationId)
    ||!Number.isSafeInteger(revision)||revision<0
    ||!Number.isSafeInteger(minimumAgeSeconds)||minimumAgeSeconds<60||minimumAgeSeconds>86400
    ||!Number.isSafeInteger(limit)||limit<1||limit>32
    ||!isSecureApiBase(API_BASE)||!isSecureBrowserOrigin())
    throw Error('Current signed owner and bounded SUSPECT request required.');
  const bearer=authHeaders().Authorization;
  if(typeof bearer!=='string'||!/^Bearer \S{1,4096}$/.test(bearer))
    throw Error('Current signed bearer required.');
  const before=await supervisionApi.authorizationStatus(engagementId);
  if(before.status!=='active'||!Number.isSafeInteger(before.version)
    ||(before.version??0)<1||!SHA.test(before.policy_sha256??''))
    throw Error('Current signed ROE unavailable.');
  const query=new URLSearchParams({
    expected_engagement_id:engagementId,expected_revision:String(revision),
    expected_authorization_version:String(before.version),
    minimum_age_seconds:String(minimumAgeSeconds),limit:String(limit),
  });
  const response=await fetch(
    `${API_BASE}/flows/${encodeURIComponent(flowId)}/native-mcp-supervision/suspects?${query}`,{
      method:'GET',headers:authHeaders({Accept:'application/json'}),
      credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
    },
  );
  if(response.status!==200)throw Error('Signed native SUSPECT status unavailable; no automatic recovery.');
  const size=response.headers?.get('content-length');
  if(size&&(!/^\d+$/.test(size)||Number(size)>12000))throw Error('Native SUSPECT read exceeds bound.');
  const text=await response.text();
  if(text.length>12000)throw Error('Native SUSPECT response exceeds bound.');
  const data=parseSuspects(strictJson(text),limit,minimumAgeSeconds);
  const after=await supervisionApi.authorizationStatus(engagementId);
  const now=currentOperator();
  if(after.status!=='active'||after.version!==before.version
    ||after.policy_sha256!==before.policy_sha256
    ||!now||now.sub!==actor.sub||now.role!==actor.role||now.exp!==actor.exp
    ||authHeaders().Authorization!==bearer)
    throw Error('Signed owner/ROE changed during SUSPECT readback.');
  return data;
}
