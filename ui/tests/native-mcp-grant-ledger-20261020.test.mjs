import assert from 'node:assert/strict';
import {after,before,test} from 'node:test';
import {createServer} from 'vite';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const originalFetch=globalThis.fetch;
const eng='eng-native-ledger';
const flow='flow-native-ledger';
const authRef='signed-roe-ref';
const roeSha='c'.repeat(64);
const policy={status:'active',version:7,policy_sha256:roeSha,key_id:'signed-roe',
  expires_at:null,remote_execution_outcome:'unknown'};
const grant=()=>({grant_id:`ngr-${'1'.repeat(32)}`,action_id:`action-${'2'.repeat(32)}`,
  request_id:`req-${'3'.repeat(48)}`,server_id:'recon-mcp',tool_name:'authority_status',
  status:'redeemed',issued_at:1761000000,expires_at:1761000030,
  reviewed_resource_bound:false,resource_bytes_checked_at_redemption:false,
  original_resource_bytes_offered_once:false,
  approved_folder_staging_bound:false,worker_stage_receipt_reported:false,
  supervisor_lifecycle_observed:false,supervisor_state:null,supervisor_revision:null,
  supervisor_cleanup_observed:false,supervisor_recovery_required:false,
  supervisor_recovery_intent_pending:false});
// 0031 pinned folder and 0032 worker testimony are distinctly historical.
const ledger=()=>({engagement_id:eng,flow_id:flow,flow_revision:2,authorization_version:7,
  source:'durable_native_grants',server_side_signed_authorization_verified:false,
  independent_target_effect_verified:false,grants:[grant()]});
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json'}});
let vite,auth,service,panel,requests=[],pending=[];
before(async()=>{
  vite=await createServer({root,appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  auth=await vite.ssrLoadModule('/src/services/api.ts');
  service=await vite.ssrLoadModule('/src/services/nativeMcpGrantLedger.ts');
  panel=await vite.ssrLoadModule('/src/components/flows/NativeMcpGrantLedgerPanel.tsx');
});
after(async()=>{auth?.signOut();globalThis.fetch=originalFetch;await vite?.close();});
async function login(){
  auth.signOut();pending=[];requests=[];
  globalThis.fetch=async(url,options={})=>{
    const req={url:String(url),path:new URL(String(url)).pathname,options};requests.push(req);
    if(req.path==='/auth/me')return reply({sub:'flow-owner',role:'operator',exp:Math.floor(Date.now()/1000)+3600});
    if(!pending.length)throw Error('Unexpected native grant HTTP call');
    const value=pending.shift();
    if(value instanceof Error)throw value;
    return typeof value==='function'?value(req):value;
  };
  await auth.signIn('native-grant-test-bearer');requests=[];
}
function queue(...items){pending.push(...items);}
function good(){queue(reply(policy),reply(ledger()),reply(policy));}
const read=()=>service.readNativeMcpGrantLedger(eng,flow,2,authRef);

test('real selected Flow panel is inert, mounted, and does not offer grant issuance',async()=>{
  const html=renderToStaticMarkup(createElement(panel.NativeMcpGrantLedgerPanel,{
    engagementId:eng,flowId:flow,revision:2,flowStatus:'running',authorizationId:authRef,
  }));
  assert.match(html,/GET ONLY/);
  assert.match(html,/no approval|no automatic retry/i);
  assert.doesNotMatch(html,/EXECUTE NATIVE|ISSUE TOKEN|APPROVE GRANT/);
  assert.match(readFileSync(new URL('../src/pages/FlowOperations.tsx',import.meta.url),'utf8'),
    /NativeMcpGrantLedgerPanel/);
});

test('owner performs strictly signed GET before/after and receives provider-only history',async()=>{
  await login();good();
  const result=await read();
  assert.equal(result.grants[0].status,'redeemed');
  assert.equal(result.independent_target_effect_verified,false);
  assert.equal(result.server_side_signed_authorization_verified,false);
  assert.deepEqual(requests.map(r=>r.options.method??'GET'),['GET','GET','GET']);
  assert.match(requests[1].path,/\/flows\/flow-native-ledger\/native-mcp-grants/);
  assert.match(requests[1].url,/expected_authorization_version=7/);
  assert.doesNotMatch(requests[1].url,/native-grant-test-bearer|private/);
  assert.equal(requests[1].options.credentials,'omit');
  assert.equal(requests[1].options.redirect,'error');
});

test('reviewed bytes display is historical, inert and cannot be forged independently',async()=>{
  await login();const data=ledger();
  data.grants[0].reviewed_resource_bound=true;
  data.grants[0].resource_bytes_checked_at_redemption=true;
  data.grants[0].original_resource_bytes_offered_once=true;
  queue(reply(policy),reply(data),reply(policy));
  const accepted=await read();
  assert.equal(accepted.grants[0].resource_bytes_checked_at_redemption,true);
  assert.equal(accepted.grants[0].original_resource_bytes_offered_once,true);
  const panelSource=readFileSync(new URL('../src/components/flows/NativeMcpGrantLedgerPanel.tsx',import.meta.url),'utf8');
  assert.match(panelSource,/not staged or executed|no resource staging/i);
  await login();const forged=ledger();
  forged.grants[0].resource_bytes_checked_at_redemption=true;
  forged.grants[0].original_resource_bytes_offered_once=true;
  queue(reply(policy),reply(forged));
  await assert.rejects(read,/Untrusted|private/);
  await login();const extra=ledger();
  extra.grants[0].resource_sha256='f'.repeat(64);
  queue(reply(policy),reply(extra));
  await assert.rejects(read,/Unexpected|private/);
});

test('0032 Ed25519 worker testimony is separate from 0031 folder approval, never a target effect',async()=>{
  await login();const data=ledger(), r=data.grants[0];
  r.reviewed_resource_bound=true;r.resource_bytes_checked_at_redemption=true;
  r.original_resource_bytes_offered_once=true;
  r.approved_folder_staging_bound=true;r.worker_stage_receipt_reported=true;
  queue(reply(policy),reply(data),reply(policy));
  const accepted=await read();
  assert.equal(accepted.grants[0].worker_stage_receipt_reported,true);
  assert.equal(accepted.independent_target_effect_verified,false);
  const source=readFileSync(new URL('../src/components/flows/NativeMcpGrantLedgerPanel.tsx',import.meta.url),'utf8');
  assert.match(source,/worker testimony, not independent OS sandbox attestation/i);
  await login();const forged=ledger();
  forged.grants[0].worker_stage_receipt_reported=true;
  queue(reply(policy),reply(forged));
  await assert.rejects(read,/Untrusted|private/);
});

test('0033 signed supervisor cleanup readback is distinct from worker self-report',async()=>{
  await login();const data=ledger();const row=data.grants[0];
  row.supervisor_lifecycle_observed=true;
  row.supervisor_state='reaped';row.supervisor_revision=4;row.supervisor_cleanup_observed=true;
  queue(reply(policy),reply(data),reply(policy));
  const accepted=await read();
  assert.equal(accepted.grants[0].worker_stage_receipt_reported,false);
  assert.equal(accepted.grants[0].supervisor_cleanup_observed,true);
  assert.equal(accepted.independent_target_effect_verified,false);
  await login();const forged=ledger();
  forged.grants[0].supervisor_cleanup_observed=true;
  queue(reply(policy),reply(forged));
  await assert.rejects(read,/Untrusted|private/);
  await login();const unsafe=ledger();unsafe.grants[0].container_id='secret-host-path';
  queue(reply(policy),reply(unsafe));
  await assert.rejects(read,/Unexpected|private/);
});

test('operator 0033 recovery is metadata-only POST, explicit confirmation, never automatic replay',async()=>{
  await login();
  const row=grant();row.supervisor_lifecycle_observed=true;
  row.supervisor_state='unknown';row.supervisor_revision=4;
  row.supervisor_recovery_required=true;
  const acknowledged={grant_id:row.grant_id,supervisor_revision:4,
    recovery_intent_recorded:true,worker_execution_replayed:false,
    independent_target_effect_verified:false};
  queue(reply(policy),reply(acknowledged),reply(policy));
  await service.requestNativeWorkerRecoveryIntent(eng,flow,2,authRef,row.grant_id,4);
  assert.deepEqual(requests.map(r=>r.options.method),['GET','POST','GET']);
  assert.match(requests[1].path,/native-mcp-supervision\/recovery/);
  const request=JSON.parse(requests[1].options.body);
  assert.equal(request.explicit_human_confirmation,true);
  assert.equal(request.expected_supervisor_revision,4);
  assert.equal(request.grant_id,row.grant_id);
  assert.doesNotMatch(requests[1].url,/private|grant-token|worker-secret/);
  await login();queue(reply(policy),reply({ ...acknowledged,worker_execution_replayed:true }));
  await assert.rejects(()=>service.requestNativeWorkerRecoveryIntent(eng,flow,2,authRef,row.grant_id,4),/ambiguous/i);
  assert.equal(requests.length,2); // never automatically repeats a failed request
  const panelSource=readFileSync(new URL('../src/components/flows/NativeMcpGrantLedgerPanel.tsx',import.meta.url),'utf8');
  assert.match(panelSource,/RECORD RECOVERY INTENT \(NO EXECUTION\)/);
  assert.match(panelSource,/No worker relaunch, native replay/);
});

test('stale signature policy SHA after awaited GET denies readback',async()=>{
  await login();queue(reply(policy),reply(ledger()),reply({...policy,policy_sha256:'d'.repeat(64)}));
  await assert.rejects(read);
});

test('revoked or expired ROE before GET never reaches grant endpoint',async()=>{
  await login();queue(reply({...policy,status:'revoked'}));
  await assert.rejects(read);
  assert.equal(requests.length,1);
});

test('rejects untrusted private or executable metadata',async()=>{
  for(const invalid of ['secret','foreign','verified','tool','extra','expiry']){
    await login();const bad=ledger();
    if(invalid==='secret')bad.grants[0].signature='PRIVATE_SIGNER';
    if(invalid==='foreign')bad.flow_id='flow-foreign';
    if(invalid==='verified')bad.independent_target_effect_verified=true;
    if(invalid==='tool')bad.grants[0].tool_name='scan';
    if(invalid==='extra')bad.grants[0].metadata={private:'data'};
    if(invalid==='expiry')bad.grants[0].expires_at+=999;
    queue(reply(policy),reply(bad));
    await assert.rejects(read);
  }
});

test('duplicate grant IDs and ambiguous JSON keys rejected before displaying',async()=>{
  await login();const bad=ledger();bad.grants.push({...grant()});queue(reply(policy),reply(bad));
  await assert.rejects(read);
  await login();
  const duplicated=JSON.stringify(ledger()).replace(
    '"independent_target_effect_verified":false',
    '"independent_target_effect_verified":true,"independent_target_effect_verified":false');
  queue(reply(policy),new Response(duplicated,{status:200}));
  await assert.rejects(read,/Duplicate/);
});

test('backend 503, lost ACK or transport failure never triggers automatic replay',async()=>{
  await login();queue(reply(policy),reply({detail:'secret-private'},503));
  await assert.rejects(read);assert.equal(requests.length,2);
  await login();queue(reply(policy),new Error('disconnected'));
  await assert.rejects(read);assert.equal(requests.length,2);
});

test('switching signed operator after request denies stale history',async()=>{
  await login();queue(reply(policy),()=>{auth.signOut();return reply(ledger());});
  await assert.rejects(read);
});

test('malformed Flow or missing bearer never contacts backend',async()=>{
  auth.signOut();requests=[];
  await assert.rejects(read);assert.equal(requests.length,0);
  await login();
  await assert.rejects(()=>service.readNativeMcpGrantLedger(eng,'../../foreign',2,authRef));
  await assert.rejects(()=>service.readNativeMcpGrantLedger(eng,flow,2,'!'));
  assert.equal(requests.length,0);
});
