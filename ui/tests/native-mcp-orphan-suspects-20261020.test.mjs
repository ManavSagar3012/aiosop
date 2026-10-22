import assert from 'node:assert/strict';
import {after,before,test} from 'node:test';
import {createServer} from 'vite';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const originalFetch=globalThis.fetch;
const eng='eng-native-ledger',flow='flow-native-ledger',authId='signed-roe-ref';
const sha='a'.repeat(64);
const policy=()=>({status:'active',version:7,policy_sha256:sha,key_id:'signed-roe',
  expires_at:null,remote_execution_outcome:'unknown'});
const candidate=()=>({ordinal:1,state:'unknown',grant_status:'unknown',
  age_since_last_signed_transition_seconds:340,
  classification:'pending_independent_recovery',
  container_destroyed_verified:false,execution_replay_authorized:false});
const suspects=()=>({source:'durable_0033_last_transition_not_heartbeat',
  classification:'READ_ONLY_SUSPECT_UNVERIFIED',count:1,candidates:[candidate()],
  independent_process_liveness_verified:false,automatic_reaping_enabled:false,
  worker_state_mutated:false,independent_target_effect_verified:false});
const reply=(data,status=200)=>new Response(JSON.stringify(data),{
  status,headers:{'Content-Type':'application/json'},
});
let vite,api,service,panel,requests=[],queue=[];
before(async()=>{
  vite=await createServer({root,appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  api=await vite.ssrLoadModule('/src/services/api.ts');
  service=await vite.ssrLoadModule('/src/services/nativeMcpGrantLedger.ts');
  panel=await vite.ssrLoadModule('/src/components/flows/NativeMcpGrantLedgerPanel.tsx');
});
after(async()=>{api?.signOut();globalThis.fetch=originalFetch;await vite?.close();});

async function login(){
  api.signOut();queue=[];requests=[];
  globalThis.fetch=async(url,options={})=>{
    const req={url:String(url),path:new URL(String(url)).pathname,options};
    requests.push(req);
    if(req.path==='/auth/me')return reply({sub:'owner-signed',role:'operator',
      exp:Math.floor(Date.now()/1000)+3600});
    if(queue.length===0)throw Error('Unexpected HTTP call');
    const next=queue.shift();
    return typeof next==='function'?next(req):next;
  };
  await api.signIn('disposable-native-bearer');
  requests=[];
}
function success(value=suspects()){queue.push(reply(policy()),reply(value),reply(policy()));}
const read=(minimum=60,limit=20)=>service.readNativeMcpOrphanSuspects(
  eng,flow,2,authId,minimum,limit,
);

test('mounted Flow grant panel shows READ ONLY SUSPECT and preserves metadata-only intent',async()=>{
  const html=renderToStaticMarkup(createElement(panel.NativeMcpGrantLedgerPanel,{
    engagementId:eng,flowId:flow,revision:2,flowStatus:'running',authorizationId:authId,
  }));
  assert.match(html,/READ ONLY — SUSPECT/);
  assert.match(html,/GET ONLY/);
  assert.match(html,/NOT a heartbeat/);
  assert.match(html,/No execution replay authorized|no execution replay authorized|never runs Docker/);
  assert.doesNotMatch(html,/REAPED VERIFIED|KILL CONTAINER|RUN SCAN/);
  const code=readFileSync(new URL('../src/components/flows/NativeMcpGrantLedgerPanel.tsx',import.meta.url),'utf8');
  assert.match(code,/RECORD RECOVERY INTENT \(NO EXECUTION\)/);
  assert.match(code,/metadata-only recovery intent/i);
});

test('signed owner GET uses bounded query and pre/post ROE; no IDs or secrets',async()=>{
  await login();success();
  const result=await read(300,3);
  assert.equal(result.count,1);
  assert.equal(result.classification,'READ_ONLY_SUSPECT_UNVERIFIED');
  assert.equal(result.candidates[0].container_destroyed_verified,false);
  assert.deepEqual(requests.map(x=>x.options.method??'GET'),['GET','GET','GET']);
  const req=requests[1];
  assert.match(req.path,/\/native-mcp-supervision\/suspects$/);
  const url=new URL(req.url);
  assert.equal(url.searchParams.get('minimum_age_seconds'),'300');
  assert.equal(url.searchParams.get('limit'),'3');
  assert.equal(url.searchParams.get('expected_engagement_id'),eng);
  assert.equal(url.searchParams.get('expected_revision'),'2');
  assert.equal(url.searchParams.get('expected_authorization_version'),'7');
  assert.equal(req.options.credentials,'omit');
  assert.equal(req.options.cache,'no-store');
  assert.equal(req.options.redirect,'error');
  assert.equal(req.options.referrerPolicy,'no-referrer');
  assert.doesNotMatch(req.url,/private|bearer|signature|grant_id|worker_id|nonce/);
});

test('read-only candidates cannot include raw worker/grant/container identities',async()=>{
  for(const field of ['grant_id','worker_id','container_id','network_id','evidence_sha256',
    'path','signature','issuer_kid','epoch','supervisor_revision']){
    await login();
    const forged=suspects();forged.candidates[0][field]='private';
    queue.push(reply(policy()),reply(forged));
    await assert.rejects(read(),/Unexpected|private|Untrusted|identity/i);
    assert.equal(requests.length,2); // Never release private metadata or perform a recovery POST.
  }
});

test('claims of liveness, cleanup, reaped or execution are denied',async()=>{
  for(const kind of ['cleanup','liveness','reaped','execution','classification','age','count']){
    await login();const data=suspects(),c=data.candidates[0];
    if(kind==='cleanup')c.container_destroyed_verified=true;
    if(kind==='liveness')data.independent_process_liveness_verified=true;
    if(kind==='reaped')c.state='reaped';
    if(kind==='execution')c.execution_replay_authorized=true;
    if(kind==='classification')c.classification='orphan_verified';
    if(kind==='age')c.age_since_last_signed_transition_seconds=0;
    if(kind==='count')data.count=2;
    queue.push(reply(policy()),reply(data));
    await assert.rejects(read());
  }
});

test('reject duplicated object keys and excess response data, no retry',async()=>{
  await login();
  queue.push(reply(policy()),new Response(
    JSON.stringify(suspects()).replace('"count":1','"count":1,"count":1'),
    {status:200},
  ));
  await assert.rejects(read(),/Duplicate|private/);
  assert.equal(requests.length,2);
  await login();
  queue.push(reply(policy()),new Response(' '.repeat(12001),{status:200}));
  await assert.rejects(read(),/exceeds bound/i);
  assert.equal(requests.length,2);
});

test('current signed policy changes after awaited response fails closed',async()=>{
  await login();
  queue.push(reply(policy()),reply(suspects()),reply({...policy(),policy_sha256:'b'.repeat(64)}));
  await assert.rejects(read(),/changed during/i);
  assert.equal(requests.length,3);
});

test('revoked ROE, invalid limits and unavailable source never fetch orphan list',async()=>{
  await login();queue.push(reply({...policy(),status:'revoked'}));
  await assert.rejects(read(),/ROE unavailable/);
  assert.equal(requests.length,1);
  await login();await assert.rejects(read(59),/bounded SUSPECT/);
  assert.equal(requests.length,0);
  await login();await assert.rejects(read(60,33),/bounded SUSPECT/);
  assert.equal(requests.length,0);
  await login();queue.push(reply(policy()),reply({status:'unknown'},503));
  await assert.rejects(read(),/unavailable/);
  assert.equal(requests.length,2);
});
