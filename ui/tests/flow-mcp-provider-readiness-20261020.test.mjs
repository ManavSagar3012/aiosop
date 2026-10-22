import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'vite';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const originalFetch=globalThis.fetch;
const ids=['burp-mcp','recon-mcp','payload-mcp','nuclei-mcp','shodan-mcp',
  'threat-intel-mcp','security-bridge','browser-mcp','source-map-mcp',
  'cloud-mcp','turbo-intruder-mcp'];
const eng='eng-provider-inventory';
const flow='flow-provider-inventory';
const authId='signed-authorization-ref';
const sha='a'.repeat(64);
const policy={status:'active',version:4,key_id:'signed-key',policy_sha256:sha,
  expires_at:null,remote_execution_outcome:'unknown'};
const emptyRow=id=>({server_id:id,registered_in_process:false,manifest_initialized:false,
  circuit_state:'unavailable',declared_tool_count:0,prepared_actions:0,
  reserved_actions:0,unknown_actions:0,finished_actions:0,cancelled_actions:0,
  stale_prepared_declarations:0,runtime_health_verified:false,
  provider_side_signed_admission_verified:false,execution_authorized:false,
  independent_target_effect_verified:false});
const readback=()=>({engagement_id:eng,flow_id:flow,flow_revision:7,
  authorization_version:4,kind:'signed_action_and_process_inventory_unverified',
  provider_contacted:false,execution_authorized:false,
  independent_target_effect_verified:false,servers:ids.map(emptyRow)});
const reply=(data,status=200)=>new Response(JSON.stringify(data),{
  status,headers:{'content-type':'application/json'},
});
let vite,auth,svc,panel,calls=[],queue=[];
before(async()=>{
  vite=await createServer({root,appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  auth=await vite.ssrLoadModule('/src/services/api.ts');
  svc=await vite.ssrLoadModule('/src/services/flowMcpProviderReadiness.ts');
  panel=await vite.ssrLoadModule('/src/components/flows/FlowMcpProviderReadinessPanel.tsx');
});
after(async()=>{auth?.signOut();globalThis.fetch=originalFetch;await vite?.close();});
async function login(role='operator'){
  auth.signOut();calls=[];queue=[];
  globalThis.fetch=async (url,options={})=>{
    const request={url:String(url),path:new URL(String(url)).pathname,options};
    calls.push(request);
    if(request.path==='/auth/me')return reply({sub:'owner',role,exp:Math.floor(Date.now()/1000)+3600});
    if(!queue.length)throw Error('Unexpected HTTP request');
    const answer=queue.shift();
    if(answer instanceof Error)throw answer;
    return typeof answer==='function'?answer(request):answer;
  };
  await auth.signIn('signed-inventory-token');calls=[];
}
function push(...results){queue.push(...results);}
function next(){push(reply(policy),reply(readback()),reply(policy));}

test('mounted operator panel is readonly and does not claim real provider readiness',async()=>{
  const html=renderToStaticMarkup(createElement(panel.FlowMcpProviderReadinessPanel,{
    flowId:flow,engagementId:eng,revision:7,flowStatus:'running',authorizationId:authId,
  }));
  assert.match(html,/NO HTTP provider check|No HTTP provider check/);
  assert.match(html,/GET ONLY/);
  assert.doesNotMatch(html,/verified ready|PROVIDER VERIFIED|execute now/i);
  const source=readFileSync(new URL('../src/pages/FlowOperations.tsx',import.meta.url),'utf8');
  assert.match(source,/FlowMcpProviderReadinessPanel/);
});

test('signed GET joins eleven bounded rows and never sends a provider POST',async()=>{
  await login();next();
  const result=await svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId);
  assert.equal(result.servers.length,11);
  assert.equal(result.kind,'signed_action_and_process_inventory_unverified');
  assert.equal(result.execution_authorized,false);
  assert.deepEqual(calls.map(c=>c.options.method??'GET'),['GET','GET','GET']);
  const lookup=calls[1];
  assert.match(lookup.path,/\/flows\/flow-provider-inventory\/mcp-provider-readiness/);
  assert.match(lookup.url,/expected_engagement_id=eng-provider-inventory/);
  assert.equal(lookup.options.credentials,'omit');
  assert.equal(lookup.options.cache,'no-store');
  assert.equal(lookup.options.redirect,'error');
  assert.equal(lookup.options.referrerPolicy,'no-referrer');
  assert.match(lookup.options.headers.Authorization,/^Bearer /);
  assert.doesNotMatch(lookup.url,/signed-inventory-token|authorization_ref|password/);
});

test('deny forged provider-verified health/side effect and foreign server',async()=>{
  for(const fault of ['health','execution','new-key','foreign','dup-id','counter']){
    await login();
    const data=readback();
    if(fault==='health')data.servers[0].runtime_health_verified=true;
    else if(fault==='execution')data.execution_authorized=true;
    else if(fault==='new-key')data.servers[0].access_token='private';
    else if(fault==='foreign')data.servers[0].server_id='foreign-secret-server';
    else if(fault==='dup-id')data.servers[0].server_id=data.servers[1].server_id;
    else data.servers[0].unknown_actions=-1;
    push(reply(policy),reply(data));
    await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId));
  }
});

test('duplicate JSON security fields rejected even if JSON.parse would select last',async()=>{
  await login();
  push(reply(policy),new Response(JSON.stringify(readback()).replace(
    '"execution_authorized":false','"execution_authorized":true,"execution_authorized":false',
  ),{status:200}));
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId),/Duplicate/);
});

test('stale signer version or changed ROE SHA rejects otherwise valid response',async()=>{
  await login();
  push(reply(policy),reply(readback()),reply({...policy,policy_sha256:'b'.repeat(64)}));
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId));
});

test('lost signer or altered actor during await cannot receive old tenant inventory',async()=>{
  await login();
  push(reply(policy),()=>{auth.signOut();return reply(readback());});
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId));
});

test('backend HTTP refusal and transport failure fail closed without retry',async()=>{
  await login();push(reply(policy),reply({detail:'private'},503));
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId));
  assert.equal(calls.length,2);
  await login();push(reply(policy),new Error('network down'));
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId));
  assert.equal(calls.length,2);
});

test('missing operator, flow id and bad authorization id never issue HTTP',async()=>{
  auth.signOut();calls=[];
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,authId));
  assert.equal(calls.length,0);
  await login();
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,'../../foreign',7,authId));
  await assert.rejects(()=>svc.readSignedFlowMcpProviderReadiness(eng,flow,7,'!')); 
  assert.equal(calls.length,0);
});
