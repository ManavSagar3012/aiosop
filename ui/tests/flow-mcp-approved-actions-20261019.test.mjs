import assert from 'node:assert/strict';
import {test,before,after} from 'node:test';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {createServer} from 'vite';

const root=fileURLToPath(new URL('../',import.meta.url));
const originalFetch=globalThis.fetch;
const flowId='flow-signed-mcp-actions';
const engagementId='eng-signed-mcp-actions';
const taskId='task-signed-mcp-actions';
const subtaskId='subtask-signed-mcp-actions';
const actionId=`action-${'a'.repeat(32)}`;
const signed={
  flowId,engagementId,flowRevision:7,authorizationVersion:5,
  authorizationId:'signed-roe',authorizationSha256:'f'.repeat(64),
};
const base={
  action_id:actionId,flow_id:flowId,engagement_id:engagementId,task_id:taskId,
  subtask_id:subtaskId,server_id:'browser_mcp',tool_name:'get_status',
  status:'prepared',parameters_sha256:'a'.repeat(64),execution_started:false,
  target_effect_verified:false,safe_to_automatically_retry:false,
};
let vite,auth,service,panel,calls,queued;
const reply=(body,status=200)=>new Response(JSON.stringify(body),{
  status,headers:{'content-type':'application/json'},
});
before(async()=>{
  vite=await createServer({root,appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  auth=await vite.ssrLoadModule('/src/services/api.ts');
  service=await vite.ssrLoadModule('/src/services/flowMcpActions.ts');
  panel=await vite.ssrLoadModule('/src/components/flows/FlowMcpActionsPanel.tsx');
});
after(async()=>{auth?.signOut();globalThis.fetch=originalFetch;await vite?.close();});
async function login(sub='action-owner'){
  auth.signOut();calls=[];queued=[];
  globalThis.fetch=async(url,options={})=>{
    const path=new URL(String(url)).pathname;
    calls.push({url:String(url),path,options});
    if(path==='/auth/me')return reply({sub,role:'operator',exp:Math.floor(Date.now()/1000)+3600});
    if(!queued.length)throw new Error('Unqueued HTTP request');
    const next=queued.shift();
    if(next instanceof Error)throw next;
    return typeof next==='function'?next():next;
  };
  await auth.signIn('signed-tab-action-token');calls=[];
}
function queue(...responses){queued.push(...responses);}
function prepareInput(serverId='browser_mcp',toolName='get_status'){
  return {taskId,subtaskId,serverId,toolName,parameters:{},confirmed:true};
}
function listing(...actions){
  return {flow_id:flowId,engagement_id:engagementId,flow_revision:7,authorization_version:5,actions};
}

test('Flow action UI is separate from inert review marker, human approval never inferred',async()=>{
  await login();
  const markup=renderToStaticMarkup(createElement(panel.FlowMcpActionsPanel,{
    flowId,engagementId,revision:7,flowStatus:'pending',authorizationId:'signed-roe',
  }));
  assert.match(markup,/independently approved current Task\/Subtask\/Action/);
  assert.match(markup,/READ SIGNED ACTION LEDGER \(NO EXECUTION\)/);
  assert.doesNotMatch(markup,/signed-tab-action-token/);
  const source=readFileSync(new URL('../src/pages/FlowOperations.tsx',import.meta.url),'utf8');
  assert.match(source,/<FlowMcpActionsPanel/);
  assert.match(source,/<McpToolCatalogPanel/);
});
test('GET signed list carries tenant Flow revision/ROE and rejects duplicate identities',async()=>{
  await login();
  queue(reply(listing(base)));
  const result=await service.listFlowMcpActions(signed);
  assert.deepEqual(result,[base]);
  assert.equal(calls.length,1);
  assert.equal(calls[0].path,`/flows/${flowId}/mcp-actions`);
  const q=new URL(calls[0].url).searchParams;
  assert.equal(q.get('expected_engagement_id'),engagementId);
  assert.equal(q.get('expected_revision'),'7');
  assert.equal(q.get('expected_authorization_version'),'5');
  assert.equal(calls[0].options.headers.Authorization,'Bearer signed-tab-action-token');
  assert.equal(calls[0].options.cache,'no-store');
  assert.equal(calls[0].options.credentials,'omit');
  assert.doesNotMatch(calls[0].url,/signed-tab-action-token/);
  queue(reply(listing(base,base)));
  await assert.rejects(service.listFlowMcpActions(signed),/Duplicate/);
});
test('prepare creates only PREPARED signed Task action then independent GET, never executes',async()=>{
  await login();
  queue(reply(base,201),reply(base));
  const recorded=await service.prepareFlowMcpAction(signed,prepareInput());
  assert.equal(recorded.status,'prepared');
  assert.equal(calls.length,2);
  assert.equal(calls[0].options.method,'POST');
  assert.equal(calls[1].options.method,'GET');
  assert.deepEqual(JSON.parse(calls[0].options.body),{
    expected_engagement_id:engagementId,expected_revision:7,expected_authorization_version:5,
    task_id:taskId,subtask_id:subtaskId,server_id:'browser_mcp',tool_name:'get_status',
    parameters:{},explicit_human_confirmation:true,
  });
  assert.doesNotMatch(calls[0].options.body,/approval_id|approved\":true|mcp_action_id/);
  await assert.rejects(service.prepareFlowMcpAction(signed,prepareInput()),/already attempted/);
  assert.equal(calls.length,2);
});
test('dispatch is separate confirmed one-shot POST, provider result still unverified',async()=>{
  await login();
  const completed={...base,status:'finished',execution_started:true};
  queue(reply(completed),reply(completed));
  const actual=await service.dispatchFlowMcpAction(signed,actionId,true);
  assert.equal(actual.status,'finished');
  assert.equal(actual.target_effect_verified,false);
  assert.equal(calls[0].path,`/flows/${flowId}/mcp-actions/${actionId}/dispatch`);
  assert.deepEqual(JSON.parse(calls[0].options.body),{
    expected_engagement_id:engagementId,expected_revision:7,
    expected_authorization_version:5,explicit_human_confirmation:true,
  });
  assert.equal(calls[1].path,`/flows/${flowId}/mcp-actions/${actionId}`);
  await assert.rejects(service.dispatchFlowMcpAction(signed,actionId,true),/already attempted/);
  assert.equal(calls.length,2);
});
test('forged verified result, foreign Flow, private token or malformed digest denied',async()=>{
  await login();
  queue(reply({...base,target_effect_verified:true}));
  await assert.rejects(service.readFlowMcpAction(signed,actionId),/unverified/);
  queue(reply({...base,flow_id:'flow-other-owner'}));
  await assert.rejects(service.readFlowMcpAction(signed,actionId),/private|Forged/i);
  queue(reply({...base,headers:{Authorization:'Bearer stolen'}}));
  // Confidential fields have not been approved for public readback.
  await assert.rejects(service.readFlowMcpAction(signed,actionId),/private|Forged/i);
  queue(reply({...base,parameters_sha256:'not-sha'}));
  await assert.rejects(service.readFlowMcpAction(signed,actionId),/private|Forged/i);
});
test('invalid body, secret fields, traversal and unsafe target deny before POST',async()=>{
  await login();
  await assert.rejects(service.prepareFlowMcpAction(signed,{
    ...prepareInput(),parameters:{'api_key':'secret'},
  }),/forbidden/);
  await assert.rejects(service.prepareFlowMcpAction(signed,{
    ...prepareInput(),parameters:{target:'http://example.test/path'},
  }),/HTTPS/);
  await assert.rejects(service.prepareFlowMcpAction(signed,{
    ...prepareInput(),parameters:{target:'https://user:pass@example.test/path'},
  }),/HTTPS/);
  await assert.rejects(service.prepareFlowMcpAction(signed,{
    ...prepareInput(),toolName:'../escape',
  }),/confirmation/);
  assert.equal(calls.length,0);
});
test('ambiguous ACK stays UNKNOWN and never automatically replays request',async()=>{
  await login();
  const uncertainId=`action-${'b'.repeat(32)}`;
  queue(new Error('Lost response'));
  await assert.rejects(service.dispatchFlowMcpAction(signed,uncertainId,true),/Lost response/);
  assert.equal(calls.length,1);
  await assert.rejects(service.dispatchFlowMcpAction(signed,uncertainId,true),/already attempted/);
  assert.equal(calls.length,1);
  queue(reply({...base,action_id:uncertainId,status:'unknown',execution_started:true}));
  const saved=await service.readFlowMcpAction(signed,uncertainId);
  assert.equal(saved.status,'unknown');
  assert.equal(saved.safe_to_automatically_retry,false);
});
test('signed list denies stale flow, switched bearer and invalid server response',async()=>{
  await login();
  queue(reply(listing(base, {...base,action_id:`action-${'c'.repeat(32)}`})));
  assert.equal((await service.listFlowMcpActions(signed)).length,2);
  queue(async()=>{auth.signOut();return reply(listing(base));});
  await assert.rejects(service.listFlowMcpActions(signed),/changed/);
  await login();
  queue(reply({...listing(base),authorization_version:6}));
  await assert.rejects(service.listFlowMcpActions(signed),/Stale/);
});

test('original signed provider-status receipt reconciliation is separate, one-shot and never MCP replay',async()=>{
  await login();
  const unknownAction={...base,action_id:`action-${'d'.repeat(32)}`,status:'unknown',
    request_id:`req-${'e'.repeat(48)}`,execution_started:true};
  const payload={request_id:unknownAction.request_id,engagement_id:engagementId,task_id:taskId,
    server_id:'browser_mcp',status:'completed',verified:true,stopped:false,
    issued_at:Math.floor(Date.now()/1000),attestation:{kid:'provider',signature:'s'.repeat(86)}};
  const finished={...unknownAction,status:'finished'};
  queue(reply(finished),reply(finished));
  const result=await service.reconcileSignedMcpAction(signed,unknownAction,JSON.stringify(payload),true);
  assert.equal(result.status,'finished');
  assert.equal(result.target_effect_verified,false);
  assert.equal(calls.length,2);
  assert.equal(calls[0].path,`/flows/${flowId}/mcp-actions/${unknownAction.action_id}/reconcile`);
  assert.equal(calls[1].options.method,'GET');
  assert.deepEqual(JSON.parse(calls[0].options.body),{
    expected_engagement_id:engagementId,expected_revision:7,expected_authorization_version:5,
    explicit_human_confirmation:true,provider_receipt:payload,
  });
  await assert.rejects(service.reconcileSignedMcpAction(signed,unknownAction,JSON.stringify(payload),true),/already attempted/);
  assert.equal(calls.length,2);
});
test('foreign signed receipt and fake success cannot become provider or target verification',async()=>{
  await login();
  const unknownAction={...base,action_id:`action-${'f'.repeat(32)}`,status:'unknown',
    request_id:`req-${'a'.repeat(48)}`,execution_started:true};
  const payload={request_id:unknownAction.request_id,engagement_id:engagementId,task_id:taskId,
    server_id:'browser_mcp',status:'completed',verified:true,stopped:false,
    issued_at:Math.floor(Date.now()/1000),attestation:{kid:'provider',signature:'s'.repeat(86)}};
  await assert.rejects(service.reconcileSignedMcpAction(signed,unknownAction,
    JSON.stringify({...payload,task_id:'task-foreign'}),true),/mismatched|Unsigned/);
  await assert.rejects(service.reconcileSignedMcpAction(signed,unknownAction,
    JSON.stringify({...payload,verified:false}),true),/Unsigned/);
  assert.equal(calls.length,0);
});
