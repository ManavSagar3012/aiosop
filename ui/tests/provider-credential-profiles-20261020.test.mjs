import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const flowId = 'flow-credential-ref';
const engagementId = 'eng-credential-ref';
const authorizationId = 'authorized-roe';
const authorizationSha256 = 'a'.repeat(64);
const policySha256 = 'b'.repeat(64);
const referenceSha256 = 'c'.repeat(64);
const reviewId = `provider-review-${'d'.repeat(32)}`;
const refId = `pcref-${'e'.repeat(32)}`;
const scope = {
  flowId, engagementId, flowRevision: 7, authorizationVersion: 5,
  authorizationId, authorizationSha256,
};
const status = {
  status:'active', version:5, policy_sha256:authorizationSha256,
  expires_at:null, key_id:'roe-signer', remote_execution_outcome:'unknown',
};
const record = {
  ref_id:refId, engagement_id:engagementId, flow_id:flowId,
  provider:'openai', slot:'primary', policy_review_id:reviewId,
  policy_sha256:policySha256, reference_sha256:referenceSha256,
  reference_revision:1, generation:1, status:'pending',
  flow_revision:7, authorization_version:5, authorization_id:authorizationId,
  authorization_sha256:authorizationSha256, senior_reviewed:false,
  created_at:'2026-10-20T00:00:00+00:00', updated_at:'2026-10-20T00:00:00+00:00',
  credentials_stored:false, credential_available_verified:false,
  credential_rotated:false, execution_enabled:false, provider_contacted:false,
  route_activated:false, server_reference_only:true,
  policy_current_approval_verified:false, status_is_historical_review_only:true,
};
const proposal = {
  provider:'openai', slot:'primary', policyReviewId:reviewId,
  policySha256, confirmed:true,
};
const reply = (data, statusCode = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status:statusCode, headers:{'content-type':'application/json', ...headers},
  });
const asMutation = row => ({...row, operation_recorded:true, idempotent_replay:false});
let vite, auth, service, panel, calls=[], responses=[];

before(async () => {
  vite = await createServer({root,appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/providerCredentialProfiles.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/ProviderCredentialProfilesPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});
async function login(role='operator', sub='flow-owner') {
  auth.signOut();
  calls=[]; responses=[];
  globalThis.fetch = async (raw, options={}) => {
    const request = {url:String(raw),path:new URL(String(raw)).pathname,options};
    calls.push(request);
    if (request.path==='/auth/me') {
      return reply({sub,role,exp:Math.floor(Date.now()/1000)+3600});
    }
    if (!responses.length) throw new Error('Unexpected request beyond explicit test queue');
    const next=responses.shift();
    if (next instanceof Error) throw next;
    return typeof next==='function' ? next(request) : next;
  };
  await auth.signIn('signed-credential-bearer');
  calls=[];
}
const queue=(...items)=>responses.push(...items);
const signed=()=>reply(status);
const sentPost=()=>calls.filter(entry=>entry.options.method==='POST');
function queueWrite(after, statusCode=200) {
  // ROE GET before POST, POST, ROE GET, ROE GET before durable detail,
  // detail, ROE GET, final ROE GET.
  queue(signed(),reply(asMutation(after),statusCode),signed(),
    signed(),reply(after),signed(),signed());
}
function queueRead(body) { queue(signed(),reply(body),signed()); }

test('named profile panel clearly disclaims secrets, provider calls and activation',async()=>{
  await login();
  const html=renderToStaticMarkup(createElement(panel.ProviderCredentialProfilesPanel,{
    flowId,engagementId,revision:7,flowStatus:'running',authorizationId,
  }));
  assert.match(html,/credential alias references — nonsecret operator workflow/i);
  assert.match(html,/metadata only/);
  assert.match(html,/NEVER verified/);
  assert.match(html,/REFRESH SIGNED REFERENCES \(GET ONLY\)/);
  assert.doesNotMatch(html,/signed-credential-bearer/);
});

test('scope derives live active signer and rejects revoked signer, no arbitrary version',async()=>{
  await login();
  queue(signed());
  assert.deepEqual(
    await service.readCredentialScope(flowId,engagementId,7,authorizationId),scope);
  assert.equal(calls.length,1);
  queue(reply({...status,status:'revoked'}));
  await assert.rejects(
    service.readCredentialScope(flowId,engagementId,7,authorizationId),
    /authorization unavailable/i);
});

test('metadata-only GET list uses 5 exact signed query fences, bearer only header, strict pagination',async()=>{
  await login();
  queueRead({items:[record],has_more:false});
  const answer=await service.providerCredentialProfiles.list(scope);
  assert.deepEqual(answer,{items:[record],has_more:false});
  assert.equal(calls.length,3);
  const request=calls[1];
  assert.equal(request.path,`/flows/${flowId}/provider-credential-profile-refs`);
  assert.equal(request.options.method,'GET');
  assert.equal(request.options.headers.Authorization,'Bearer signed-credential-bearer');
  assert.equal(request.options.credentials,'omit');
  assert.equal(request.options.cache,'no-store');
  assert.equal(request.options.redirect,'error');
  assert.equal(request.options.referrerPolicy,'no-referrer');
  const q=new URL(request.url).searchParams;
  assert.deepEqual([...q.keys()].sort(),[
    'expected_engagement_id','expected_revision','expected_authorization_version',
    'expected_authorization_id','expected_authorization_sha256','limit','offset',
  ].sort());
  assert.equal(q.get('expected_authorization_id'),authorizationId);
  assert.equal(q.get('expected_authorization_sha256'),authorizationSha256);
  assert.equal(q.get('limit'),'20');
  assert.equal(q.get('offset'),'0');
  assert.doesNotMatch(request.url,/signed-credential-bearer|Bearer|api_key|secret/i);
});

test('GET exact detail uses redacted strict profile reference, no other data fields',async()=>{
  await login();
  queueRead(record);
  assert.deepEqual(await service.providerCredentialProfiles.get(scope,refId),record);
  assert.equal(calls[1].path,`/flows/${flowId}/provider-credential-profile-refs/${refId}`);
  assert.equal(sentPost().length,0);
});

test('register metadata-only reference POST201 then independent GET; no credential bytes',async()=>{
  await login();
  queueWrite(record,201);
  const answer=await service.providerCredentialProfiles.register(scope,proposal);
  assert.equal(answer.status,'pending');
  assert.equal(answer.server_reference_only,true);
  assert.equal(answer.credential_available_verified,false);
  assert.equal(sentPost().length,1);
  const post=sentPost()[0];
  const posted=JSON.parse(post.options.body);
  assert.deepEqual(Object.keys(posted).sort(),[
    'operation','operation_id','provider','slot','policy_review_id','policy_sha256',
  ].sort());
  assert.equal(posted.operation,'register');
  assert.match(posted.operation_id,/^pcop-[0-9a-f]{32}$/);
  assert.equal(posted.policy_review_id,reviewId);
  assert.doesNotMatch(post.options.body,/api_key|password|token|secret|vault|env|raw/i);
  // A new random id never turns a lost POST into a safe replay.
  queue(signed());
  await assert.rejects(service.providerCredentialProfiles.register(scope,proposal),/previously attempted/i);
  assert.equal(sentPost().length,1);
});

test('rotate approved reference advances generation, removes review, never rotates a key',async()=>{
  await login();
  const approved={...record,status:'approved',senior_reviewed:true,reference_revision:2};
  const rotated={...approved,status:'pending',senior_reviewed:false,reference_revision:3,
    generation:2,reference_sha256:'9'.repeat(64)};
  queueWrite(rotated);
  const actual=await service.providerCredentialProfiles.rotate(scope,approved,proposal);
  assert.equal(actual.status,'pending');
  assert.equal(actual.generation,2);
  assert.equal(actual.credential_rotated,false);
  assert.deepEqual(JSON.parse(sentPost()[0].options.body),{
    operation:'rotate',operation_id:JSON.parse(sentPost()[0].options.body).operation_id,
    ref_id:refId,expected_ref_revision:2,provider:'openai',slot:'primary',
    policy_review_id:reviewId,policy_sha256:policySha256,
  });
  await assert.rejects(
    service.providerCredentialProfiles.rotate(scope,record,proposal),/exact approved/i);
  assert.equal(sentPost().length,1);
});

test('independent delegated senior approval is signed metadata only, never activated',async()=>{
  await login('senior_operator','different-senior');
  const approved={...record,status:'approved',senior_reviewed:true,reference_revision:2};
  queueWrite(approved);
  const actual=await service.providerCredentialProfiles.decide(
    scope,record,'approve','Independent bounded alias review',true);
  assert.equal(actual.status,'approved');
  assert.equal(actual.route_activated,false);
  assert.equal(actual.execution_enabled,false);
  const payload=JSON.parse(sentPost()[0].options.body);
  assert.equal(payload.operation,'approve');
  assert.equal(payload.expected_ref_revision,1);
  assert.equal(payload.reason,'Independent bounded alias review');
  assert.match(payload.operation_id,/^pcop-[0-9a-f]{32}$/);
});

test('senior revoke pending/approved requires exact revision, records only revoked alias',async()=>{
  await login('senior_operator','different-senior');
  const approved={...record,status:'approved',senior_reviewed:true,reference_revision:2};
  const revoked={...approved,status:'revoked',senior_reviewed:true,reference_revision:3};
  queueWrite(revoked);
  const result=await service.providerCredentialProfiles.decide(
    scope,approved,'revoke','Distinct bounded revocation review',true);
  assert.equal(result.status,'revoked');
  assert.equal(result.credentials_stored,false);
  assert.equal(JSON.parse(sentPost()[0].options.body).operation,'revoke');
});

test('review requires senior, bounded nonsecret reason and no local fake senior approval',async()=>{
  await login();
  await assert.rejects(
    service.providerCredentialProfiles.decide(scope,record,'approve','Separate review text',true),
    /senior reviewer/i);
  assert.equal(calls.length,0);
  await login('senior_operator');
  for(const reason of ['short','send sk-live-12345','include api_key','provide secret token',
    'http://private.example/internal','a'.repeat(161)]) {
    await assert.rejects(
      service.providerCredentialProfiles.decide(scope,record,'approve',reason,true),
      /reason|required|non-secret|bounded/i);
  }
  assert.equal(calls.length,0);
});

test('foreign Flow, missing or forged unsafe booleans, secret/private payloads fail closed',async()=>{
  const forged=[
    {...record,flow_id:'flow-foreign'},
    {...record,authorization_sha256:'f'.repeat(64)},
    {...record,reference_sha256:'INVALID'},
    {...record,credentials_stored:true},
    {...record,credential_available_verified:true},
    {...record,credential_rotated:true},
    {...record,execution_enabled:true},
    {...record,provider_contacted:true},
    {...record,route_activated:true},
    {...record,server_reference_only:false},
    {...record,status:'approved',senior_reviewed:false},
    {...record,api_key:'sk-live-do-not-leak'},
    {...record,raw_credentials:{secret:'private'}},
  ];
  for(const data of forged) {
    await login();
    queueRead({items:[data],has_more:false});
    await assert.rejects(service.providerCredentialProfiles.list(scope),/Untrusted|private|forged/i);
    assert.equal(sentPost().length,0);
  }
});

test('POST forged idempotent replay, missing operation acknowledgment and false activation DENIED',async()=>{
  const mutations=[
    {...asMutation(record),idempotent_replay:true},
    {...record,idempotent_replay:false},
    {...asMutation(record),route_activated:true},
    {...asMutation(record),raw_key:'opaque'},
    {...asMutation(record),server_reference_only:false},
    {...asMutation(record),policy_current_approval_verified:true},
    {...asMutation(record),status_is_historical_review_only:false},
  ];
  for(const [index,mutation] of mutations.entries()) {
    await login('operator',`forged-actor-${index}`);
    queue(signed(),reply(mutation,201),signed());
    await assert.rejects(service.providerCredentialProfiles.register(scope,proposal),
      /forged|Unexpected|Untrusted/i);
    assert.equal(sentPost().length,1);
  }
});

test('malformed duplicate JSON fields or unsafe size fail without accepting server data',async()=>{
  await login();
  const doubled=JSON.stringify({items:[record],has_more:false}).replace(
    '"has_more":false','"has_more":true,"has_more":false');
  queue(signed(),new Response(doubled,{
    status:200,headers:{'content-type':'application/json'},
  }));
  await assert.rejects(service.providerCredentialProfiles.list(scope),/Duplicate/);
  await login();
  queue(signed(),reply({items:[record],has_more:false,private:'x'.repeat(35000)}));
  await assert.rejects(service.providerCredentialProfiles.list(scope),/size bound/);
  await login();
  queue(signed(),new Response('<html>bad</html>',{
    status:200,headers:{'content-type':'text/html'},
  }));
  await assert.rejects(service.providerCredentialProfiles.list(scope),/not bounded JSON/);
});

test('operator sign-out and signed authorization drift during response invalidate everything',async()=>{
  await login();
  queue(signed(),()=>{auth.signOut();return reply({items:[record],has_more:false});});
  await assert.rejects(service.providerCredentialProfiles.list(scope),/identity changed/);
  await login();
  queue(signed(),reply({items:[record],has_more:false}),
    reply({...status,version:6}));
  await assert.rejects(service.providerCredentialProfiles.list(scope),/ROE revoked or changed/);
});

test('ambiguous 503 or lost POST remains UNKNOWN with one attempt, no automatic retry',async()=>{
  await login('operator','unconfirmed-actor-1');
  queue(signed(),reply({detail:'unavailable'},503));
  await assert.rejects(service.providerCredentialProfiles.register(scope,proposal),/outcome UNKNOWN/);
  assert.equal(sentPost().length,1);
  queue(signed());
  await assert.rejects(service.providerCredentialProfiles.register(scope,proposal),/previously attempted/);
  assert.equal(sentPost().length,1);
  await login('operator','unconfirmed-actor-2');
  queue(signed(),new Error('Lost commit acknowledgment'));
  await assert.rejects(service.providerCredentialProfiles.register(scope,proposal),/Lost commit/);
  assert.equal(sentPost().length,1);
});

test('invalid scope and proposal cannot mutate any credential profile',async()=>{
  await login();
  await assert.rejects(
    service.providerCredentialProfiles.register({...scope,authorizationSha256:'bad'},proposal),
    /signed Flow/i);
  await assert.rejects(
    service.providerCredentialProfiles.register(scope,{...proposal,policySha256:'x'}),
    /approved 0025/i);
  await assert.rejects(
    service.providerCredentialProfiles.register(scope,{...proposal,slot:'env.SECRET'}),
    /approved 0025/i);
  assert.equal(calls.length,0);
});
