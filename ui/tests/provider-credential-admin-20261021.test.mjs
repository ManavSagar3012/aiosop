import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const savedFetch = globalThis.fetch;
const flowId = 'flow-admin-credential';
const engagementId = 'eng-admin-credential';
const authorizationId = 'signed-roe-admin';
const authSha = 'a'.repeat(64);
const policySha = 'b'.repeat(64);
const reviewId = `provider-review-${'c'.repeat(32)}`;
const refId = `pcref-${'d'.repeat(32)}`;
const input = {flowId, engagementId, flowRevision:3, authorizationId};
const scope = {...input, authorizationVersion:5, authorizationSha256:authSha};
const status = {status:'active',version:5,policy_sha256:authSha,expires_at:null,
  key_id:'signer',remote_execution_outcome:'unknown'};
const policy = {review_id:reviewId,engagement_id:engagementId,flow_id:flowId,
  policy_revision:2,policy_sha256:policySha,status:'approved',
  policy:{provider:'openai',model:'gpt-4o-mini',operations:['completion'],
    allowed_roles:['vuln_analysis'],capabilities:['text_completion'],
    max_output_tokens:1024,budget_source:'signed_postgres_roe'},
  flow_revision:3,authorization_version:5,authorization_id:authorizationId,
  authorization_sha256:authSha,senior_reviewed:true,purpose:'operator_declared_policy_only',
  provider_served_model_verified:false,provider_capability_verified:false,
  callable_remotely:false,execution_enabled:false,budget_reserved:false,credentials_stored:false,
  created_at:'2026-10-21T00:00:00+00:00',updated_at:'2026-10-21T00:00:00+00:00'};

const baseRecord = {
  ref_id:refId,flow_id:flowId,engagement_id:engagementId,
  provider:'openai',slot:'primary',policy_review_id:reviewId,
  policy_sha256:policySha,reference_sha256:'e'.repeat(64),reference_revision:2,
  generation:1,status:'approved',flow_revision:3,authorization_version:5,
  authorization_id:authorizationId,authorization_sha256:authSha,senior_reviewed:true,
  created_at:'2026-10-21T00:00:00+00:00',updated_at:'2026-10-21T00:00:00+00:00',
  credentials_stored:false,credential_available_verified:false,credential_rotated:false,
  execution_enabled:false,provider_contacted:false,route_activated:false,
  server_reference_only:true,policy_current_approval_verified:false,
  status_is_historical_review_only:true,
};

const reply = (payload,statusCode=200,extra={}) => new Response(JSON.stringify(payload),{
  status:statusCode, headers:{'content-type':'application/json',...extra},
});

let vite, auth, admin, panel, calls = [], state = {...baseRecord};
let role = 'operator';
let revoked = false;
let lostAck = false;
let changedActorDuringRead = false;
let forgedField = false;
let oversizedProfile = false;
let policyRequests = 0;

before(async () => {
  vite = await createServer({root,appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  admin = await vite.ssrLoadModule('/src/services/providerCredentialAdministration.ts');
  panel = await vite.ssrLoadModule('/src/components/ProviderCredentialAdministrationPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = savedFetch;
  await vite?.close();
});

async function login(newRole='operator', sub='admin-operator') {
  auth.signOut();
  role = newRole; calls=[]; state={...baseRecord}; revoked=false;
  lostAck=false; changedActorDuringRead=false; forgedField=false; oversizedProfile=false;
  policyRequests=0;
  globalThis.fetch = async (target,options={}) => {
    const url = new URL(String(target));
    const path = url.pathname;
    calls.push({url:String(target),path,options});
    if(path === '/auth/me') return reply({sub,role,exp:Math.floor(Date.now()/1000)+3600});
    if(path.includes('/authoriz') || path.includes('/authorization')) {
      return reply(revoked?{...status,status:'revoked'}:status);
    }
    if(path.endsWith('/provider-route-policy-reviews')) {
      policyRequests += 1;
      return reply({items:[policy],has_more:false});
    }
    if(path.includes('/provider-credential-profile-refs')) {
      if (changedActorDuringRead) {
        changedActorDuringRead = false;
        auth.signOut();
      }
      if(options.method === 'POST') {
        const payload = JSON.parse(options.body);
        if(lostAck) throw new Error('Simulated lost durable POST acknowledgement');
        if(payload.operation==='rotate') {
          state={...state,status:'pending',senior_reviewed:false,generation:2,
            reference_revision:3,reference_sha256:'f'.repeat(64)};
        } else if(payload.operation==='approve' || payload.operation==='revoke') {
          state={...state,status:payload.operation==='approve'?'approved':'revoked',
            senior_reviewed:true,reference_revision:state.reference_revision+1,
            reference_sha256:'9'.repeat(64)};
        } else if(payload.operation==='register') {
          state={...state,status:'pending',senior_reviewed:false,
            provider:payload.provider,slot:payload.slot,
            policy_review_id:payload.policy_review_id,policy_sha256:payload.policy_sha256,
            reference_revision:1,
            generation:1,reference_sha256:'8'.repeat(64)};
        }
        return reply({...state,operation_recorded:true,idempotent_replay:false},
          payload.operation==='register'?201:200);
      }
      if(path.endsWith('/provider-credential-profile-refs')) {
        if(oversizedProfile) return reply({items:[state],has_more:false,noise:'x'.repeat(40000)});
        const result = forgedField?{...state,api_key:'secret-not-allowed'}:state;
        return reply({items:[result],has_more:false});
      }
      return reply(forgedField?{...state,private_key:'redacted'}:state);
    }
    throw new Error(`Unexpected fixture request: ${path}`);
  };
  await auth.signIn('memory-only-admin-bearer');
  calls=[];
}
const postCalls = () => calls.filter(c => c.options.method==='POST');
const readonlyCalls = () => calls.filter(c => c.options.method==='GET');

test('Administration panel renders disclaimer and excludes credentials from DOM',async()=>{
  await login();
  const html=renderToStaticMarkup(createElement(panel.ProviderCredentialAdministrationPanel));
  assert.match(html,/NOT VAULT-MATERIAL VERIFIED \/ NO PROVIDER CALL/);
  assert.match(html,/Expected Flow revision/);
  assert.match(html,/READ CURRENT SIGNED PROFILE \(GET ONLY\)/);
  assert.match(html,/Signed authorization ID \(nonsecret identifier\)/);
  assert.doesNotMatch(html,/memory-only-admin-bearer/);
  assert.doesNotMatch(html,/type="password"/);
  assert.equal(calls.length,0);
});

test('reject malformed Flow authority before any network read',async()=>{
  await login();
  await assert.rejects(admin.readCredentialAdministration({...input,flowRevision:-1}),/exact Flow/i);
  await assert.rejects(admin.readCredentialAdministration({...input,authorizationId:'Bearer fake'}),/exact Flow/i);
  assert.equal(calls.length,0);
});

test('reads current nonsecret profile and policy with strict bearer/header/origin rules',async()=>{
  await login();
  const result=await admin.readCredentialAdministration(input);
  assert.deepEqual(result.scope,scope);
  assert.equal(result.items.length,1);
  assert.equal(result.items[0].credential_available_verified,false);
  assert.equal(result.approvedPolicies.length,1);
  assert.equal(policyRequests,1);
  assert.equal(postCalls().length,0);
  const request=calls.find(c=>c.path.endsWith('/provider-credential-profile-refs'));
  assert.equal(request.options.method,'GET');
  assert.equal(request.options.credentials,'omit');
  assert.equal(request.options.cache,'no-store');
  assert.equal(request.options.redirect,'error');
  assert.equal(request.options.referrerPolicy,'no-referrer');
  assert.equal(request.options.headers.Authorization,'Bearer memory-only-admin-bearer');
  assert.deepEqual([...new URL(request.url).searchParams.keys()].sort(),[
    'expected_engagement_id','expected_revision','expected_authorization_version',
    'expected_authorization_id','expected_authorization_sha256','limit','offset',
  ].sort());
  assert.doesNotMatch(request.url,/memory-only-admin-bearer|api_key|private_key/i);
});

test('operator rotation submits only exact revision and rotates reference, never secret',async()=>{
  await login('operator','admin-rotation-operator');
  const result=await admin.providerCredentialAdministration.rotationIntent(scope,state,2,true);
  assert.equal(result.generation,2);
  assert.equal(result.status,'pending');
  assert.equal(result.credential_rotated,false);
  assert.equal(result.route_activated,false);
  const posted=postCalls();
  assert.equal(posted.length,1);
  assert.deepEqual(JSON.parse(posted[0].options.body),{
    operation:'rotate', operation_id:JSON.parse(posted[0].options.body).operation_id,
    ref_id:refId,expected_ref_revision:2,provider:'openai',slot:'primary',
    policy_review_id:reviewId,policy_sha256:policySha,
  });
  assert.match(JSON.parse(posted[0].options.body).operation_id,/^pcop-[0-9a-f]{32}$/);
  assert.doesNotMatch(posted[0].options.body,/api_key|password|vault|sk[-_]|private_key|secret/i);
  await assert.rejects(admin.providerCredentialAdministration.rotationIntent(scope,baseRecord,3,true),/exact expected/i);
  assert.equal(postCalls().length,1);
});

test('stale record and forged profile fail before any POST',async()=>{
  await login('operator','admin-stale-operator');
  state={...state,reference_revision:5};
  await assert.rejects(admin.readCurrentCredentialReference(scope,baseRecord),/changed/i);
  assert.equal(postCalls().length,0);
  await login('operator','admin-forged-operator');
  forgedField=true;
  await assert.rejects(admin.readCredentialAdministration(input),/private|forged|untrusted/i);
  assert.equal(postCalls().length,0);
  await login('operator','admin-oversized-operator');
  oversizedProfile=true;
  await assert.rejects(admin.readCredentialAdministration(input),/size bound/i);
  assert.equal(postCalls().length,0);
});

test('untrusted browser origin denies request before any reference or policy fetch',async()=>{
  await login('operator','admin-insecure-origin');
  const prior=globalThis.window;
  try {
    globalThis.window={location:{protocol:'http:',hostname:'untrusted.example'}};
    await assert.rejects(admin.readCredentialAdministration(input),/secure origin/i);
    assert.equal(readonlyCalls().length,0);
  } finally {
    if(prior === undefined) delete globalThis.window;
    else globalThis.window=prior;
  }
});

test('revoked ROE and identity lost during response invalidate state with no POST',async()=>{
  await login('operator','admin-revoked-operator');
  revoked=true;
  await assert.rejects(admin.readCredentialAdministration(input),/authorization unavailable|revoked/i);
  assert.equal(postCalls().length,0);
  await login('operator','admin-signout-operator');
  changedActorDuringRead=true;
  await assert.rejects(admin.readCredentialAdministration(input),/changed/i);
  assert.equal(postCalls().length,0);
});

test('lost acknowledgment remains UNKNOWN, service never retries mutation',async()=>{
  await login('operator','admin-ack-operator');
  lostAck=true;
  await assert.rejects(admin.providerCredentialAdministration.rotationIntent(scope,state,2,true),/lost durable POST/i);
  assert.equal(postCalls().length,1);
  lostAck=false;
  await assert.rejects(admin.providerCredentialAdministration.rotationIntent(scope,state,2,true),
    /previously attempted/i);
  assert.equal(postCalls().length,1);
});

test('senior role alone cannot rotate; signed senior may record scoped decision',async()=>{
  await login('senior_operator','independent-admin-senior');
  await assert.rejects(admin.providerCredentialAdministration.rotationIntent(scope,state,2,true),
    /separate operator/i);
  assert.equal(postCalls().length,0);
  const result=await admin.providerCredentialAdministration.decide(
    scope,state,2,'revoke','Separate bounded senior review',true);
  assert.equal(result.status,'revoked');
  assert.equal(result.credentials_stored,false);
  const write=JSON.parse(postCalls()[0].options.body);
  assert.equal(write.operation,'revoke');
  assert.equal(write.expected_ref_revision,2);
  assert.equal(write.reason,'Separate bounded senior review');
  assert.equal(postCalls().length,1);
});

test('registration cannot synthesize approved policy or allow senior self-review',async()=>{
  await login('operator','admin-register-operator');
  await assert.rejects(admin.providerCredentialAdministration.register(scope,
    {...policy,status:'pending'},'primary',true),/independent signed/i);
  assert.equal(postCalls().length,0);
  await login('senior_operator','admin-register-senior');
  await assert.rejects(admin.providerCredentialAdministration.register(scope,policy,'primary',true),
    /operator creates pending/i);
  assert.equal(postCalls().length,0);
});

test('operator registers only pending alias from signed approved policy; no vault material',async()=>{
  await login('operator','admin-create-operator');
  const result=await admin.providerCredentialAdministration.register(scope,policy,'backup',true);
  assert.equal(result.status,'pending');
  assert.equal(result.senior_reviewed,false);
  assert.equal(result.credential_available_verified,false);
  assert.equal(result.credential_rotated,false);
  const posted=postCalls();
  assert.equal(posted.length,1);
  const body=JSON.parse(posted[0].options.body);
  assert.deepEqual(Object.keys(body).sort(),[
    'operation','operation_id','provider','slot','policy_review_id','policy_sha256',
  ].sort());
  assert.equal(body.operation,'register');
  assert.equal(body.slot,'backup');
  assert.doesNotMatch(posted[0].options.body,/password|bearer|api_key|sk[-_]|secret|private_key/i);
});
