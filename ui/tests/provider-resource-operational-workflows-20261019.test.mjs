import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite, auth, providers, resources, providerPanel, resourcePanel;
let reply, calls = [], actorRole;
const flowId = 'flow-policy-demo';
const engagementId = 'eng-policy-demo';
const sha = 'a'.repeat(64);
const otherSha = 'b'.repeat(64);
const reviewId = `provider-review-${'f'.repeat(32)}`;
const artifactId = `artifact-${'e'.repeat(32)}`;
const taskId = 'task-resource-demo';
const policy = {
  provider: 'openai', model: 'openai/demo-operator', operations: ['completion'],
  allowed_roles: ['recon'], capabilities: ['text_completion'],
  max_output_tokens: 1024, budget_source: 'signed_postgres_roe',
};
const scope = {
  flowId, engagementId, flowRevision: 3,
  authorizationVersion: 2, authorizationId: 'authorized-roe-reference',
  authorizationSha256: otherSha,
};
const reviewed = {
  review_id: reviewId, flow_id: flowId, engagement_id: engagementId,
  policy_revision: 1, policy_sha256: sha, policy, status: 'pending',
  flow_revision: 3, authorization_version: 2,
  authorization_id: scope.authorizationId, authorization_sha256: otherSha,
  senior_reviewed: false, purpose: 'operator_declared_policy_only',
  provider_served_model_verified: false, provider_capability_verified: false,
  callable_remotely: false, execution_enabled: false, budget_reserved: false,
  credentials_stored: false, created_at: '2026-10-19T20:00:00', updated_at: '2026-10-19T20:00:00',
};
const sourceItem = {
  artifact_id: artifactId, original_name: 'notes.txt',
  alias_path: `virtual/text/${artifactId}/notes.txt`, virtual_folder: 'virtual/text',
  classification: 'utf8_inert_text', sha256: sha, size_bytes: 123,
  available_as_inert_data_only: true, approved_for_task: false,
  approved_for_agent_instructions: false, executed: false,
};
const resourceList = {
  format: 'ai-osop-derived-flow-resource-aliases-v1', flow_id: flowId,
  flow_revision: 3, authorization_version: 2, source_manifest_sha256: otherSha,
  folders: [{path:'virtual/text',count:1},{path:'virtual/source',count:0}],
  items: [sourceItem], count: 1, aliases_persisted: false,
  virtual_folders_persisted: false, read_only: true, host_files_created: false,
  container_resource_sync_performed: false, artifact_bytes_untrusted: true,
};

before(async () => {
  vite = await createServer({root, appType:'custom', logLevel:'silent', server:{middlewareMode:true}});
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  providers = await vite.ssrLoadModule('/src/services/providerPolicyReviews.ts');
  resources = await vite.ssrLoadModule('/src/services/flowResourceAliases.ts');
  providerPanel = await vite.ssrLoadModule('/src/components/flows/ProviderPolicyReviewPanel.tsx');
  resourcePanel = await vite.ssrLoadModule('/src/components/flows/FlowResourceAliasesPanel.tsx');
});
after(async () => {auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close();});

async function signIn(role='operator') {
  auth.signOut(); actorRole = role; calls = [];
  globalThis.fetch = async (url, options={}) => {
    const path = new URL(String(url)).pathname;
    calls.push({path,url:String(url),options});
    if (path === '/auth/me')
      return {ok:true,status:200,json:async()=>({sub:'tenant-owner',role:actorRole,exp:null})};
    if (!reply) throw new Error('Test reply missing');
    return {ok:true,status:options.method==='POST' && !path.endsWith('/task-preview')?201:200,json:async()=>structuredClone(reply)};
  };
  await auth.signIn('operator-review-bearer'); calls = [];
}

test('actual mounted Flow operator panels clearly separate intent, inert aliases and target verification', async () => {
  await signIn();
  const rendered = renderToStaticMarkup(createElement(providerPanel.ProviderPolicyReviewPanel, {
    flowId,engagementId,revision:3,flowStatus:'pending',authorizationId:scope.authorizationId,
  }));
  assert.match(rendered,/Provider policy lifecycle — durable INTENT only/);
  assert.match(rendered,/no API secrets, provider network probes/i);
  const aliases = renderToStaticMarkup(createElement(resourcePanel.FlowResourceAliasesPanel, {
    flowId,engagementId,revision:3,flowStatus:'running',
  }));
  assert.match(aliases,/Signed Flow virtual resources — read-only/);
  assert.match(aliases,/NOT persisted file moves/);
  const page = readFileSync(new URL('../src/pages/FlowOperations.tsx',import.meta.url),'utf8');
  assert.match(page,/<ProviderPolicyReviewPanel/);
  assert.match(page,/<FlowResourceAliasesPanel/);
  assert.match(page,/authorizationId=\{selectedEngagement\?\.scope\.authorization_ref\}/);
});

test('provider review list enforces signed query, private bearer and strict unverified schema', async () => {
  await signIn();
  reply = {items:[reviewed],has_more:false};
  const items = await providers.providerPolicyReviews.list(scope);
  assert.deepEqual(items,[reviewed]);
  assert.equal(calls.length,1);
  const call = calls[0];
  assert.equal(call.options.method,'GET');
  assert.equal(call.options.headers.Authorization,'Bearer operator-review-bearer');
  assert.equal(call.options.credentials,'omit');
  assert.equal(call.options.redirect,'error');
  assert.match(call.url,/expected_authorization_id=authorized-roe-reference/);
  assert.match(call.url,/expected_authorization_sha256=bbbb/);
  assert.doesNotMatch(call.url,/operator-review-bearer|Bearer/);
});

test('provider pending POST records inert policy without credentials and rejects falsely enabled reply', async () => {
  await signIn();
  reply = reviewed;
  const actual = await providers.providerPolicyReviews.create(scope,policy);
  assert.deepEqual(actual,reviewed);
  assert.deepEqual(JSON.parse(calls[0].options.body),policy);
  assert.equal(calls[0].options.method,'POST');
  assert.equal(calls[0].options.headers.Authorization,'Bearer operator-review-bearer');
  assert.doesNotMatch(JSON.stringify(JSON.parse(calls[0].options.body)),/api_key|credential|http|secret/i);
  await assert.rejects(providers.providerPolicyReviews.create(scope,policy),/previously attempted/);
  assert.equal(calls.length,1);
  const changed = { ...policy, model:'openai/not-verified' };
  reply = {...reviewed,policy:changed,execution_enabled:true};
  await assert.rejects(providers.providerPolicyReviews.create(scope,changed),/falsely enabled|Untrusted/);
});

test('native PUT uses exact pending policy revision CAS and never configures a provider', async () => {
  await signIn();
  const nextPolicy = {...policy, model:'openai/next-reviewed-intent'};
  reply = {...reviewed,policy:nextPolicy,policy_sha256:'c'.repeat(64),policy_revision:2};
  const updated = await providers.providerPolicyReviews.update(scope,reviewed,nextPolicy);
  assert.equal(updated.policy_revision,2);
  assert.equal(updated.execution_enabled,false);
  assert.equal(updated.callable_remotely,false);
  assert.equal(calls.length,1);
  assert.equal(calls[0].options.method,'PUT');
  assert.equal(calls[0].path,`/flows/${flowId}/provider-route-policy-reviews/${reviewId}`);
  assert.deepEqual(JSON.parse(calls[0].options.body),{
    ...nextPolicy,expected_policy_revision:1,
  });
  await assert.rejects(providers.providerPolicyReviews.update(scope,reviewed,nextPolicy),/already attempted/);
  assert.equal(calls.length,1);
});

test('non-senior cannot approve even an operator-declared provider intent', async () => {
  await signIn();
  await assert.rejects(providers.providerPolicyReviews.decide(scope,reviewed,'approve','Review for signed tenant'),/Separate signed senior/);
  assert.equal(calls.length,0);
});

test('derived resource aliases are SHA-scoped only and never persisted/executable', async () => {
  await signIn(); reply = resourceList;
  const result = await resources.readFlowResourceAliases(flowId,3,2);
  assert.deepEqual(result,resourceList);
  assert.equal(calls[0].options.method,'GET');
  assert.equal(calls[0].options.credentials,'omit');
  assert.equal(calls[0].options.headers.Authorization,'Bearer operator-review-bearer');
  assert.match(calls[0].url,/resource-aliases\?expected_revision=3/);
  assert.equal(result.aliases_persisted,false);
  assert.equal(result.container_resource_sync_performed,false);
});

test('tampered alias path, injected file body or false sync fails closed', async () => {
  await signIn();
  const attacks = [
    {...resourceList,host_files_created:true},
    {...resourceList,aliases_persisted:true},
    {...resourceList,items:[{...sourceItem,alias_path:'../../secrets'}]},
    {...resourceList,items:[{...sourceItem,private_body:'Bearer target-token'}]},
    {...resourceList,folders:[{path:'virtual/source',count:1},{path:'virtual/text',count:0}]},
  ];
  for (const tamper of attacks) {
    reply = tamper;
    await assert.rejects(resources.readFlowResourceAliases(flowId,3,2));
  }
});

test('exact derived alias metadata GET has no bytes and rejects forged executable response', async () => {
  await signIn();
  reply = {...sourceItem,flow_id:flowId,flow_revision:3,authorization_version:2,
    source_manifest_sha256:otherSha,preview_contains_artifact_bytes:false,replayable_or_executable:false};
  const item = await resources.previewFlowAlias(flowId,3,2,otherSha,artifactId);
  assert.deepEqual(item,sourceItem);
  assert.equal(calls[0].options.method,'GET');
  assert.match(calls[0].url,/expected_manifest_sha256=bbbb/);
  reply.replayable_or_executable = true;
  await assert.rejects(resources.previewFlowAlias(flowId,3,2,otherSha,artifactId));
});

test('signed Task preflight never transfers bytes and rejects forged execution receipts', async () => {
  await signIn();
  reply = {...sourceItem,flow_id:flowId,flow_revision:3,authorization_version:2,
    source_manifest_sha256:otherSha,task_id:taskId,signed_task_currently_approved:true,
    approved_command_sha256:sha,preview_contains_artifact_bytes:false,
    resource_transferred_to_worker:false,container_resource_sync_performed:false,
    execution_started_by_preview:false};
  const request = {
    flowId,engagementId,revision:3,version:2,taskId,artifactId,
    artifactSha:sha,authorizationSha:otherSha,manifestSha:otherSha,confirmed:true,
  };
  const actual = await resources.previewSignedTaskResource(request);
  assert.equal(actual.execution_started_by_preview,false);
  assert.equal(actual.approved_command_sha256,sha);
  assert.equal(calls.length,1);
  assert.equal(calls[0].options.method,'POST');
  assert.deepEqual(JSON.parse(calls[0].options.body),{
    engagement_id:engagementId,task_id:taskId,artifact_id:artifactId,
    artifact_sha256:sha,authorization_sha256:otherSha,
    expected_manifest_sha256:otherSha,
  });
  await assert.rejects(resources.previewSignedTaskResource(request),/already attempted/);
  reply = {...reply,execution_started_by_preview:true};
  await assert.rejects(resources.previewSignedTaskResource({...request,taskId:'task-other'}),/falsely|unsafe/);
});

test('untrusted actor / incomplete signed authority cause zero I/O', async () => {
  await signIn('viewer');
  await assert.rejects(resources.readFlowResourceAliases(flowId,3,2));
  await assert.rejects(providers.providerPolicyReviews.list(scope));
  assert.equal(calls.length,0);
  await signIn();
  await assert.rejects(resources.previewFlowAlias(flowId,3,2,'not-a-sha',artifactId));
  await assert.rejects(providers.providerPolicyReviews.list({...scope,authorizationSha256:'bad'}));
  assert.equal(calls.length,0);
});
