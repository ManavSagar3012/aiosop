import assert from 'node:assert/strict';
import {before, after, test} from 'node:test';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {createServer} from 'vite';
import {fileURLToPath} from 'node:url';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const originalFetch = globalThis.fetch;
const ids = {
  flowId: 'flow-original-action', engagementId: 'eng-original-action',
  taskId: 'task-original-action', subtaskId: 'subtask-original-action',
};
const authority = {
  flowId: ids.flowId, engagementId: ids.engagementId,
  flowRevision: 7, authorizationVersion: 5,
  authorizationId: 'original-owner', authorizationSha256: 'a'.repeat(64),
};
const action = {
  action_id: `action-${'a'.repeat(32)}`,
  flow_id: ids.flowId, engagement_id: ids.engagementId,
  task_id: ids.taskId, subtask_id: ids.subtaskId,
  server_id: 'browser-mcp', tool_name: 'get_status',
  status: 'finished', parameters_sha256: 'b'.repeat(64),
  flow_revision: 7, authorization_version: 5,
  declaration_sha256: 'c'.repeat(64), intent_sha256: 'd'.repeat(64),
  receipt_sha256: 'e'.repeat(64), side_effect_class: 'READ_ONLY',
  request_id: `req-${'f'.repeat(48)}`, cancel_requested: false,
  execution_started: true, target_effect_verified: false,
  safe_to_automatically_retry: false,
};
let vite;
let auth;
let service;
let panel;
let requested;
let queued;
const response = (data) => new Response(JSON.stringify(data), {
  status: 200, headers: {'content-type': 'application/json'},
});

before(async () => {
  vite = await createServer({root, appType: 'custom', logLevel: 'silent',
    server: {middlewareMode: true}});
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/flowMcpActions.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/FlowMcpActionsPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

async function login() {
  auth.signOut();
  requested = [];
  queued = [];
  globalThis.fetch = async (url, options = {}) => {
    const path = new URL(String(url)).pathname;
    if (path === '/auth/me') return response({sub: 'action-owner', role: 'operator',
      exp: Math.floor(Date.now() / 1000) + 3600});
    requested.push({url, options});
    if (!queued.length) throw new Error('Unexpected action request');
    return queued.shift();
  };
  await auth.signIn('test-current-owner-token');
}

function listing(item) {
  return {flow_id: ids.flowId, engagement_id: ids.engagementId,
    flow_revision: 7, authorization_version: 5, actions: [item]};
}

test('real public Action readback retains ROE version and signed provider digest', async () => {
  await login();
  queued.push(response(listing(action)));
  const rows = await service.listFlowMcpActions(authority);
  assert.deepEqual(rows, [action]);
  assert.equal(requested.length, 1);
  assert.equal(requested[0].options.method, 'GET');
  assert.equal(requested[0].options.credentials, 'omit');
});

test('same bounded contract rejects forged version, target verification, and private provider claims', async () => {
  await login();
  queued.push(response(listing({...action, authorization_version: 6})));
  await assert.rejects(service.listFlowMcpActions(authority), /Forged|unverified/);
  queued.push(response(listing({...action, target_effect_verified: true})));
  await assert.rejects(service.listFlowMcpActions(authority), /Forged|unverified/);
  queued.push(response(listing({...action, verified: true, certified: true})));
  await assert.rejects(service.listFlowMcpActions(authority), /Forged|unverified/);
  queued.push(response(listing({...action, provider_receipt: {secret: 'private'}})));
  await assert.rejects(service.listFlowMcpActions(authority), /Forged|unverified/);
  assert.equal(requested.length, 4);
  assert.ok(requested.every(req => req.options.method === 'GET'));
});

test('FINISHED and CANCELLED ledger states never render a verified external target effect', () => {
  const finished = renderToStaticMarkup(createElement(panel.McpActionAuthorityLabels,
    {action}));
  assert.match(finished, /FINISHED in Action ledger; provider\/tool status only/);
  assert.match(finished, /Provider status receipt digest stored/);
  assert.match(finished, /Target effect verified: NO/);
  assert.match(finished, /Safe automatic replay: NO/);
  assert.doesNotMatch(finished, /Target effect verified: YES/);
  const cancelled = renderToStaticMarkup(createElement(panel.McpActionAuthorityLabels,
    {action: {...action, status: 'cancelled'}}));
  assert.match(cancelled, /remote termination not independently proven/);
});

test('0027 UNKNOWN labels deny replay even with unobserved execution and lost HTTP ACK', () => {
  const markup = renderToStaticMarkup(createElement(panel.McpActionAuthorityLabels,
    {action: {...action, status: 'unknown', receipt_sha256: null}}));
  assert.match(markup, /Original 0027 Action outcome UNKNOWN/);
  assert.match(markup, /Do not resend the dispatch/);
  assert.match(markup, /safe automatic replay|Safe automatic replay: NO/);
  assert.doesNotMatch(markup, /Provider status receipt digest stored/);
});

test('declaration-only SourceMap, Cloud and Turbo are never displayed as actionable tools', () => {
  const declarations = ['source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp',
    'browser-mcp'].map(server_id => ({
      server_id, manifest_initialized: true, circuit_state: 'closed',
      runtime_health_verified: false,
      tools: [{name: 'get_status', side_effect_class: 'READ_ONLY',
        declared_scope_check: true, declared_requires_approval: true,
        execution_authorized: false, runtime_health_verified: false,
        signed_task_required_for_execution: true}],
    }));
  assert.deepEqual(panel.declaredActionChoices({servers: declarations}),
    [{server_id: 'browser-mcp', tool_name: 'get_status'}]);
  assert.deepEqual(panel.declaredActionChoices({servers: declarations.map(server => ({
    ...server, circuit_state: 'open',
  }))}), []);
  assert.deepEqual(panel.declaredActionChoices(null), []);
  for (const server_id of ['source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp']) {
    assert.equal(panel.allowsSignedActionDispatch({...action, status: 'prepared', server_id}), false);
  }
  assert.equal(panel.allowsSignedActionDispatch({...action, status: 'prepared'}), true);
  assert.equal(panel.allowsSignedActionDispatch({...action, status: 'unknown'}), false);
});
