import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const flowId = 'flow-preflight-review';
const engagementId = 'eng-preflight-review';
const taskId = 'task-preflight-review';
const subtaskId = 'subtask-preflight-review';
const actionId = `action-${'a'.repeat(32)}`;
const paramsSha = 'b'.repeat(64);
const declarationSha = 'c'.repeat(64);
const resourceSha = 'd'.repeat(64);
const authSha = 'e'.repeat(64);
const signer = 'authorized-roe-ref';
const scope = {
  flowId, engagementId, flowRevision: 7, authorizationVersion: 5,
  authorizationId: signer, authorizationSha256: authSha,
};
const prepared = {
  action_id: actionId, flow_id: flowId, engagement_id: engagementId,
  task_id: taskId, subtask_id: subtaskId, server_id: 'local_mcp',
  tool_name: 'get_metadata', status: 'prepared', parameters_sha256: paramsSha,
  execution_started: false, target_effect_verified: false,
  safe_to_automatically_retry: false,
};
const noEffect = {
  read_only: true, provider_contacted: false, approval_issued: false,
  dispatch_performed: false, reservation_performed: false,
  guarantees_future_dispatch: false,
};
const eligible = {
  ...noEffect,
  allowed: true, code: 'preflight_eligible',
  reason: 'Existing prepared Action passes current read-only authority checks',
  flow_id: flowId, action_id: actionId, task_id: taskId, subtask_id: subtaskId,
  action_status: 'prepared', declaration_sha256: declarationSha,
  parameters_sha256: paramsSha, resource_bound: false,
  resource_artifact_sha256: null,
};
const denied = {
  ...noEffect, allowed: false, code: 'approval_denied',
  reason: 'Current independently approved Task, Subtask or lease unavailable',
};
const policy = {
  status: 'active', version: 5, policy_sha256: authSha, key_id: 'trusted-key',
  expires_at: null, remote_execution_outcome: 'unknown',
};
const catalog = (...items) => ({
  flow_id: flowId, engagement_id: engagementId,
  flow_revision: 7, authorization_version: 5, actions: items,
});

const reply = (value, status = 200, headers = {}) =>
  new Response(JSON.stringify(value), {
    status, headers: { 'content-type': 'application/json', ...headers },
  });

let vite;
let auth;
let service;
let panel;
let calls = [];
let pending = [];

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/flowMcpActionPreflight.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/FlowMcpActionPreflightPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});
async function login(role = 'operator') {
  auth.signOut();
  calls = [];
  pending = [];
  globalThis.fetch = async (url, options = {}) => {
    const request = { url: String(url), path: new URL(String(url)).pathname, options };
    calls.push(request);
    if (request.path === '/auth/me') {
      return reply({
        sub: 'flow-owner', role, exp: Math.floor(Date.now() / 1000) + 3600,
      });
    }
    if (!pending.length) throw new Error('Unexpected extra network request');
    const response = pending.shift();
    if (response instanceof Error) throw response;
    return typeof response === 'function' ? response(request) : response;
  };
  await auth.signIn('signed-preflight-tab-token');
  calls = [];
}
function queue(...items) {
  pending.push(...items);
}
function queueCheck(result = eligible, post = prepared) {
  // Pre-signer, signed catalog, Action detail, signer, backend preflight,
  // post-signer, durable Action detail, post-signer.
  queue(
    reply(policy), reply(catalog(prepared)), reply(prepared), reply(policy),
    result instanceof Response || result instanceof Error || typeof result === 'function'
      ? result : reply(result),
    reply(policy), reply(post), reply(policy),
  );
}
function preflightRequests() {
  return calls.filter(item => item.path.endsWith('/preflight'));
}

test('named panel renders safe eligibility controls without execution or approval', async () => {
  await login();
  const markup = renderToStaticMarkup(createElement(
    panel.FlowMcpActionPreflightPanel,
    { flowId, engagementId, revision: 7, flowStatus: 'running', authorizationId: signer },
  ));
  assert.match(markup, /Signed MCP Action preflight/);
  assert.match(markup, /READ PREPARED ACTIONS \(NO EXECUTION\)/);
  assert.match(markup, /contacts no/);
  assert.doesNotMatch(markup, /signed-preflight-tab-token/);
});

test('construct signed Flow context from server-authorized ROE and no client-pinned version', async () => {
  await login();
  queue(reply(policy));
  const result = await service.currentMcpPreflightScope(flowId, engagementId, 7, signer);
  assert.deepEqual(result, scope);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, `/engagements/${engagementId}/authorization/status`);
  assert.equal(calls[0].options.method, 'GET');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer signed-preflight-tab-token');
});

test('list only signed prepared Actions without automatically preflighting or dispatching', async () => {
  await login();
  const finished = { ...prepared, action_id: `action-${'f'.repeat(32)}`,
    status: 'finished', execution_started: true };
  queue(reply(policy), reply(catalog(prepared, finished)), reply(policy));
  const result = await service.listPreparedMcpPreflightActions(scope);
  assert.deepEqual(result, [prepared]);
  assert.equal(calls.length, 3);
  assert.equal(calls.filter(item => item.options.method !== 'GET').length, 0);
  assert.equal(preflightRequests().length, 0);
});

test('positive backend preflight strictly bound to prepared catalog IDs and ROE, no secrets in query', async () => {
  await login();
  queueCheck();
  const result = await service.checkFlowMcpActionPreflight(scope, actionId);
  assert.equal(result.allowed, true);
  assert.equal(result.code, 'preflight_eligible');
  assert.equal(result.provider_contacted, false);
  assert.equal(result.approval_issued, false);
  assert.equal(result.reservation_performed, false);
  assert.equal(result.guarantees_future_dispatch, false);
  assert.equal(calls.length, 8);
  assert.equal(preflightRequests().length, 1);
  const call = preflightRequests()[0];
  assert.equal(call.path, `/flows/${flowId}/mcp-actions/${actionId}/preflight`);
  assert.equal(call.options.method, 'GET');
  assert.equal(call.options.credentials, 'omit');
  assert.equal(call.options.cache, 'no-store');
  assert.equal(call.options.redirect, 'error');
  assert.equal(call.options.headers.Authorization, 'Bearer signed-preflight-tab-token');
  const query = new URL(call.url).searchParams;
  assert.deepEqual([...query.keys()].sort(), [
    'expected_authorization_version', 'expected_engagement_id', 'expected_parameters_sha256',
    'expected_revision', 'server_id', 'subtask_id', 'task_id', 'tool_name',
  ].sort());
  assert.equal(query.get('expected_parameters_sha256'), paramsSha);
  assert.equal(query.get('task_id'), taskId);
  assert.equal(query.get('subtask_id'), subtaskId);
  assert.equal(query.get('server_id'), 'local_mcp');
  assert.equal(query.get('tool_name'), 'get_metadata');
  assert.equal(query.get('expected_authorization_version'), '5');
  assert.doesNotMatch(new URL(call.url).search, /Bearer|signed-preflight-tab-token|raw_request|approval_id|https?:\/\//);
  assert.equal(calls.filter(item => item.options.method !== 'GET').length, 0);
});

test('optional SHA only can request immutable resource check and verify SHA in response', async () => {
  await login();
  queueCheck({
    ...eligible, resource_bound: true, resource_artifact_sha256: resourceSha,
  });
  const result = await service.checkFlowMcpActionPreflight(scope, actionId, resourceSha);
  assert.equal(result.allowed, true);
  assert.equal(result.resource_bound, true);
  assert.equal(result.resource_artifact_sha256, resourceSha);
  assert.equal(new URL(preflightRequests()[0].url).searchParams.get('expected_manifest_sha256'), resourceSha);
});

test('authoritative denied preflight remains denied with deterministic safe code and reason', async () => {
  await login();
  queueCheck(denied);
  const result = await service.checkFlowMcpActionPreflight(scope, actionId);
  assert.deepEqual(result, denied);
  assert.equal(preflightRequests().length, 1);
  assert.equal(calls.every(item => item.options.method === 'GET'), true);
});

test('forged READY or private backend data can never become eligibility', async () => {
  const variants = [
    { ...eligible, provider_contacted: true },
    { ...eligible, approval_issued: true },
    { ...eligible, reservation_performed: true },
    { ...eligible, guarantees_future_dispatch: true },
    { ...eligible, flow_id: 'flow-other' },
    { ...eligible, action_id: `action-${'f'.repeat(32)}` },
    { ...eligible, parameters_sha256: '0'.repeat(64) },
    { ...eligible, declaration_sha256: 'not-valid' },
    { ...eligible, resource_bound: true, resource_artifact_sha256: null },
    { ...eligible, target_effect_verified: true },
    { ...eligible, parameters: { target: 'https://example.invalid/private' } },
    { ...denied, allowed: true },
    { ...denied, reason: 'Approved!' },
    { ...denied, private_target: 'https://internal.invalid' },
  ];
  for (const payload of variants) {
    await login();
    queueCheck(payload);
    await assert.rejects(
      service.checkFlowMcpActionPreflight(scope, actionId),
      /unsafe|Untrusted|Forged|preflight|metadata/i,
    );
    assert.equal(preflightRequests().length, 1);
  }
});

test('reject duplicate-key, unbounded and non-JSON preflight HTTP responses', async () => {
  await login();
  const text = JSON.stringify(eligible).replace('"allowed":true', '"allowed":false,"allowed":true');
  queueCheck(new Response(text, { status: 200, headers: { 'content-type': 'application/json' } }));
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /Duplicate/);
  await login();
  queueCheck(reply({ ...eligible, extra: 'x'.repeat(5000) }));
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /size|metadata/i);
  await login();
  queueCheck(new Response(JSON.stringify(eligible), {
    status: 200, headers: { 'content-type': 'text/html' },
  }));
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /unavailable/);
});

test('sign-out or bearer switch while backend GET awaits invalidates preflight', async () => {
  await login();
  queueCheck(() => { auth.signOut(); return reply(eligible); });
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /identity changed/);
  assert.equal(preflightRequests().length, 1);
});

test('revoked post-signature and re-reserved Action fail closed', async () => {
  await login();
  queue(
    reply(policy), reply(catalog(prepared)), reply(prepared), reply(policy),
    reply(eligible), reply({ ...policy, version: 6 }),
  );
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /ROE changed/);
  assert.equal(preflightRequests().length, 1);
  await login();
  queueCheck(eligible, { ...prepared, status: 'reserved' });
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /changed/);
  assert.equal(preflightRequests().length, 1);
});

test('unavailable preflight HTTP response or transport is unknown, with no automatic retry', async () => {
  await login();
  queueCheck(reply({ detail: 'revoked' }, 503));
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /unavailable/);
  assert.equal(preflightRequests().length, 1);
  assert.equal(calls.length, 5);
  await login();
  queueCheck(new Error('Lost read-only response'));
  await assert.rejects(service.checkFlowMcpActionPreflight(scope, actionId), /Lost read-only response/);
  assert.equal(preflightRequests().length, 1);
  assert.equal(calls.length, 5);
});

test('malformed signer, action ID or optional resource digest denied before network', async () => {
  await login();
  await assert.rejects(
    service.checkFlowMcpActionPreflight(scope, 'action-../../etc/passwd'),
    /Exact prepared Action/,
  );
  await assert.rejects(
    service.checkFlowMcpActionPreflight(scope, actionId, 'not-a-sha'),
    /manifest SHA/,
  );
  await assert.rejects(
    service.checkFlowMcpActionPreflight({ ...scope, authorizationSha256: 'incorrect' }, actionId),
    /signed Flow/,
  );
  assert.equal(calls.length, 0);
});
