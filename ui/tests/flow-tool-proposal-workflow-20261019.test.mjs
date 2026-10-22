import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite, auth, service, panel;
let reply;
let readback;
let postCount = 0;
let calls = [];
const flowId = 'flow-review-tool';
const engagementId = 'eng-review-tool';
const objectiveTaskId = 'task-review-tool';
const subtaskId = 'subtask-review-tool';

function receipt() {
  return {
    status: 'proposal_recorded_pending_review',
    flow_id: flowId,
    engagement_id: engagementId,
    subtask_id: subtaskId,
    flow_revision: 5,
    authorization_version: 3,
    execution_started: false,
    human_approval_still_required: true,
    runtime_health_verified: false,
    target_effect_verified: false,
    safe_to_automatically_retry: false,
  };
}

function flow() {
  return {
    flow: { id: flowId, engagement_id: engagementId, revision: 5, status: 'pending' },
    tasks: [{ id: objectiveTaskId }],
    subtasks: [{
      id: subtaskId, task_id: objectiveTaskId, flow_id: flowId,
      status: 'pending', task_type: 'operator_mcp_capability_review',
      agent_type: 'human_oversight', approval_required: true,
    }],
  };
}

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/flowToolProposals.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/McpToolCatalogPanel.tsx');
});
after(async () => {
  auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close();
});

async function signIn(role = 'operator') {
  auth.signOut(); reply = receipt(); readback = flow(); postCount = 0; calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, url: String(url), options });
    if (pathname === '/auth/me')
      return { ok: true, status: 200, json: async () => ({ sub: 'reviewer', role, exp: null }) };
    if (pathname.endsWith('/tool-proposals')) {
      postCount++;
      return { ok: true, status: 201, json: async () => structuredClone(reply) };
    }
    if (pathname === `/flows/${flowId}`)
      return { ok: true, status: 200, json: async () => structuredClone(readback) };
    throw new Error(`Unexpected endpoint ${pathname}`);
  };
  await auth.signIn('explicit-tool-review-token'); calls = [];
}

function input(overrides = {}) {
  return {
    flowId, engagementId, objectiveTaskId,
    serverId: 'browser_mcp', toolName: 'passive_metadata', expectedFlowRevision: 4,
    expectedAuthorizationVersion: 3, explicitHumanConfirmation: true, ...overrides,
  };
}

test('mounted operator selects declared tool + objective with separate human acknowledgment', async () => {
  await signIn();
  const html = renderToStaticMarkup(createElement(panel.McpToolCatalogPanel, {
    engagementId, flowId, revision: 4, flowStatus: 'pending',
    objectives: [{ id: objectiveTaskId, title: 'Review scoped metadata' }],
  }));
  assert.match(html, /READ DECLARED TOOLS \(GET ONLY\)/);
  const panelSource = readFileSync(new URL('../src/components/flows/McpToolCatalogPanel.tsx', import.meta.url), 'utf8');
  assert.match(panelSource, /pending HUMAN REVIEW subtask/i);
  assert.match(panelSource, /RECORD PENDING TOOL REVIEW \(NO EXECUTION\)/);
  assert.match(panelSource, /further signed Task\/Action and approval/i);
  assert.doesNotMatch(html, /Bearer explicit-tool-review-token|private-body/);
  const mounted = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');
  assert.match(mounted, /objectives=\{objectives\.filter\(item => item\.status === 'planned'\)/);
  assert.match(mounted, /onProposed=\{\(\) => void refreshFlow\(selectedFlow\.id\)\}/);
});

test('real client POSTs only bounded identity/intent and independently GETs native pending subtask', async () => {
  await signIn();
  const result = await service.proposeDeclaredToolReview(input());
  assert.deepEqual(result, receipt());
  assert.equal(postCount, 1);
  assert.equal(calls.length, 2);
  const request = calls[0];
  assert.equal(request.pathname, `/flows/${flowId}/tool-proposals`);
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers.Authorization, 'Bearer explicit-tool-review-token');
  assert.equal(request.options.credentials, 'omit');
  assert.equal(request.options.redirect, 'error');
  assert.equal(request.options.cache, 'no-store');
  assert.deepEqual(JSON.parse(request.options.body), {
    objective_task_id: objectiveTaskId, server_id: 'browser_mcp',
    tool_name: 'passive_metadata', expected_flow_revision: 4,
    expected_authorization_version: 3, explicit_human_confirmation: true,
  });
  assert.doesNotMatch(request.url, /Bearer|explicit-tool-review-token|token=/);
  assert.equal(calls[1].pathname, `/flows/${flowId}`);
  assert.equal(calls[1].options.method, 'GET');
  await assert.rejects(service.proposeDeclaredToolReview(input()), /already attempted/);
  assert.equal(postCount, 1);
});

test('malformed/false receipt cannot promote execution or get automatic retry', async () => {
  await signIn();
  reply = { ...receipt(), target_effect_verified: true };
  await assert.rejects(service.proposeDeclaredToolReview(input({ toolName: 'forged_verified' })), /malformed|unsafe/);
  assert.equal(postCount, 1);
  await assert.rejects(service.proposeDeclaredToolReview(input({ toolName: 'forged_verified' })), /already attempted/);
  assert.equal(postCount, 1);
  reply = { ...receipt(), host: 'private-host' };
  await assert.rejects(service.proposeDeclaredToolReview(input({ toolName: 'extra_private' })));
  assert.equal(postCount, 2);
});

test('signed native readback must contain the same pending human-only subtask', async () => {
  await signIn();
  readback.subtasks[0].status = 'dispatched';
  await assert.rejects(service.proposeDeclaredToolReview(input({ toolName: 'stale_execution' })), /UNKNOWN/);
  assert.equal(postCount, 1);
});

test('rejected HTTP 503, uncertain response and missing approval cannot automatically replay', async () => {
  await signIn();
  const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (String(url).includes('/tool-proposals')) {
      postCount++;
      return { ok: false, status: 503 };
    }
    return original(url, options);
  };
  const params = input({ toolName: 'post_unknown' });
  await assert.rejects(service.proposeDeclaredToolReview(params), /UNKNOWN/);
  await assert.rejects(service.proposeDeclaredToolReview(params), /already attempted/);
  assert.equal(postCount, 1);
  await assert.rejects(service.proposeDeclaredToolReview(input({
    toolName: 'invalid_confirm',
    explicitHumanConfirmation: false,
  })));
  assert.equal(postCount, 1);
});

test('unsafe role, stale version, unsafe names never make an external request', async () => {
  await signIn('auditor');
  await assert.rejects(service.proposeDeclaredToolReview(input()));
  assert.equal(postCount, 0);
  await signIn();
  await assert.rejects(service.proposeDeclaredToolReview(input({ expectedAuthorizationVersion: 0 })));
  await assert.rejects(service.proposeDeclaredToolReview(input({ expectedFlowRevision: -1 })));
  await assert.rejects(service.proposeDeclaredToolReview(input({ toolName: 'bad/../../target' })));
  assert.equal(postCount, 0);
});

test('operator changing mid-POST never receives trusted completion', async () => {
  await signIn();
  let resume;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (String(url).endsWith('/tool-proposals')) {
      postCount++;
      return { ok: true, status: 201, json: () => new Promise(resolve => { resume = resolve; }) };
    }
    return original(url, options);
  };
  const promise = service.proposeDeclaredToolReview(input({ toolName: 'swapped_operator' }));
  for (let n = 0; n < 200 && !resume; n++) await Promise.resolve();
  assert.equal(typeof resume, 'function');
  auth.signOut(); resume(receipt());
  await assert.rejects(promise, /Operator changed/);
  assert.equal(postCount, 1);
});
