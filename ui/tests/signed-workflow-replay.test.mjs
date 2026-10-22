import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let api;
let replay;
let component;

const engagement = {
  session_id: 'eng-live',
  phase: 'reconnaissance',
  scope: { authorization_ref: 'signed-roe', domains: ['authorized.example'], ips: [] },
};
const flow = {
  id: 'flow-live',
  engagement_id: 'eng-live',
  objective: 'Reviewed authorization workflow',
  status: 'running',
  revision: 3,
  created_at: '2026-10-15T00:00:00Z',
  updated_at: '2026-10-15T00:00:00Z',
};
const source = {
  source_task_id: 'task-source',
  workflow_id: 'wf-live',
  source_user_label: 'user_a',
};
const fields = {
  workflowId: source.workflow_id,
  sourceTaskId: source.source_task_id,
  sourceUserLabel: source.source_user_label,
  targetUserLabel: 'user_b',
};

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  replay = await vite.ssrLoadModule('/src/services/signedReplay.ts');
  component = await vite.ssrLoadModule('/src/components/flows/FlowOperations.tsx');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function setup(overrides = {}) {
  api.signOut();
  const calls = [];
  const config = {
    role: 'senior_operator',
    authorizationVersion: 7,
    catalogVersion: 7,
    revision: 3,
    identities: ['user_a', 'user_b'],
    sources: [source],
    taskStatus: 'completed',
    apiStatus: 200,
    apiNetworkFailure: false,
    apiReceipt: {
      status: 'awaiting_execution_approval', task_id: 'task-replay-proposal',
      workflow_id: 'wf-live', execution_started: false,
    },
    ...overrides,
  };
  globalThis.fetch = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    const query = new URL(String(url)).searchParams;
    calls.push({ path, query, url: String(url), init });
    if (path === '/auth/me') {
      return response({ sub: 'signed-test-operator', role: config.role, exp: null });
    }
    if (path === '/engagements/eng-live/authorization/status') {
      return response({
        status: config.authorizationVersion === null ? 'revoked' : 'active',
        version: config.authorizationVersion,
        key_id: 'signed-qual-kid',
        expires_at: null,
        policy_sha256: 'signed-policy-hash',
        remote_execution_outcome: 'unknown',
      });
    }
    if (path === '/engagements/eng-live/workflows/replay-sources') {
      assert.equal(query.get('flow_id'), 'flow-live');
      return response({
        flow_id: 'flow-live',
        flow_revision: config.revision,
        authorization_version: config.catalogVersion,
        sources: config.sources,
        identities: config.identities,
      });
    }
    if (path === '/flows/flow-live') {
      return response({
        flow: { ...flow, revision: config.revision },
        tasks: [{
          id: 'task-human-objective', type: 'flow_objective',
          engagement_id: 'eng-live', flow_id: 'flow-live',
        }],
        subtasks: [],
      });
    }
    if (path === '/tasks/task-source') {
      return response({
        id: 'task-source',
        type: 'map_workflow',
        status: config.taskStatus,
        flow_id: null,
        engagement_id: 'eng-live',
        payload: {
          user_label: 'user_a', url: 'https://authorized.example/home',
          _authorization_version: 7,
        },
        result: { workflow_id: 'wf-live', status: 'workflow_recorded' },
      });
    }
    if (path === '/engagements/eng-live/workflows/wf-live/replay') {
      if (config.apiNetworkFailure) throw new TypeError('Synthetic lost POST response');
      return response(config.apiReceipt, config.apiStatus);
    }
    if (path === '/engagements/eng-live/workflows/wf-live/signed-comparisons') {
      return response(config.comparison ?? {
        flow_id: 'flow-live', replay_task_id: 'task-replay-proposal',
        step_id: 'step-observed', status: 'candidate_needs_independent_review',
        reason: 'matching_provider_body_digest_not_ownership_proof',
        source_observed: true, target_observed: true,
        provider_testimony_only: true, source_authenticity_verified: false,
        target_effect_verified: false, authorization_violation_verified: false,
        findings_count: 0, comparison_sha256: 'a'.repeat(64),
      }, config.apiStatus);
    }
    throw new Error('Unexpected network operation ' + path);
  };
  return { calls, config };
}

async function signIn(role = 'senior_operator') {
  await api.signIn('local-ui-fixture-bearer');
  assert.equal(api.currentOperator().role, role);
}

test('requires explicit bounded IDs, two distinct identities and integer signed versions', () => {
  const valid = {
    engagementId: engagement.session_id,
    flowId: flow.id,
    workflowId: source.workflow_id,
    sourceTaskId: source.source_task_id,
    sourceUserLabel: 'user_a',
    targetUserLabel: 'user_b',
    expectedAuthorizationVersion: 7,
    expectedFlowRevision: 3,
  };
  assert.equal(replay.validateReplayInput(valid), null);
  for (const wrong of [
    { sourceUserLabel: 'user_b' },
    { sourceUserLabel: 'anonymous' },
    { targetUserLabel: 'guest' },
    { targetUserLabel: 'other/user' },
    { sourceTaskId: '../../task' },
    { workflowId: 'unverified-wf' },
    { flowId: '' },
    { engagementId: 'abc' },
    { expectedAuthorizationVersion: 0 },
    { expectedAuthorizationVersion: 1.5 },
    { expectedFlowRevision: -1 },
    { expectedFlowRevision: Number.NaN },
  ]) {
    assert.ok(replay.validateReplayInput({ ...valid, ...wrong }));
  }
});

test('signed comparison is a read-only bearer request with no false findings', async () => {
  const { calls } = setup();
  await signIn();
  const result = await replay.loadSignedReplayComparison(
    'eng-live', 'wf-live', 'flow-live', 'task-replay-proposal', 'step-observed',
  );
  assert.equal(result.status, 'candidate_needs_independent_review');
  assert.equal(result.findings_count, 0);
  assert.equal(result.authorization_violation_verified, false);
  const reads = calls.filter(call => call.path.includes('signed-comparisons'));
  assert.equal(reads.length, 1);
  assert.equal(reads[0].init.method, 'GET');
  assert.equal(reads[0].init.headers.Authorization, 'Bearer local-ui-fixture-bearer');
  assert.equal(reads[0].query.get('flow_id'), 'flow-live');
  assert.equal(reads[0].query.get('replay_task_id'), 'task-replay-proposal');
  assert.equal(reads[0].query.get('step_id'), 'step-observed');
  assert.equal(calls.filter(call => call.init.method === 'POST').length, 0);
});

test('comparison refuses fabricated independent success and arbitrary source IDs', async () => {
  const { calls } = setup({
    comparison: {
      flow_id: 'flow-live', replay_task_id: 'task-replay-proposal',
      step_id: 'step-observed', status: 'verified_idor',
      provider_testimony_only: false, authorization_violation_verified: true,
      source_authenticity_verified: true, target_effect_verified: true,
      findings_count: 1, reason: 'verified',
    },
  });
  await signIn();
  await assert.rejects(replay.loadSignedReplayComparison(
    'eng-live', 'wf-live', 'flow-live', 'task-replay-proposal', 'step-observed',
  ), /cannot independently establish/);
  const prior = calls.length;
  await assert.rejects(replay.loadSignedReplayComparison(
    'eng-live', 'wf-live', 'flow-live', '../../task', 'step-observed',
  ), /Explicit confirmed/);
  assert.equal(calls.length, prior);
});

test('real service verifies durable source, Flow, signer and catalog before exact authenticated POST', async () => {
  const { calls } = setup();
  await signIn();
  const verified = await replay.verifyReplayProposal(engagement, flow, fields);
  assert.equal(verified.expectedAuthorizationVersion, 7);
  assert.equal(verified.expectedFlowRevision, 3);
  assert.equal(verified.sourceTaskId, 'task-source');
  assert.equal(verified.workflowId, 'wf-live');
  assert.equal(calls.filter(call => call.init.method === 'POST').length, 0);

  const receipt = await replay.submitWorkflowReplay(engagement, verified);
  assert.deepEqual(receipt, {
    status: 'awaiting_execution_approval',
    task_id: 'task-replay-proposal',
    workflow_id: 'wf-live',
    execution_started: false,
  });
  const posts = calls.filter(call => call.init.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].path, '/engagements/eng-live/workflows/wf-live/replay');
  assert.equal(posts[0].query.toString(), '');
  assert.equal(posts[0].init.headers.Authorization, 'Bearer local-ui-fixture-bearer');
  assert.equal(posts[0].init.credentials, 'omit');
  assert.equal(posts[0].init.redirect, 'error');
  assert.deepEqual(JSON.parse(posts[0].init.body), {
    source_user_label: 'user_a',
    target_user_label: 'user_b',
    expected_authorization_version: 7,
    flow_id: 'flow-live',
    source_task_id: 'task-source',
    expected_flow_revision: 3,
  });
  assert.equal(Object.hasOwn(JSON.parse(posts[0].init.body), 'confirm_execution'), false);
  assert.equal(calls.filter(call => call.path === '/engagements/eng-live/workflows/replay-sources').length >= 2, true);
  assert.doesNotMatch(posts[0].url, /Bearer|token=|authorization_version/);
});

test('a non-senior operator cannot read catalog, verify or POST', async () => {
  const { calls } = setup({ role: 'operator' });
  await signIn('operator');
  await assert.rejects(
    replay.loadWorkflowReplaySources('eng-live', 'flow-live'),
    /senior_operator/,
  );
  await assert.rejects(
    replay.verifyReplayProposal(engagement, flow, fields),
    /senior_operator/,
  );
  assert.equal(calls.filter(call => call.path !== '/auth/me').length, 0);
});

test('missing or stale authoritative catalog and identity disables verification before POST', async () => {
  for (const mismatch of [
    { revision: 4 },
    { catalogVersion: 8 },
    { sources: [] },
    { identities: ['user_a'] },
    { taskStatus: 'running' },
  ]) {
    const { calls } = setup(mismatch);
    await signIn();
    await assert.rejects(
      replay.verifyReplayProposal(engagement, flow, fields),
      /revision|version|source|identity|completed|unavailable|match|Flow/i,
    );
    assert.equal(calls.filter(call => call.init.method === 'POST').length, 0);
  }
});

test('authorization revoke after review fences POST and leaves no fabricated findings', async () => {
  const { calls, config } = setup();
  await signIn();
  const evidence = await replay.verifyReplayProposal(engagement, flow, fields);
  config.authorizationVersion = null;
  await assert.rejects(
    replay.submitWorkflowReplay(engagement, evidence),
    /signed authorization|revoked|expired/i,
  );
  assert.equal(calls.filter(call => call.init.method === 'POST').length, 0);
});

test('unsupported response, server refusal and timeout never become replay success', async () => {
  for (const mismatch of [
    { apiReceipt: { status: 'completed', task_id: 'task-replay-proposal', workflow_id: 'wf-live', execution_started: true } },
    { apiReceipt: { detail: 'signed Flow conflict' }, apiStatus: 409 },
    { apiReceipt: { status: 'awaiting_execution_approval', task_id: 'task-replay-proposal', workflow_id: 'other', execution_started: false } },
  ]) {
    const { calls } = setup(mismatch);
    await signIn();
    const evidence = await replay.verifyReplayProposal(engagement, flow, fields);
    await assert.rejects(
      replay.submitWorkflowReplay(engagement, evidence),
      /outcome UNKNOWN|not confirmed/,
    );
    assert.equal(calls.filter(call => call.init.method === 'POST').length, 1);
  }
  const { calls } = setup({ apiNetworkFailure: true });
  await signIn();
  const evidence = await replay.verifyReplayProposal(engagement, flow, fields);
  await assert.rejects(
    replay.submitWorkflowReplay(engagement, evidence),
    /Synthetic lost POST response/,
  );
  assert.equal(calls.filter(call => call.init.method === 'POST').length, 1);
});

test('mounted panel defaults to disabled and visibly separates proposal, approval, unknown and findings', async () => {
  const { calls } = setup();
  await signIn();
  const html = renderToStaticMarkup(
    createElement(component.SignedWorkflowReplayPanel, { engagement, flow }),
  );
  assert.match(html, /VERIFIED COMPLETED MAP_WORKFLOW SOURCE/);
  assert.match(html, /DISTINCT VERIFIED TARGET IDENTITY/);
  assert.match(html, /SENIOR: PROPOSE DIFFERENTIAL REPLAY/);
  assert.match(html, /Remote effects remain UNKNOWN/);
  assert.match(html, /Verified findings: none/);
  assert.match(html, /disabled/);
  assert.equal(calls.filter(call => call.init.method === 'POST').length, 0);
  const page = readFileSync(fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)), 'utf8');
  assert.match(page, /import \{ SignedWorkflowReplayPanel \}/);
  assert.match(page, /<SignedWorkflowReplayPanel/);
  assert.match(page, /engagement=\{selectedEngagement \?\? null\}/);
  assert.match(page, /flow=\{selectedFlow\}/);
  assert.match(page, /!flowDetailsCurrent/);
});
