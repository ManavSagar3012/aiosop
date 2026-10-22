import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const root = fileURLToPath(new URL('../', import.meta.url));
const fetchBefore = globalThis.fetch;
let vite;
let api;

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/flows.ts');
});

after(async () => {
  globalThis.fetch = fetchBefore;
  await vite?.close();
});

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: async () => payload,
  };
}

test('senior adaptive continuation submits only approval identity and signed revisions', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return response({
      status: 'proposal_ready', approval_id: 'apr-adaptive/1',
      execution_started: false, review_required: true,
      proposal: { action: 'stop', parameters: {} },
    });
  };
  const data = await api.flowApi.continueApprovedAdaptivePlanner('apr-adaptive/1', 11, 4);
  assert.equal(data.execution_started, false);
  assert.equal(data.review_required, true);
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/approvals\/apr-adaptive%2F1\/adaptive\/continue$/);
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    request_id: 'apr-adaptive/1',
    expected_authorization_version: 11,
    expected_flow_revision: 4,
  });
  assert.doesNotMatch(calls[0].url, /token=|Bearer|auth_version=/);
  assert.doesNotMatch(calls[0].url, /dispatch|schedule|execute_strategic_action/);
});

test('persistent review reads do not send a POST or trigger provider execution', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return response(url.includes('/adaptive/proposals')
      ? [{ approval_id: 'apr-adaptive', status: 'proposal_ready' }]
      : { approval_id: 'apr-adaptive', status: 'proposal_ready' });
  };
  const list = await api.flowApi.listAdaptivePlannerProposals('eng-test/1');
  const single = await api.flowApi.getAdaptivePlannerProposal('apr-adaptive');
  assert.equal(list.length, 1);
  assert.equal(single.status, 'proposal_ready');
  assert.match(calls[0].url, /\/approvals\/adaptive\/proposals\?engagement_id=eng-test%2F1$/);
  assert.match(calls[1].url, /\/approvals\/apr-adaptive\/adaptive\/proposal$/);
  assert.ok(calls.every(({ init }) => init.method === undefined));
});

test('revoked/stale/unknown outcome cannot be represented as success', async () => {
  globalThis.fetch = async () => response({ detail: 'Planner approval was revoked or consumed' }, 409);
  await assert.rejects(
    api.flowApi.continueApprovedAdaptivePlanner('apr', 3, 8),
    (error) => error.status === 409 && /revoked/.test(error.message),
  );
});

test('FlowOperations adaptive UI requests proposal only, requires senior review and does not dispatch', () => {
  const source = readFileSync(fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)), 'utf8');
  assert.match(source, /purpose === 'adaptive_planning' && !canAttemptApproval/);
  assert.match(source, /flowApi\.continueApprovedAdaptivePlanner\(/);
  assert.match(source, /execution_started !== false/);
  assert.match(source, /PROPOSE ADAPTIVE NEXT STEP \(SENIOR\)/);
  assert.match(source, /ADAPTIVE PROPOSAL ONLY/);
  assert.match(source, /flowApi\.listAdaptivePlannerProposals/);
  assert.match(source, /No agent, scan or follow-up task has been scheduled/);
  assert.doesNotMatch(source, /adaptive_planner\.on_task_completed\(/);
});
