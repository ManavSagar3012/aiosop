import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let flows;

before(async () => {
  vite = await createServer({
    root,
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true },
  });
  flows = await vite.ssrLoadModule('/src/services/flows.ts');
});

after(async () => {
  globalThis.fetch = originalFetch;
  await vite?.close();
});

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300, status,
    headers: { get: () => 'application/json' },
    json: async () => body,
  };
}

test('internal planner POST pins expected signed ROE version and Flow revision', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return response({ id: 'apr-planner-1', status: 'approved' });
  };
  const answer = await flows.flowApi.resolveApproval(
    'apr-planner-1', 'approved', 'Human review of bounded model planning', {
      expected_authorization_version: 7, expected_flow_revision: 12,
    },
  );
  assert.equal(answer.status, 'approved');
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/approvals\/apr-planner-1\/resolve$/);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    request_id: 'apr-planner-1',
    decision: 'approved',
    notes: 'Human review of bounded model planning',
    expected_authorization_version: 7,
    expected_flow_revision: 12,
  });
  assert.doesNotMatch(calls[0].url, /token|Bearer|authorization_version|flow_revision/);
});

test('ordinary approval POST never invents signed planner revisions', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return response({ id: 'apr-regular', status: 'rejected' });
  };
  await flows.flowApi.resolveApproval('apr-regular', 'rejected', 'Not within ROE');
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    request_id: 'apr-regular',
    decision: 'rejected',
    notes: 'Not within ROE',
  });
});

test('planner approval UI requires trusted revision and explicitly avoids dispatch', () => {
  const source = readFileSync(fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)), 'utf8');
  assert.match(source, /action_type === 'planner_inference'/);
  assert.match(source, /Number\.isInteger\(approval\.authorization_version\)/);
  assert.match(source, /Number\.isInteger\(approval\.flow_revision\)/);
  assert.match(source, /explicitly re-run generation\/refinement after approval/);
  assert.doesNotMatch(source, /operator_id:\s*approverId/);
});
