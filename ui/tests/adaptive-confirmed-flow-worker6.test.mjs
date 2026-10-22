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
    root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
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

test('separate human confirmation pins signer Flow revision target and true consent in POST body', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return response({ status: 'pending_dispatch_review',
      objective_task_id: 'task-new', subtask_id: 'subtask-new',
      dispatch_required: true, approval_required: true, execution_started: false,
    });
  };
  const receipt = await flows.flowApi.prepareConfirmedAdaptiveFollowup(
    'apr/test', 6, 17, 'example.com',
  );
  assert.equal(receipt.execution_started, false);
  assert.equal(receipt.dispatch_required, true);
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/approvals\/apr%2Ftest\/adaptive\/prepare-followup$/);
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    request_id: 'apr/test', expected_authorization_version: 6,
    expected_flow_revision: 17, confirmed_target: 'example.com',
    confirm_execution: true,
  });
  assert.doesNotMatch(calls[0].url, /Bearer|token=|authorization_version/);
  assert.doesNotMatch(calls[0].url, /\/dispatch\b/);
});

test('stale signed Flow admission fails without fabricated execution success', async () => {
  globalThis.fetch = async () => response({ detail: 'Adaptive follow-up denied by signed ROE' }, 409);
  await assert.rejects(
    flows.flowApi.prepareConfirmedAdaptiveFollowup('apr', 3, 7, 'example.com'),
    (err) => err.status === 409 && /signed/.test(err.message),
  );
});

test('React confirmation is senior-only, never schedules and explicitly requires later dispatch', () => {
  const source = readFileSync(fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)), 'utf8');
  assert.match(source, /const confirmAdaptiveFollowup = /);
  assert.match(source, /!canAttemptApproval/);
  assert.match(source, /window\.confirm\(/);
  assert.match(source, /flowApi\.prepareConfirmedAdaptiveFollowup\(/);
  assert.match(source, /pending_dispatch_review/);
  assert.match(source, /execution_started !== false/);
  assert.match(source, /dispatch_required !== true/);
  assert.match(source, /SEPARATE|separate/);
  assert.match(source, /SENIOR: CONFIRM & PREPARE FOLLOW-UP PLAN/);
  assert.doesNotMatch(source, /schedule_task\(/);
});
