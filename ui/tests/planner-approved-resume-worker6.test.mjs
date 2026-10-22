import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let server;
let api;

before(async () => {
  server = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await server.ssrLoadModule('/src/services/flows.ts');
});

after(async () => {
  globalThis.fetch = originalFetch;
  await server?.close();
});

function jsonResponse(body, status = 200) {
  return {
    status, ok: status >= 200 && status < 300,
    headers: { get: () => 'application/json' },
    json: async () => body,
  };
}

test('approved planner list is scoped to encoded engagement and uses authenticated API path', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse([{
      id: 'apr-planner-1', action_type: 'planner_inference', status: 'approved',
      flow_id: 'flow-a', flow_revision: 5, authorization_version: 2,
      planner_purpose: 'flow_generation', parent_task_id: 'task-parent',
    }]);
  };
  const result = await api.flowApi.listApprovedPlannerApprovals('eng /1&other=forged');
  assert.equal(result.length, 1);
  assert.equal(result[0].planner_purpose, 'flow_generation');
  assert.match(calls[0].url, /\/approvals\/planner-ready\?engagement_id=eng%20%2F1%26other%3Dforged$/);
  assert.equal(calls[0].init.method, undefined);
  assert.doesNotMatch(calls[0].url, /Bearer|token=|access_token/i);
});

test('planner resume uses existing scoped proposal routes and never dispatch endpoint', async () => {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse({ status: 'proposed', added_subtask_ids: ['sub-new'] });
  };
  const generated = await api.flowApi.generateProposals('flow/authorized', 'parent objective');
  const refined = await api.flowApi.refineProposals('flow/authorized', 'subtask done');
  assert.equal(generated.status, 'proposed');
  assert.equal(refined.status, 'proposed');
  assert.equal(calls.length, 2);
  assert.match(calls[0].url, /\/flows\/flow%2Fauthorized\/tasks\/parent%20objective\/generate$/);
  assert.match(calls[1].url, /\/flows\/flow%2Fauthorized\/subtasks\/subtask%20done\/refine$/);
  assert.ok(calls.every((call) => call.init.method === 'POST'));
  assert.ok(calls.every((call) => !call.url.includes('/dispatch')));
});

test('server denial is not converted into successful planner continuation', async () => {
  globalThis.fetch = async () => jsonResponse({ detail: 'Approval stale or revoked' }, 409);
  await assert.rejects(
    api.flowApi.generateProposals('flow-a', 'parent-a'),
    (error) => error.status === 409 && /revoked/.test(error.message),
  );
});

test('flow page shows durable parked state and requires explicit resume + signer revalidation', () => {
  const source = readFileSync(fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)), 'utf8');
  assert.match(source, /approvedPlannerApprovals/);
  assert.match(source, /readyFlowApprovals/);
  assert.match(source, /flow_revision_current !== true/);
  assert.match(source, /RESUME APPROVED PLANNER/);
  assert.match(source, /HUMAN APPROVED \/ NOT EXECUTED/);
  assert.match(source, /This explicitly requests a paid model inference/);
  assert.match(source, /flowApi\.generateProposals\(flowId, objective!\.id\)/);
  assert.match(source, /flowApi\.refineProposals\(flowId, source!\.id\)/);
  assert.match(source, /Adaptive continuation needs a dedicated authenticated endpoint/);
  assert.doesNotMatch(source, /resolveApproval\([\s\S]{0,300}dispatchSubtask\(/);
});
