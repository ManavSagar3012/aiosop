import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const previousFetch = globalThis.fetch;
let vite, api, supervision;

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  supervision = await vite.ssrLoadModule('/src/services/supervision.ts');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = previousFetch;
  await vite?.close();
});

const original = {
  server_id: 'pinned-provider', request_id: 'req-original',
  task_id: 'task-scoped', tool_name: 'remote_status',
  status: 'outcome_unknown', authorization_version: 5,
};

test('explicit senior remote stop sends only original receipt tuple and reason, no tool arguments', async () => {
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/auth/me')) return { ok: true, json: async () => ({
      sub: 'owner', role: 'senior_operator',
      exp: Math.floor(Date.now() / 1000) + 120,
    }) };
    return { ok: true, json: async () => ({
      status: 'unknown', persisted_status: 'cancel_requested',
      provider_reported_stop: false, remote_stopped: false,
      safe_to_retry: false, external_effect_status: 'unknown',
    }) };
  };
  await api.signIn('signed-senior-runtime-only');
  const result = await supervision.supervisionApi.cancelPersistedMcpDispatch(
    'eng-owned', 'task-scoped', original, 'Human confirmed one-time stop request',
  );
  assert.equal(result.status, 'unknown');
  assert.equal(result.safe_to_retry, false);
  assert.equal(result.remote_stopped, false);
  const stop = calls[1];
  assert.equal(stop.url,
    api.API_BASE + '/supervision/engagements/eng-owned/tasks/task-scoped/mcp/cancel-persisted');
  assert.equal(stop.options.method, 'POST');
  assert.equal(stop.options.headers.Authorization, 'Bearer signed-senior-runtime-only');
  assert.deepEqual(JSON.parse(stop.options.body), {
    server_id: 'pinned-provider',
    request_id: 'req-original',
    expected_authorization_version: 5,
    reason: 'Human confirmed one-time stop request',
  });
  assert.equal(stop.url.includes('signed-senior-runtime-only'), false);
  assert.equal(stop.url.includes('/mcp/execute'), false);
  assert.equal(stop.options.body.includes('tool_name'), false);
});

test('stale signed version, target mismatch or absent operator reason denies locally', async () => {
  let requests = 0;
  globalThis.fetch = async () => {
    requests += 1;
    throw Error('unexpected');
  };
  for (const [receipt, reason] of [
    [{ ...original, task_id: 'task-other' }, 'Human accepted remote cancellation'],
    [{ ...original, authorization_version: 0 }, 'Human accepted remote cancellation'],
    [{ ...original, server_id: 'https://evil.invalid' }, 'Human accepted remote cancellation'],
    [original, 'no'],
  ]) {
    assert.throws(() => supervision.supervisionApi.cancelPersistedMcpDispatch(
      'eng-owned', 'task-scoped', receipt, reason,
    ));
  }
  assert.equal(requests, 0);
});

test('supervisor uses explicit confirmation and never marks provider statement physical effect', () => {
  const panel = readFileSync(
    fileURLToPath(new URL('../src/components/flows/SupervisionPanel.tsx', import.meta.url)),
    'utf8',
  );
  assert.match(panel, /stopPersistedRemoteRequest/);
  assert.match(panel, /cancelPersistedMcpDispatch/);
  assert.match(panel, /window\.confirm/);
  assert.match(panel, /REQUEST ONE POST-RESTART REMOTE STOP/);
  assert.match(panel, /authorization\.version === receipt\.authorization_version/);
  assert.match(panel, /No independent physical stop/);
});
