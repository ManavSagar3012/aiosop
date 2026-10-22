import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const oldFetch = globalThis.fetch;
let vite, api, supervision;

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  supervision = await vite.ssrLoadModule('/src/services/supervision.ts');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = oldFetch;
  await vite?.close();
});

test('bounded MCP sweep uses signed runtime bearer not URL or an execute route', async () => {
  const requests = [];
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith('/auth/me')) return {
      ok: true,
      json: async () => ({
        sub: 'operator-owned', role: 'operator',
        exp: Math.floor(Date.now() / 1000) + 180,
      }),
    };
    return {
      ok: true,
      json: async () => ({
        observed: [{
          server_id: 'mcp-server', request_id: 'req-claimed',
          status: 'unknown', persisted_status: 'outcome_unknown',
          safe_to_retry: false, external_effect_status: 'unknown',
        }],
        remaining_unobserved: 0,
        safe_to_retry: false,
        external_effect_status: 'unknown',
      }),
    };
  };
  await api.signIn('test-signed-runtime-bearer');
  const output = await supervision.supervisionApi.observePendingMcpDispatches(
    'eng-owner', 'task-original',
  );
  assert.equal(output.safe_to_retry, false);
  assert.equal(output.observed[0].status, 'unknown');
  assert.equal(requests.length, 2);
  const observed = requests[1];
  assert.equal(observed.url,
    api.API_BASE + '/supervision/engagements/eng-owner/tasks/task-original/mcp/reconcile-pending');
  assert.equal(observed.options.method, 'POST');
  assert.deepEqual(JSON.parse(observed.options.body), { limit: 6 });
  assert.equal(observed.options.headers.Authorization, 'Bearer test-signed-runtime-bearer');
  assert.equal(observed.url.includes('test-signed-runtime-bearer'), false);
  assert.equal(observed.url.includes('/mcp/execute'), false);
});

test('operator supervision marks remote results only as provider assertions', () => {
  const panel = readFileSync(
    fileURLToPath(new URL('../src/components/flows/SupervisionPanel.tsx', import.meta.url)),
    'utf8',
  );
  assert.match(panel, /observePendingMcpDispatches\(/);
  assert.match(panel, /OBSERVE UP TO 6 UNKNOWN REMOTE REQUESTS \(NO REPLAY\)/);
  assert.match(panel, /result\.safe_to_retry !== false/);
  assert.match(panel, /provider statements are not proof of physical target effects/);
  assert.doesNotMatch(panel, /remote effects confirmed successful/i);
});
