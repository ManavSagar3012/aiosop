import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

let vite, auth, service, panel;
const originalFetch = globalThis.fetch;
const expiration = Math.floor(Date.now() / 1000) + 3600;
const six = [
  'recon-mcp', 'payload-mcp', 'nuclei-mcp', 'shodan-mcp', 'threat-intel-mcp', 'security-bridge',
];
let requests = [];
const root = fileURLToPath(new URL('../', import.meta.url));

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/nativeInertFleetOperator.ts');
  panel = await vite.ssrLoadModule('/src/components/NativeInertFleetOperatorPanel.tsx');
});
after(async () => { auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close(); });

function response(value, code = 200) { return new Response(JSON.stringify(value), { status: code, headers: { 'content-type': 'application/json' } }); }
function hostUnconfigured() {
  return { lifecycle: 'host_unconfigured', classification: 'host_local_inert_process_only', processes: [],
    mcp_initialized: false, signed_0033_witness_verified: false, native_target_execution_enabled: false,
    target_effect_verified: false, automatic_action_retry_authorized: false, production_certified: false };
}
async function login(role = 'senior_operator') {
  auth.signOut(); requests = [];
  globalThis.fetch = async (url, config) => {
    if (new URL(String(url)).pathname === '/auth/me') return response({ sub: 'owned-operator', role, exp: expiration });
    requests.push({ url: String(url), config }); return response(hostUnconfigured());
  };
  await auth.signIn('memory-only-test-token');
  requests = [];
}

test('senior status uses only bounded local GET and never process/action controls', async () => {
  await login();
  const value = await service.readNativeInertFleetStatus();
  assert.equal(value.lifecycle, 'host_unconfigured');
  assert.equal(value.target_effect_verified, false);
  assert.equal(requests.length, 1);
  const [{ url, config }] = requests;
  assert.equal(new URL(url).pathname, '/system/native-inert-fleet/status');
  assert.equal(config.method, 'GET');
  assert.equal(config.redirect, 'error');
  assert.equal(config.credentials, 'omit');
  assert.equal(config.headers.Authorization, 'Bearer memory-only-test-token');
  assert.doesNotMatch(url, /token|start|stop|execute/);
});

test('plain process visibility cannot imply signed authority, secrets, or execution', async () => {
  await login();
  const variants = [
    x => { x.target_effect_verified = true; },
    x => { x.signed_0033_witness_verified = true; },
    x => { x.mcp_initialized = true; },
    x => { x.production_certified = true; },
    x => { x.processes = [{ server_id: six[0], observed: true }]; },
    x => { x.token = 'disclosed-secret'; },
    x => { x.lifecycle = 'production-ready'; },
  ];
  for (const mutate of variants) {
    const sample = hostUnconfigured(); mutate(sample);
    globalThis.fetch = async () => response(sample);
    await assert.rejects(() => service.readNativeInertFleetStatus());
  }
  globalThis.fetch = async () => response({ ...hostUnconfigured(), lifecycle: 'running_inert_unavailable', processes: six.map(server_id => ({ server_id, observed: true })) });
  const inert = await service.readNativeInertFleetStatus();
  assert.equal(inert.processes.length, 6);
  assert.equal(inert.signed_0033_witness_verified, false);
});

test('non senior operator cannot read native process state', async () => {
  await login('operator');
  await assert.rejects(() => service.readNativeInertFleetStatus(), /senior/);
  assert.equal(requests.length, 0);
});

test('panel contains NO process start/stop/scan buttons or invented target proof', async () => {
  await login();
  const html = renderToStaticMarkup(createElement(panel.NativeInertFleetOperatorPanel));
  assert.match(html, /NOT PRODUCTION CERTIFIED \/ NOT READY/);
  assert.match(html, /Refresh inert process status/);
  assert.doesNotMatch(html, /<button[^>]*>(?:start|stop|scan|execute)/i);
  assert.doesNotMatch(html, /memory-only-test-token/);
});
