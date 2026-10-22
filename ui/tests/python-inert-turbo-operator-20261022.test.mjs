import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const initialFetch = globalThis.fetch;
let vite, auth, service, panel, requests = [];
const expiration = Math.floor(Date.now() / 1000) + 200;

before(async () => {
  vite = await createServer({ root: fileURLToPath(new URL('../', import.meta.url)), appType: 'custom',
    logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/pythonInertTurboReadback.ts');
  panel = await vite.ssrLoadModule('/src/components/PythonInertTurboOperatorPanel.tsx');
});
after(async () => { auth?.signOut(); globalThis.fetch = initialFetch; await vite?.close(); });

const status = () => ({
  service_id: 'turbo-intruder-mcp', lifecycle: 'host_unconfigured',
  process_owned: false, listener_owned: false, health_unavailable: false,
  mcp_initialized: false, signed_action_verified: false,
  native_execution_enabled: false, independent_target_effect_verified: false,
  production_certified: false,
});

const response = (value, code = 200) => new Response(JSON.stringify(value), { status: code });

async function signed(role = 'senior_operator') {
  auth.signOut();
  globalThis.fetch = async (uri, config) => {
    if (new URL(String(uri)).pathname === '/auth/me')
      return response({ sub: 'host-senior-fixture', role, exp: expiration });
    requests.push({ uri: String(uri), config });
    return response(status());
  };
  await auth.signIn('private-fixture-memory-token');
  requests = [];
}

test('senior has read-only exact host-operator GET, not a process-launch control', async () => {
  await signed();
  const observed = await service.readPythonInertTurboStatus();
  assert.equal(observed.lifecycle, 'host_unconfigured');
  assert.equal(observed.native_execution_enabled, false);
  assert.equal(requests.length, 1);
  const [{ uri, config }] = requests;
  assert.equal(new URL(uri).pathname, '/system/python-inert-turbo/status');
  assert.equal(config.method, 'GET');
  assert.equal(config.credentials, 'omit');
  assert.equal(config.redirect, 'error');
  assert.equal(config.headers.Authorization, 'Bearer private-fixture-memory-token');
  assert.doesNotMatch(uri, /start|stop|execute|token|key|target/);
});

test('provider-ready claims, extra keys and malformed process ownership fail closed', async () => {
  await signed();
  for (const change of [
    doc => { doc.native_execution_enabled = true; },
    doc => { doc.signed_action_verified = true; },
    doc => { doc.independent_target_effect_verified = true; },
    doc => { doc.production_certified = true; },
    doc => { doc.process_owned = true; },
    doc => { doc.secret_path = 'private-source'; },
    doc => { doc.lifecycle = 'ready'; },
  ]) {
    const claim = status();
    change(claim);
    globalThis.fetch = async () => response(claim);
    await assert.rejects(() => service.readPythonInertTurboStatus());
  }
  globalThis.fetch = async () => response({
    ...status(), lifecycle: 'running_disabled_unavailable',
    process_owned: true, listener_owned: true, health_unavailable: true,
  });
  const result = await service.readPythonInertTurboStatus();
  assert.equal(result.process_owned, true);
  assert.equal(result.production_certified, false);
});

test('non-senior role cannot read host process or send any request', async () => {
  await signed('operator');
  await assert.rejects(() => service.readPythonInertTurboStatus(), /senior/);
  assert.equal(requests.length, 0);
});

test('rendered panel cannot request start/stop/scan/attack or reveal bearer', async () => {
  await signed();
  const html = renderToStaticMarkup(createElement(panel.PythonInertTurboOperatorPanel));
  assert.match(html, /NOT PRODUCTION CERTIFIED \/ NOT READY/);
  assert.match(html, /Read disabled Turbo process status/);
  assert.doesNotMatch(html, /<button[^>]*>(?:start|stop|scan|attack|execute)/i);
  assert.doesNotMatch(html, /private-fixture-memory-token/);
});
