/** Unmounted optional fleet panel: real server contract, no credential disclosure. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const originalWindow = globalThis.window;
const expiry = Math.floor(Date.now() / 1000) + 3600;
const ids = [
  'burp-mcp', 'recon-mcp', 'payload-mcp', 'nuclei-mcp',
  'shodan-mcp', 'threat-intel-mcp', 'security-bridge', 'browser-mcp',
  'source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp',
];
const critical = new Set([
  'nuclei-mcp', 'browser-mcp', 'source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp',
]);
const sample = () => ({
  catalog_scope: 'configured_fleet_process_visibility_only',
  configured_count: 11,
  independently_verified_operations: null,
  production_certified: false,
  release_decision: 'NOT PRODUCTION CERTIFIED / NOT READY',
  services: ids.map((id, i) => ({
    server_id: id,
    importance: critical.has(id) ? 'critical' : 'optional',
    process_registered: i === 0,
    process_initialized: i === 0 ? true : null,
    process_circuit: i === 0 ? 'closed' : null,
    runtime_health_verified: false,
    current_authorized_operation_verified: false,
    independent_target_effect_verified: false,
    production_certified: false,
    qualification: i === 0 ? 'process_registration_only' : 'not_verified',
  })),
});
const reply = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json' },
});

let vite, auth, svc, panel, pending = [], calls = [];
before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  svc = await vite.ssrLoadModule('/src/services/mcpFleetOperatorReadiness.ts');
  panel = await vite.ssrLoadModule('/src/components/McpFleetOperatorReadinessPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  if (originalWindow === undefined) delete globalThis.window;
  else globalThis.window = originalWindow;
  await vite?.close();
});

async function login(role = 'senior_operator') {
  auth.signOut();
  pending = [];
  calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const request = { url: new URL(String(url)), options };
    if (request.url.pathname === '/auth/me')
      return reply({ sub: 'current-senior', role, exp: expiry });
    calls.push(request);
    if (!pending.length) throw new Error('Unqueued fleet request');
    const answer = pending.shift();
    return typeof answer === 'function' ? await answer(request) : answer;
  };
  await auth.signIn('memory-only-senior-bearer');
  calls = [];
}
const queue = (...responses) => pending.push(...responses);

test('optional panel has exactly eleven statuses but never implies health or execution', async () => {
  await login();
  const html = renderToStaticMarkup(createElement(panel.McpFleetOperatorReadinessPanel));
  assert.equal((html.match(/<tr class=/g) || []).length, 11);
  for (const id of ids) assert.ok(html.includes(id), id);
  assert.match(html, /NOT PRODUCTION CERTIFIED \/ NOT READY/);
  assert.match(html, /Current authorization/);
  assert.match(html, /Independent target effect/);
  assert.match(html, /Runtime health: not verified/);
  assert.match(html, /Refresh GET only/);
  assert.doesNotMatch(html, /memory-only-senior-bearer|password|127\.0\.0\.1:8200|execute now/i);
  assert.doesNotMatch(html, /<button[^>]*>\s*(?:execute|approve|reset|ping|scan)/i);
  const currentAdministration = readFileSync(new URL('../src/pages/Administration.tsx', import.meta.url), 'utf8');
  assert.match(currentAdministration, /\/system\/mcp\/fleet-readiness/);
  assert.match(currentAdministration, /All 11 MCP services/);
  assert.doesNotMatch(currentAdministration, /McpFleetOperatorReadinessPanel/);
});

test('read original 11-entry senior GET only; exact process/certification separation', async () => {
  await login();
  queue(reply(sample()));
  const view = await svc.readMcpFleetOperatorReadiness();
  assert.deepEqual(view.services.map(row => row.server_id), ids);
  assert.deepEqual(svc.MCP_FLEET_IDS, ids);
  assert.equal(view.configured_count, 11);
  assert.equal(view.independently_verified_operations, null);
  assert.equal(view.services[0].process_registered, true);
  assert.equal(view.services[0].current_authorized_operation_verified, false);
  assert.equal(view.services[0].independent_target_effect_verified, false);
  assert.equal(view.services[0].runtime_health_verified, false);
  assert.equal(view.production_certified, false);
  assert.equal(calls.length, 1);
  const [{ url, options }] = calls;
  assert.equal(url.pathname, '/system/mcp/fleet-readiness');
  assert.equal(url.search, '');
  assert.equal(options.method, 'GET');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.headers.Authorization, 'Bearer memory-only-senior-bearer');
  assert.doesNotMatch(url.toString(), /memory-only-senior-bearer|access_token|private/);
});

test('foreign, duplicate, truncated or overstated fleet entries never become process truth', async () => {
  await login();
  const mutations = [
    x => { x.services[0].server_id = 'private-customer'; },
    x => { x.services[0].server_id = x.services[1].server_id; },
    x => { x.services.pop(); },
    x => { x.configured_count = 10; },
    x => { x.catalog_scope = 'fully_certified'; },
    x => { x.independently_verified_operations = 0; },
    x => { x.release_decision = 'READY'; },
    x => { x.production_certified = true; },
    x => { x.services[0].runtime_health_verified = true; },
    x => { x.services[0].current_authorized_operation_verified = true; },
    x => { x.services[0].independent_target_effect_verified = true; },
    x => { x.services[0].production_certified = true; },
    x => { x.services[0].importance = 'critical'; },
    x => { x.services[0].process_circuit = 'ready'; },
    x => { x.services[0].process_initialized = null; },
    x => { x.services[1].process_initialized = false; },
    x => { x.services[1].process_circuit = 'closed'; },
    x => { x.services[0].qualification = 'verified'; },
    x => { x.services[0].server_private_port = 8200; },
    x => { x.services[0].manifest = ['private-tenant-tool']; },
    x => { x.services[0].token = 'secret'; },
    x => { x.api_url = 'http://internal-mcp.local:8443'; },
  ];
  for (const mutate of mutations) {
    const changed = sample(); mutate(changed);
    queue(reply(changed));
    await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /fleet|MCP/i);
  }
  assert.equal(calls.length, mutations.length);
  assert.ok(calls.every(x => x.options.method === 'GET'));
});

test('duplicate JSON security keys, oversized body, malformed bytes and non-200 fail closed', async () => {
  await login();
  const valid = JSON.stringify(sample());
  queue(new Response(valid.replace(
    '"production_certified":false',
    '"production_certified":true,"production_certified":false',
  ), { status: 200 }));
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /Duplicate/);
  queue(new Response(JSON.stringify(sample()).replace(
    '"server_id":"burp-mcp"',
    '"server_id":"burp-mcp","server_id":"burp-mcp"',
  ), { status: 200 }));
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /Duplicate/);
  queue(new Response('x'.repeat(16385), { status: 200 }));
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /limit/i);
  queue(new Response('{broken', { status: 200 }));
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness());
  queue(reply({ detail: 'private internal connection' }, 503));
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /unavailable/);
  queue(new Error('network unavailable'));
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness());
  assert.equal(calls.length, 6);
});

test('only verified unexpired senior can read; insecure browser origin and abort deny before GET', async () => {
  auth.signOut();
  calls = [];
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /senior-only/);
  assert.equal(calls.length, 0);
  await login('operator');
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /senior-only/);
  assert.equal(calls.length, 0);
  await login();
  globalThis.window = { location: { protocol: 'http:', hostname: 'nonloopback.invalid' } };
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /senior-only/);
  if (originalWindow === undefined) delete globalThis.window;
  else globalThis.window = originalWindow;
  assert.equal(calls.length, 0);
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(ac.signal), /cancelled/);
  assert.equal(calls.length, 0);
});

test('lost identity during response/body read denies and does not retry or use previous data', async () => {
  await login();
  queue(() => { auth.signOut(); return reply(sample()); });
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness(), /senior-only|changed/);
  assert.equal(calls.length, 1);
  await login();
  queue(new Response(JSON.stringify(sample()), { status: 200 }));
  const ready = await svc.readMcpFleetOperatorReadiness();
  assert.equal(ready.services.length, 11);
  queue(() => {
    auth.signOut();
    return new Response(JSON.stringify(sample()), { status: 200 });
  });
  await assert.rejects(() => svc.readMcpFleetOperatorReadiness());
});

test('fixed roster only; no execution path, credential storage, provider tool catalogs or private port', () => {
  const serviceSource = readFileSync(new URL('../src/services/mcpFleetOperatorReadiness.ts', import.meta.url), 'utf8');
  const panelSource = readFileSync(new URL('../src/components/McpFleetOperatorReadinessPanel.tsx', import.meta.url), 'utf8');
  assert.match(serviceSource, /\/system\/mcp\/fleet-readiness/);
  assert.match(serviceSource, /method: 'GET'/);
  assert.doesNotMatch(serviceSource, /method: 'POST'|localStorage\.|sessionStorage\.|document\.cookie/);
  assert.doesNotMatch(panelSource, /\/system\/mcp\/[^']*\/(?:ping|reset-circuit)|executeMcp|POST/);
  assert.equal(svc.unverifiedMcpFleetRows().length, 11);
  assert.ok(svc.unverifiedMcpFleetRows().every(row => !row.process_registered
    && row.process_initialized === null && !row.production_certified));
});
