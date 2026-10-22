import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const fetchOriginal = globalThis.fetch;
let vite, auth, service, panel;
let calls = [], reply;
const eng = 'eng-mcp-catalog';
const flow = 'flow-mcp-catalog';

function catalog() {
  return {
    engagement_id: eng, flow_id: flow, flow_revision: 3,
    authorization_version: 2, catalog_kind: 'declarations_only_unverified',
    execution_authorized: false,
    servers: [{
      server_id: 'browser_mcp', manifest_initialized: true, circuit_state: 'closed',
      runtime_health_verified: false,
      tools: [{
        name: 'inspect_only', side_effect_class: 'READ_ONLY',
        declared_requires_approval: false, declared_scope_check: true,
        signed_task_required_for_execution: true, execution_authorized: false,
        runtime_health_verified: false,
      }],
    }],
  };
}

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/mcpToolCatalog.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/McpToolCatalogPanel.tsx');
});
after(async () => {
  auth?.signOut(); globalThis.fetch = fetchOriginal; await vite?.close();
});

async function signIn(role = 'operator') {
  auth.signOut(); calls = []; reply = catalog();
  globalThis.fetch = async (url, options = {}) => {
    const path = new URL(String(url)).pathname;
    calls.push({ url: String(url), options });
    if (path === '/auth/me') return { ok: true, status: 200, json: async () => ({ sub: 'owner', role, exp: null }) };
    if (path.endsWith('/flow-tool-catalog')) return { ok: true, status: 200, json: async () => structuredClone(reply) };
    throw new Error('No other endpoint should be called');
  };
  await auth.signIn('test-only-mcp-token'); calls = [];
}

test('actual mounted Flow UX is read-only, no tool-execute control or private data', async () => {
  await signIn();
  const html = renderToStaticMarkup(createElement(panel.McpToolCatalogPanel,
    { engagementId: eng, flowId: flow, revision: 3, flowStatus: 'running' }));
  assert.match(html, /READ DECLARED TOOLS \(GET ONLY\)/);
  assert.match(html, /does NOT probe providers, run tools/);
  assert.doesNotMatch(html, /Bearer test-only-mcp-token|private-token|Execute tool/i);
  const page = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');
  assert.match(page, /import \{ McpToolCatalogPanel \}/);
  assert.match(page, /<McpToolCatalogPanel/);
  assert.match(page, /flowStatus=\{selectedFlow\.status\}/);
  const source = readFileSync(new URL('../src/components/flows/McpToolCatalogPanel.tsx', import.meta.url), 'utf8');
  assert.match(source, /authorizationStatus\(engagementId\)/);
  assert.doesNotMatch(source, /executeTool|MCPExecute|startTask|dangerouslySetInnerHTML/);
});

test('real client performs one signed GET with bearer in header, never in URL', async () => {
  await signIn();
  assert.deepEqual(await service.readSignedToolCatalog(eng, flow, 3, 2), catalog());
  assert.equal(calls.length, 1);
  const call = calls[0];
  assert.match(call.url, /flow-tool-catalog\?flow_id=flow-mcp-catalog/);
  assert.match(call.url, /expected_flow_revision=3&expected_authorization_version=2/);
  assert.equal(call.options.method, 'GET');
  assert.equal(call.options.headers.Authorization, 'Bearer test-only-mcp-token');
  assert.equal(call.options.credentials, 'omit');
  assert.equal(call.options.cache, 'no-store');
  assert.equal(call.options.redirect, 'error');
  assert.doesNotMatch(call.url, /Bearer|test-only-mcp-token|execute|credential/i);
});

test('malicious/private or forged executable metadata is rejected, never returned', async () => {
  await signIn();
  const valid = catalog();
  const mutations = [
    { ...valid, execution_authorized: true },
    { ...valid, secret_token: 'Bearer private' },
    { ...valid, catalog_kind: 'target_verified' },
    { ...valid, authorization_version: 9 },
    { ...valid, servers: [{ ...valid.servers[0], host: 'localhost', port: 8091 }] },
    { ...valid, servers: [{ ...valid.servers[0], tools: [{ ...valid.servers[0].tools[0],
      response_body: 'private-data' }] }] },
    { ...valid, servers: [{ ...valid.servers[0], tools: [{ ...valid.servers[0].tools[0],
      execution_authorized: true }] }] },
    { ...valid, servers: [{ ...valid.servers[0], manifest_initialized: false }] },
  ];
  for (const mutation of mutations) {
    reply = mutation;
    await assert.rejects(service.readSignedToolCatalog(eng, flow, 3, 2));
  }
});

test('untrusted senior/junior actors and stale signed versions make zero registry requests', async () => {
  await signIn('dev_api_token');
  await assert.rejects(service.readSignedToolCatalog(eng, flow, 3, 2));
  assert.equal(calls.length, 0);
  await signIn();
  await assert.rejects(service.readSignedToolCatalog(eng, flow, -1, 2));
  await assert.rejects(service.readSignedToolCatalog(eng, flow, 3, 0));
  await assert.rejects(service.readSignedToolCatalog(eng, 'flow-invalid<script>', 3, 2));
  assert.equal(calls.length, 0);
});

test('operator changes during awaited read never receive prior tenant catalog', async () => {
  await signIn();
  let replyRead;
  let resume;
  globalThis.fetch = async (url, options) => {
    const path = new URL(String(url)).pathname;
    if (path === '/auth/me') return { ok: true, status: 200, json: async () => ({ sub: 'new-operator', role: 'operator', exp: null }) };
    if (path.endsWith('/flow-tool-catalog')) return { ok: true, status: 200,
      json: () => new Promise(resolve => { resume = resolve; }) };
    throw new Error('No other endpoint');
  };
  replyRead = service.readSignedToolCatalog(eng, flow, 3, 2);
  for (let i = 0; i < 200 && !resume; i++) await Promise.resolve();
  assert.equal(typeof resume, 'function');
  auth.signOut();
  resume(catalog());
  await assert.rejects(replyRead);
});
