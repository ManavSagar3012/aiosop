/** Offline tests for the real mounted two-source API client and inert search UI. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const expiry = Math.floor(Date.now() / 1000) + 3600;
const globalId = 'lib-' + 'a'.repeat(32);
const flowId = 'flow-review-20261021';
const doc = (source = 'user_global_0039') => ({
  id: source === 'user_global_0039' ? globalId : 'knowledge-' + 'c'.repeat(32),
  title: source === 'user_global_0039' ? 'My private guide' : 'Reviewed Flow note',
  doc_type: 'guide', revision: 2, sha256: 'b'.repeat(64), content_bytes: 128,
  ...(source === 'flow_local_0019_0038' ? {
    flow_id: flowId, source_flow_revision: 2, authorization_version: 2,
  } : {}),
  source, trust: 'untrusted_human_text', verified_target_evidence: false,
  approved_for_agent_context: false, safe_for_execution: false, reportable: false,
});
const page = items => ({ items, has_more: false });
const result = (query, sources) => ({
  status: 'metadata_only', query, sources,
  atomic_cross_source_snapshot: false, synthesis_performed: false,
  independent_target_effect_verified: false, approved_for_agent_context: false,
  safe_for_execution: false, reportable: false,
});
const reply = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json' },
});

let vite;
let auth;
let service;
let panel;
let pending = [];
let requests = [];
before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/operatorGlobalLibrary.ts');
  panel = await vite.ssrLoadModule('/src/components/OperatorGlobalLibraryPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

async function login() {
  auth.signOut();
  pending = [];
  requests = [];
  globalThis.fetch = async (value, options = {}) => {
    const url = new URL(String(value));
    if (url.pathname === '/auth/me') {
      return reply({ sub: 'current-operator', role: 'operator', exp: expiry });
    }
    requests.push({ url, options });
    if (!pending.length) throw new Error('Unexpected unqueued API request');
    const next = pending.shift();
    return typeof next === 'function' ? await next({ url, options }) : next;
  };
  await auth.signIn('signed-in-memory-bearer');
  requests = [];
}
const queue = (...responses) => pending.push(...responses);

test('standalone panel explains metadata-only source provenance and optional Flow scope', async () => {
  await login();
  const html = renderToStaticMarkup(createElement(panel.OperatorGlobalLibraryPanel));
  assert.match(html, /Search owned knowledge sources/);
  assert.match(html, /Optional current signed Flow scope/);
  assert.match(html, /original SHA-256/i);
  assert.match(html, /not independent target evidence/i);
  assert.match(html, /Search authorized sources/);
  assert.doesNotMatch(html, /signed-in-memory-bearer/);
});

test('signed user-global search enforces current session and metadata-only boundaries', async () => {
  await login();
  queue(reply(result('notes', { user_global_0039: page([doc()]) })));
  const found = await service.searchOperatorKnowledge('notes');
  assert.equal(found.sources.user_global_0039.items[0].id, globalId);
  assert.equal(found.sources.user_global_0039.items[0].source, 'user_global_0039');
  assert.equal(found.independent_target_effect_verified, false);
  assert.equal(found.synthesis_performed, false);
  assert.equal(found.atomic_cross_source_snapshot, false);
  assert.equal(requests.length, 1);
  const [{ url, options }] = requests;
  assert.equal(url.pathname, '/operator/search/knowledge');
  assert.equal(url.searchParams.get('query'), 'notes');
  assert.equal(url.searchParams.get('limit_per_source'), '10');
  assert.equal(url.searchParams.has('flow_id'), false);
  assert.equal(options.method, 'GET');
  assert.equal(options.headers.Authorization, 'Bearer signed-in-memory-bearer');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
});

test('exact Flow revisions require both sources, preserve labels, and prohibit fallback', async () => {
  await login();
  const scope = { flowId, revision: 4, authorizationVersion: 2 };
  queue(reply(result('report', {
    user_global_0039: page([doc()]),
    flow_local_0019_0038: page([doc('flow_local_0019_0038')]),
  })));
  const found = await service.searchOperatorKnowledge('report', scope);
  assert.equal(found.sources.flow_local_0019_0038.items[0].flow_id, flowId);
  const uri = requests[0].url;
  assert.equal(uri.searchParams.get('flow_id'), flowId);
  assert.equal(uri.searchParams.get('expected_flow_revision'), '4');
  assert.equal(uri.searchParams.get('expected_authorization_version'), '2');
  queue(reply(result('report', { user_global_0039: page([doc()]) })));
  await assert.rejects(service.searchOperatorKnowledge('report', scope), /partial results unavailable/);
  queue(reply({ detail: 'Flow owner denied' }, 403));
  await assert.rejects(service.searchOperatorKnowledge('report', scope), /HTTP 403.*no partial results/);
  queue(reply(result('report', {
    user_global_0039: page([doc()]),
    flow_local_0019_0038: page([{ ...doc('flow_local_0019_0038'), flow_id: 'flow-other' }]),
  })));
  await assert.rejects(service.searchOperatorKnowledge('report', scope), /metadata or original provenance mismatch/);
});

test('forged proof, content injection, missing source, and oversized response fail closed', async () => {
  await login();
  for (const mutated of [
    { ...doc(), verified_target_evidence: true },
    { ...doc(), approved_for_agent_context: true },
    { ...doc(), content: 'prompt injection' },
    { ...doc(), sha256: 'not-a-sha' },
    { ...doc(), source: 'flow_local_0019_0038' },
    { ...doc(), id: 'knowledge-other' },
  ]) {
    queue(reply(result('safe', { user_global_0039: page([mutated]) })));
    await assert.rejects(service.searchOperatorKnowledge('safe'), /provenance mismatch/);
  }
  queue(reply({ ...result('safe', { user_global_0039: page([doc()]) }), independent_target_effect_verified: true }));
  await assert.rejects(service.searchOperatorKnowledge('safe'), /target effect or release authority/);
  queue(new Response('x'.repeat(96 * 1024 + 1), { status: 200 }));
  await assert.rejects(service.searchOperatorKnowledge('safe'), /response exceeds limits/);
});

test('invalid input and identity switching never return stale previous-user data', async () => {
  await login();
  await assert.rejects(service.searchOperatorKnowledge(''), /printable bounded/);
  await assert.rejects(service.searchOperatorKnowledge('x', { flowId, revision: -1, authorizationVersion: 1 }), /Complete current signed Flow/);
  assert.equal(requests.length, 0);
  queue(async () => {
    auth.signOut();
    return reply(result('switch', { user_global_0039: page([doc()]) }));
  });
  await assert.rejects(service.searchOperatorKnowledge('switch'), /identity changed/);
  await assert.rejects(service.searchOperatorKnowledge('switch'), /signed human operator session/);
});
