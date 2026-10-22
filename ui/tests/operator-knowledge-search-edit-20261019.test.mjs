import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const previousFetch = globalThis.fetch;
const flowId = 'flow-knowledge-test';
const documentId = 'knowledge-test-document';
const digest = 'a'.repeat(64);
const scope = { flowId, revision: 5, authorizationVersion: 3 };
const identity = { sub: 'knowledge-owner', role: 'senior_operator', exp: Math.floor(Date.now() / 1000) + 600 };
let vite, api, knowledge;

const document = {
  id: documentId, flow_id: flowId, authorization_version: 3,
  title: 'Original text', doc_type: 'guide', revision: 4, sha256: digest,
  content_classification: 'untrusted_operator_text', approved_for_agent_context: false,
};

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  knowledge = await vite.ssrLoadModule('/src/services/operatorKnowledge.ts');
});
after(async () => {
  api?.signOut();
  globalThis.fetch = previousFetch;
  await vite?.close();
});

async function invoke(reply, callback) {
  let requested;
  globalThis.fetch = async (url, options = {}) => {
    if (url.endsWith('/auth/me')) return { ok: true, json: async () => identity };
    requested = { url, options };
    return { ok: true, status: 200, json: async () => reply };
  };
  await api.signIn('local-knowledge-credential');
  const result = await callback();
  return { requested, result };
}

test('GET maps server-authenticated untrusted_content into the existing editor without erasing it', async () => {
  const { requested, result } = await invoke(
    { ...document, untrusted_content: 'keep the original investigation notes' },
    () => knowledge.operatorKnowledgeApi.get(scope, documentId),
  );
  assert.equal(result.content, 'keep the original investigation notes');
  assert.equal(result.revision, 4);
  assert.equal(result.approved_for_agent_context, undefined);
  assert.equal(requested.options.method, 'GET');
  assert.equal(requested.options.cache, 'no-store');
  assert.equal(requested.options.credentials, 'omit');
  assert.equal(requested.options.redirect, 'error');
  assert.match(requested.options.headers.Authorization, /^Bearer /);
  assert.match(requested.url, /expected_revision=5/);
  assert.match(requested.url, /expected_authorization_version=3/);
});

test('foreign document or downgraded trust classification is rejected before editor display', async () => {
  for (const bad of [
    { ...document, flow_id: 'flow-foreign', untrusted_content: 'foreign' },
    { ...document, authorization_version: 2, untrusted_content: 'stale' },
    { ...document, approved_for_agent_context: true, untrusted_content: 'injected' },
    { ...document, content: 'unexpected secret', untrusted_content: 'text' },
    { ...document },
  ]) {
    await assert.rejects(invoke(bad, () => knowledge.operatorKnowledgeApi.get(scope, documentId)),
      /untrusted|stale|foreign/);
  }
});

test('server-side search uses bounded signed scoped query and emits display-only metadata', async () => {
  const page = { items: [document], has_more: true, limit: 20, offset: 20 };
  const { requested, result } = await invoke(page, () => knowledge.operatorKnowledgeApi.search(
    scope, 'literal %_ research', { offset: 20, docType: 'guide' },
  ));
  assert.equal(result.items.length, 1);
  assert.equal(result.has_more, true);
  assert.equal(result.items[0].content, undefined);
  const url = new URL(requested.url);
  assert.match(url.pathname, /\/operator-knowledge\/search$/);
  assert.equal(url.searchParams.get('query'), 'literal %_ research');
  assert.equal(url.searchParams.get('offset'), '20');
  assert.equal(url.searchParams.get('doc_type'), 'guide');
  assert.equal(url.searchParams.get('expected_authorization_version'), '3');
});

test('invalid bounds, foreign pages, hidden content, and incorrect offsets fail closed', async () => {
  await assert.rejects(invoke({}, () => knowledge.operatorKnowledgeApi.search(scope, '\nunsafe')),
    /bounded printable/);
  await assert.rejects(invoke({}, () => knowledge.operatorKnowledgeApi.list(scope, { offset: 1001 })),
    /authorized bounds/);
  for (const page of [
    { items: [document], has_more: false, limit: 20, offset: 3 },
    { items: [{ ...document, untrusted_content: 'private' }], has_more: false, limit: 20, offset: 0 },
    { items: [{ ...document, flow_id: 'flow-other' }], has_more: false, limit: 20, offset: 0 },
  ]) {
    await assert.rejects(invoke(page, () => knowledge.operatorKnowledgeApi.list(scope)), /Knowledge/);
  }
});
