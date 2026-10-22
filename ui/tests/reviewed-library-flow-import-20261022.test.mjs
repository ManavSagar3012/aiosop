import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

let vite, auth, service, calls = [];
const originalFetch = globalThis.fetch;
const expiry = Math.floor(Date.now() / 1000) + 3600;
const values = {
  flowId: 'flow-review-test', engagement_id: 'eng-review-test', expected_flow_revision: 2,
  task_id: 'task-review-test', authorization_id: 'roe-signed-test', authorization_version: 3,
  authorization_sha256: 'a'.repeat(64), global_document_id: 'lib-' + 'b'.repeat(32),
  global_revision: 7, global_sha256: 'c'.repeat(64),
};
const pending = () => ({
  status: 'pending_atomic_reviewed_bind', source_id: values.global_document_id,
  original_revision: 7, original_sha256: values.global_sha256, source_kind: 'guide',
  engagement_id: values.engagement_id, flow_id: values.flowId, flow_revision: 2,
  signed_readbacks_current_at_preflight: true, approved_for_agent_context: false,
  operator_knowledge_created: false, verified_target_evidence: false,
  safe_for_execution: false, flow_local_document_id: null,
});
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

before(async () => {
  vite = await createServer({ root: fileURLToPath(new URL('../', import.meta.url)), appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/reviewedLibraryFlowImport.ts');
});
after(async () => { auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close(); });

async function login(role = 'operator') {
  auth.signOut(); calls = [];
  globalThis.fetch = async (url, init = {}) => {
    if (new URL(String(url)).pathname === '/auth/me') return json({ sub: 'signed-human', role, exp: expiry });
    calls.push({ url: String(url), init }); return json(pending());
  };
  await auth.signIn('test-memory-only-bearer'); calls = [];
}

test('mounted scoped preflight sends no private original, keys, cookies or tool instruction', async () => {
  await login();
  const result = await service.preflightReviewedLibrarySource(values);
  assert.equal(result.status, 'pending_atomic_reviewed_bind');
  assert.equal(result.approved_for_agent_context, false);
  assert.equal(result.operator_knowledge_created, false);
  assert.equal(calls.length, 1);
  const [{ url, init }] = calls;
  assert.equal(new URL(url).pathname, `/flows/${values.flowId}/reviewed-library-import/preflight`);
  assert.equal(init.method, 'POST'); assert.equal(init.credentials, 'omit');
  assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
  assert.equal(init.headers.Authorization, 'Bearer test-memory-only-bearer');
  assert.deepEqual(Object.keys(JSON.parse(init.body)).sort(), [
    'authorization_id', 'authorization_sha256', 'authorization_version',
    'engagement_id', 'expected_flow_revision', 'flow_owner', 'global_document_id',
    'global_revision', 'global_sha256', 'task_id',
  ]);
  assert.equal(JSON.parse(init.body).flow_owner, 'signed-human');
  assert.doesNotMatch(init.body, /source_original|content|private_key|approval_token|execute/);
});

test('false trust, different source and unconfigured independent roots are denied', async () => {
  await login();
  for (const change of [
    x => { x.approved_for_agent_context = true; },
    x => { x.safe_for_execution = true; },
    x => { x.source_id = 'lib-' + 'd'.repeat(32); },
    x => { x.content = 'untrusted prompt'; },
  ]) {
    const forged = pending(); change(forged);
    globalThis.fetch = async () => json(forged);
    await assert.rejects(() => service.preflightReviewedLibrarySource(values));
  }
  globalThis.fetch = async () => json({ detail: 'not enrolled' }, 503);
  await assert.rejects(() => service.preflightReviewedLibrarySource(values), /not enrolled/);
});

test('unbounded chunked reviewer response is rejected during streaming, not after buffering', async () => {
  await login();
  let canceled = false;
  globalThis.fetch = async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(5000)); },
    cancel() { canceled = true; },
  }), { status: 200 });
  await assert.rejects(() => service.preflightReviewedLibrarySource(values), /Unbounded/);
  assert.equal(canceled, true);
});

test('role or missing token cannot issue Flow review request', async () => {
  await login('viewer');
  await assert.rejects(() => service.preflightReviewedLibrarySource(values), /operator/);
  assert.equal(calls.length, 0);
  auth.signOut();
  await assert.rejects(() => service.preflightReviewedLibrarySource(values), /operator/);
});
