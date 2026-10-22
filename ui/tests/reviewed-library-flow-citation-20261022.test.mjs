import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

let vite, auth, service, calls = [];
const originalFetch = globalThis.fetch;
const exp = Math.floor(Date.now() / 1000) + 3600;
const scope = {
  flowId: 'flow-review-test', engagement_id: 'eng-review-test', expected_flow_revision: 2,
  task_id: 'task-review-test', authorization_id: 'roe-review', authorization_version: 3,
  authorization_sha256: 'a'.repeat(64), global_document_id: 'lib-' + 'b'.repeat(32),
  global_revision: 7, global_sha256: 'c'.repeat(64),
};
const receipt = () => ({
  citation_id: 'citation-' + 'd'.repeat(32), source_id: scope.global_document_id,
  source_revision: scope.global_revision, source_sha256: scope.global_sha256,
  engagement_id: scope.engagement_id, flow_id: scope.flowId, task_id: scope.task_id,
  status: 'recorded_untrusted_source_citation', transaction_committed_citation: true,
  flow_local_document_created: false, approved_for_agent_context: false,
  verified_target_evidence: false, safe_for_execution: false, source_original_returned: false,
});
const storedOriginalReceipt = () => ({
  citation_id: 'citation-' + 'e'.repeat(32), source_id: scope.global_document_id,
  source_revision: scope.global_revision, source_sha256: scope.global_sha256,
  original_utf8_bytes: 184, engagement_id: scope.engagement_id,
  flow_id: scope.flowId, task_id: scope.task_id,
  status: 'reviewed_flow_original_stored_inert',
  transaction_committed_source_and_citation: true, flow_local_original_stored: true,
  approved_for_agent_context: false, verified_target_evidence: false,
  safe_for_execution: false, source_original_returned: false,
});
const json = (doc, status = 200) => new Response(JSON.stringify(doc), {
  status, headers: { 'content-type': 'application/json' },
});

before(async () => {
  vite = await createServer({ root: fileURLToPath(new URL('../', import.meta.url)),
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/reviewedLibraryFlowImport.ts');
});
after(async () => { auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close(); });

async function login(role = 'operator') {
  auth.signOut(); calls = [];
  globalThis.fetch = async (url, init = {}) => {
    if (new URL(String(url)).pathname === '/auth/me') return json({ sub: 'owner-review-test', role, exp });
    calls.push({ url: String(url), init }); return json(receipt());
  };
  await auth.signIn('citation-memory-only-test-bearer');
  calls = [];
}

test('actual mounted path receives scoped signed operator and NO original text', async () => {
  await login();
  const result = await service.recordReviewedLibraryCitation(scope);
  assert.equal(result.transaction_committed_citation, true);
  assert.equal(result.approved_for_agent_context, false);
  assert.equal(calls.length, 1);
  const [{ url, init }] = calls;
  assert.equal(new URL(url).pathname, `/flows/${scope.flowId}/reviewed-library-import/record-citation`);
  assert.equal(init.method, 'POST'); assert.equal(init.credentials, 'omit');
  assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
  assert.equal(init.headers.Authorization, 'Bearer citation-memory-only-test-bearer');
  assert.equal(JSON.parse(init.body).flow_owner, 'owner-review-test');
  assert.doesNotMatch(init.body, /content|original_text|private_key|approval_token|execute/);
});

test('forged approval, foreign source, extra content and false commit rejected', async () => {
  await login();
  for (const transform of [
    x => { x.approved_for_agent_context = true; },
    x => { x.flow_local_document_created = true; },
    x => { x.safe_for_execution = true; },
    x => { x.transaction_committed_citation = false; },
    x => { x.source_id = 'lib-' + 'f'.repeat(32); },
    x => { x.content = 'untrusted tool instructions'; },
    x => { x.citation_id = '../escape'; },
  ]) {
    const payload = receipt(); transform(payload);
    globalThis.fetch = async () => json(payload);
    await assert.rejects(() => service.recordReviewedLibraryCitation(scope), /UNKNOWN/);
  }
});

test('missing real host signers, error and ambiguous delivery are never retried', async () => {
  await login();
  let count = 0;
  globalThis.fetch = async () => { count++; return json({ detail: 'not enrolled' }, 503); };
  await assert.rejects(() => service.recordReviewedLibraryCitation(scope), /not enrolled/);
  assert.equal(count, 1);
  globalThis.fetch = async () => { count++; throw new Error('lost response'); };
  await assert.rejects(() => service.recordReviewedLibraryCitation(scope), /lost response/);
  assert.equal(count, 2);
});

test('unsigned viewer and invalid scope cannot write', async () => {
  await login('viewer');
  await assert.rejects(() => service.recordReviewedLibraryCitation(scope), /operator/);
  assert.equal(calls.length, 0);
  await login();
  await assert.rejects(() => service.recordReviewedLibraryCitation({ ...scope, global_sha256: 'bad' }), /identities/);
  assert.equal(calls.length, 0);
});

test('fresh signed readback after ambiguous write issues one read-only verification POST', async () => {
  await login();
  const data = await service.readbackReviewedLibraryCitation(scope);
  assert.equal(data.citation_id, 'citation-' + 'd'.repeat(32));
  assert.equal(data.approved_for_agent_context, false);
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).pathname,
    `/flows/${scope.flowId}/reviewed-library-import/record-citation/readback`);
  assert.doesNotMatch(calls[0].init.body, /content|original_text|private_key/);
});

test('reviewed original write is explicit scoped atomic metadata, no source text in request or receipt', async () => {
  await login();
  globalThis.fetch = async (url, init = {}) => { calls.push({ url: String(url), init }); return json(storedOriginalReceipt()); };
  const result = await service.storeReviewedFlowOriginal(scope);
  assert.equal(result.status, 'reviewed_flow_original_stored_inert');
  assert.equal(result.flow_local_original_stored, true);
  assert.equal(result.approved_for_agent_context, false);
  assert.equal(calls.length, 1);
  const [{ url, init }] = calls;
  assert.equal(new URL(url).pathname, `/flows/${scope.flowId}/reviewed-library-import/store-reviewed-original`);
  assert.equal(init.credentials, 'omit'); assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
  assert.equal(JSON.parse(init.body).flow_owner, 'owner-review-test');
  assert.doesNotMatch(init.body, /content|original_text|private_key|approval_token|execute/);
  assert.ok(!('content' in result));
});

test('original manual signed readback is one separate nonmutating endpoint', async () => {
  await login();
  globalThis.fetch = async (url, init = {}) => { calls.push({ url: String(url), init }); return json(storedOriginalReceipt()); };
  const result = await service.readbackStoredReviewedFlowOriginal(scope);
  assert.equal(result.transaction_committed_source_and_citation, true);
  assert.equal(result.source_original_returned, false);
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).pathname,
    `/flows/${scope.flowId}/reviewed-library-import/store-reviewed-original/readback`);
});

test('forged original trust, foreign hash, unbounded receipt and absent independent roots deny', async () => {
  await login();
  for (const transform of [
    row => { row.approved_for_agent_context = true; },
    row => { row.safe_for_execution = true; },
    row => { row.verified_target_evidence = true; },
    row => { row.flow_local_original_stored = false; },
    row => { row.original_utf8_bytes = 9000; },
    row => { row.source_sha256 = '0'.repeat(64); },
    row => { row.content = 'untrusted instruction'; },
  ]) {
    const source = storedOriginalReceipt(); transform(source);
    globalThis.fetch = async () => json(source);
    await assert.rejects(() => service.storeReviewedFlowOriginal(scope), /UNKNOWN/);
  }
  let requests = 0;
  globalThis.fetch = async () => { requests++; return json({ detail: 'roots absent' }, 503); };
  await assert.rejects(() => service.storeReviewedFlowOriginal(scope), /not enrolled/);
  assert.equal(requests, 1);
  globalThis.fetch = async () => { requests++; throw new Error('unknown socket ACK'); };
  await assert.rejects(() => service.storeReviewedFlowOriginal(scope), /unknown socket ACK/);
  assert.equal(requests, 2);
});
