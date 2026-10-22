/** Offline Vite-loaded production client + React page qualification, no providers. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const oldFetch = globalThis.fetch;
const now = Math.floor(Date.now() / 1000);
const id = 'lib-' + 'a'.repeat(32);
const original = 'This is inert, owner-written reference 📘.';
const hash = createHash('sha256').update(original, 'utf8').digest('hex');
const meta = {
  id, title: 'My guide', doc_type: 'guide', revision: 1,
  sha256: hash, content_bytes: Buffer.byteLength(original, 'utf8'),
  created_at: '2026-10-21T00:00:00+00:00',
  version_created_at: '2026-10-21T00:00:00+00:00',
  content_classification: 'untrusted_user_text',
  approved_for_agent_context: false, verified_target_evidence: false,
};
const page = items => ({ items, has_more: false, content_classification: 'untrusted_user_text', approved_for_agent_context: false });
const reply = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', ...headers },
});

let vite, auth, library, ui, incoming = [], observed = [];
before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  library = await vite.ssrLoadModule('/src/services/userGlobalLibrary.ts');
  ui = await vite.ssrLoadModule('/src/pages/UserLibrary.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = oldFetch;
  await vite?.close();
});

async function login(name = 'principal-a') {
  auth.signOut();
  incoming = [];
  observed = [];
  globalThis.fetch = async (raw, options = {}) => {
    const uri = String(raw);
    if (new URL(uri).pathname === '/auth/me') return reply({ sub: name, role: 'operator', exp: now + 3600 });
    observed.push({ uri, options });
    if (!incoming.length) throw new Error('Unexpected unqueued global user request');
    const next = incoming.shift();
    if (typeof next === 'function') return next({ uri, options });
    return next;
  };
  await auth.signIn('signed-original-user-bearer');
  observed = [];
}

const queue = (...responses) => incoming.push(...responses);

test('global user library is an accessible distinct route, never Flow-coupled or autonomous trust', async () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const sidebar = readFileSync(new URL('../src/components/layout/Sidebar.tsx', import.meta.url), 'utf8');
  assert.match(appSource, /path="user-library"/);
  assert.match(sidebar, /path: '\/user-library', label: 'My Library'/);
  const html = renderToStaticMarkup(createElement(ui.UserLibrary));
  assert.match(html, /User-owned Library/);
  assert.match(html, /untrusted human-authored text/);
  assert.match(html, /does not approve it for agent context/);
  assert.doesNotMatch(html, /signed-original-user-bearer/);
});

test('signed human owner fetches bounded current original SHA-checked bytes', async () => {
  await login('principal-a');
  queue(reply(page([meta])), reply({ ...meta, content: original }));
  const listed = await library.userGlobalLibraryApi.list(0, 'percent_%');
  assert.equal(listed.items.length, 1);
  assert.equal(listed.items[0].content, undefined);
  const doc = await library.userGlobalLibraryApi.get(id);
  assert.equal(doc.content, original);
  assert.equal(doc.sha256, hash);
  const urls = observed.map(item => new URL(item.uri));
  assert.equal(urls[0].pathname, '/operator/library/documents');
  assert.equal(urls[0].searchParams.get('query'), 'percent_%');
  assert.equal(urls[0].searchParams.get('limit'), '20');
  assert.equal(urls[1].pathname, '/operator/library/documents/' + id);
  assert.ok(observed.every(item => item.options.headers.Authorization === 'Bearer signed-original-user-bearer'));
  assert.ok(observed.every(item => item.options.credentials === 'omit' && item.options.redirect === 'error' && item.options.cache === 'no-store'));
  assert.ok(observed.every(item => !new URL(item.uri).searchParams.has('owner')));
});

test('current library must deny arbitrary elevated truth labels, content leaks and wrong digest', async () => {
  await login();
  for (const item of [
    { ...meta, approved_for_agent_context: true },
    { ...meta, verified_target_evidence: true },
    { ...meta, content: original },
    { ...meta, sha256: 'wrong' },
    { ...meta, id: 'lib-' + 'b'.repeat(32), owner_id: 'foreign-human' },
  ]) {
    queue(reply(page([item])));
    await assert.rejects(library.userGlobalLibraryApi.list(), /Library content|invalid|trust/i);
  }
  queue(reply({ ...meta, sha256: '0'.repeat(64), content: original }));
  await assert.rejects(library.userGlobalLibraryApi.get(id), /no longer match advertised digest/);
  queue(reply({ ...meta, content: 'foreign content' }));
  await assert.rejects(library.userGlobalLibraryApi.get(id), /SHA-256 verification unavailable|Original library bytes/);
});

test('mutation uses one exact expected revision; unconfirmed responses remain denied', async () => {
  await login();
  const revisionTwo = { ...meta, revision: 2, title: 'changed', sha256: createHash('sha256').update('updated').digest('hex'), content_bytes: 7 };
  queue(reply(meta), reply({ ...meta, content: original }));
  const created = await library.userGlobalLibraryApi.create('My guide', 'guide', original);
  assert.equal(created.revision, 1);
  assert.equal(JSON.parse(observed.at(-2).options.body).content, original);
  assert.equal(observed.at(-2).options.method, 'POST');
  assert.equal(observed.at(-1).options.method, 'GET');
  queue(reply(revisionTwo), reply({ ...revisionTwo, content: 'updated' }));
  const updated = await library.userGlobalLibraryApi.update(created, 'changed', 'updated');
  assert.equal(updated.revision, 2);
  assert.deepEqual(JSON.parse(observed.at(-2).options.body), {
    title: 'changed', doc_type: 'guide', content: 'updated', expected_revision: 1,
  });
  assert.equal(observed.at(-2).options.method, 'PUT');
  assert.equal(observed.at(-1).options.method, 'GET');
  queue(reply({ id, revision: 2, status: 'tombstoned', safe_for_execution: false }));
  await library.userGlobalLibraryApi.remove(updated);
  assert.deepEqual(JSON.parse(observed.at(-1).options.body), { expected_revision: 2 });
  assert.equal(observed.at(-1).options.method, 'DELETE');
  queue(reply({ id, revision: 2, status: 'deleted', safe_for_execution: true }));
  await assert.rejects(library.userGlobalLibraryApi.remove(updated), /ambiguous/);
  queue(reply({ ...revisionTwo, revision: 4 }));
  await assert.rejects(library.userGlobalLibraryApi.update(created, 'changed', 'updated'), /CAS mismatch/);
});

test('postcommit write original custody refuses forged, shifted, missing and wrong-owner readback without retry', async () => {
  await login();
  queue(reply(meta), reply({ ...meta, content: 'tampered same-length original bytes' }));
  await assert.rejects(
    library.userGlobalLibraryApi.create(meta.title, 'guide', original),
    /UNKNOWN.*readback unavailable/,
  );
  assert.equal(observed.filter(value => value.options.method === 'POST').length, 1);
  assert.equal(observed.filter(value => value.options.method === 'GET').length, 1);

  observed = [];
  queue(reply(meta), reply({ ...meta, revision: 2, content: original }));
  await assert.rejects(
    library.userGlobalLibraryApi.create(meta.title, 'guide', original),
    /UNKNOWN.*committed bytes or revision/,
  );
  assert.equal(observed.filter(value => value.options.method === 'POST').length, 1);

  observed = [];
  queue(reply(meta), reply({ ...meta, title: 'foreign title', content: original }));
  await assert.rejects(
    library.userGlobalLibraryApi.create(meta.title, 'guide', original),
    /UNKNOWN.*committed bytes or revision/,
  );
  assert.equal(observed.filter(value => value.options.method === 'POST').length, 1);

  observed = [];
  queue(reply(meta), () => { throw new Error('Lost independent original response'); });
  await assert.rejects(
    library.userGlobalLibraryApi.create(meta.title, 'guide', original),
    /UNKNOWN.*readback unavailable/,
  );
  assert.equal(observed.filter(value => value.options.method === 'POST').length, 1);

  observed = [];
  queue(reply(meta), () => {
    auth.signOut();
    return reply({ ...meta, content: original });
  });
  await assert.rejects(
    library.userGlobalLibraryApi.create(meta.title, 'guide', original),
    /UNKNOWN.*readback unavailable/,
  );
  assert.equal(observed.filter(value => value.options.method === 'POST').length, 1);
});

test('untrusted page is size bounded and signed owner must still be current after response', async () => {
  await login();
  queue(reply(page([]), 200, { 'content-length': '99999999' }));
  await assert.rejects(library.userGlobalLibraryApi.list(), /Unbounded library response/);
  await assert.rejects(library.userGlobalLibraryApi.list(1001), /outside bounds/);
  let settle;
  queue(() => new Promise(resolve => { settle = resolve; }));
  const pending = library.userGlobalLibraryApi.list();
  for (let attempts = 0; !settle && attempts < 100; attempts++) await Promise.resolve();
  assert.ok(settle);
  auth.signOut();
  settle(reply(page([meta])));
  await assert.rejects(pending, /identity changed/);
});

test('inert global text rejects ambiguous Unicode byte overrun and missing operator', async () => {
  await login();
  await assert.rejects(library.userGlobalLibraryApi.create('Notes', 'guide', '📘'.repeat(3000)), /Bounded plain-text/);
  await assert.rejects(library.userGlobalLibraryApi.create('Notes', 'guide', '\0secret'), /Bounded plain-text/);
  auth.signOut();
  await assert.rejects(library.userGlobalLibraryApi.list(), /current signed human operator/);
});
