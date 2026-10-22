/** Offline real service/markup tests: no Browser, target, DB or provider. */
import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const priorFetch = globalThis.fetch;
const engagement = 'eng-readback';
const requestId = 'req-' + 'a'.repeat(48);
const SHA = 'f'.repeat(64);
const artifacts = {
  http_raw: { sha256: 'a'.repeat(64), size_bytes: 189 },
  screenshot: { sha256: 'b'.repeat(64), size_bytes: 2048 },
  dom: { sha256: 'c'.repeat(64), size_bytes: 512 },
  har: { sha256: 'd'.repeat(64), size_bytes: 1024 },
};
const realShape = () => ({
  status: 'CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK',
  engagement_id: engagement, request_id: requestId,
  host_enrollment_sha256: SHA, custody_claims_sha256: SHA, artifacts,
  current_original_artifact_bytes_verified: true,
  raw_http_original_bytes_verified: true,
  independent_target_effect_verified: false,
  automatic_retry_authorized: false, production_release_certified: false,
});
const reply = (value, status = 200, contentType = 'application/json') => new Response(
  JSON.stringify(value), { status, headers: { 'Content-Type': contentType } },
);

let vite, auth, module, panel, requests, queued;
before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  module = await vite.ssrLoadModule('/src/services/browserHostOriginalReadback.ts');
  panel = await vite.ssrLoadModule('/src/components/BrowserHostOriginalPanel.tsx');
});
after(async () => { auth?.signOut(); globalThis.fetch = priorFetch; await vite?.close(); });

async function login(role = 'senior_operator') {
  auth.signOut();
  requests = [];
  queued = [];
  globalThis.fetch = async (url, options = {}) => {
    if (new URL(String(url)).pathname === '/auth/me') {
      return reply({
        sub: 'senior-fixture', role, exp: Math.floor(Date.now() / 1000) + 600,
      });
    }
    requests.push({ url: new URL(String(url)), options });
    const next = queued.shift();
    if (!next) throw new Error('Unqueued test-only network');
    return typeof next === 'function' ? next() : next;
  };
  await auth.signIn('memory-only-browser-host-test-bearer');
}

test('host original senior POST emits only two identifier fields and refuses any execution', async () => {
  await login();
  queued.push(reply(realShape()));
  const actual = await module.readBrowserHostOriginalDigests(engagement, requestId);
  assert.equal(actual.status, 'CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK');
  assert.equal(Object.keys(actual.artifacts).length, 4);
  assert.equal(requests.length, 1);
  const { url, options } = requests[0];
  assert.equal(url.pathname, '/system/browser/original-host/readback');
  assert.equal(url.search, '');
  assert.equal(options.method, 'POST');
  assert.equal(options.headers.Authorization, 'Bearer memory-only-browser-host-test-bearer');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.redirect, 'error');
  assert.deepEqual(JSON.parse(options.body), { engagement_id: engagement, request_id: requestId });
  assert.ok(!options.body.includes('signer') && !options.body.includes('path'));
});

test('503 without host enrollment, malformed or forged effect readbacks fail closed', async () => {
  await login();
  for (const result of [
    reply({ detail: { status: 'UNVERIFIED' } }, 503),
    reply({ ...realShape(), independent_target_effect_verified: true }),
    reply({ ...realShape(), raw_http_original_bytes_verified: false }),
    reply({ ...realShape(), production_release_certified: true }),
    reply({ ...realShape(), automatic_retry_authorized: true }),
    reply({ ...realShape(), request_id: 'req-' + 'b'.repeat(48) }),
    reply({ ...realShape(), original_http_content: 'private original body' }),
    reply({ ...realShape(), artifacts: { ...artifacts, http_raw: { sha256: 'not-a-digest', size_bytes: 189 } } }),
    reply({ ...realShape(), artifacts: { ...artifacts, har: { sha256: 'd'.repeat(64), size_bytes: -1 } } }),
    reply('<html>backend was replaced</html>', 200, 'text/html'),
  ]) {
    queued.push(result);
    await assert.rejects(module.readBrowserHostOriginalDigests(engagement, requestId), /UNVERIFIED/);
  }
  assert.equal(requests.length, 10);
  assert.ok(requests.every(item => item.url.pathname === '/system/browser/original-host/readback'));
});

test('wrong role or invalid original identifiers cannot send to the host', async () => {
  await login('operator');
  await assert.rejects(module.readBrowserHostOriginalDigests(engagement, requestId), /UNVERIFIED/);
  assert.equal(requests.length, 0);
  await login();
  for (const [eng, id] of [
    ['eng-bad/../../target', requestId],
    [engagement, 'req-user-request'],
    [engagement, requestId + '?token=secret'],
  ]) await assert.rejects(module.readBrowserHostOriginalDigests(eng, id), /UNVERIFIED/);
  assert.equal(requests.length, 0);
});

test('principal signout during response discards even valid server receipt with no retry', async () => {
  await login();
  queued.push(() => { auth.signOut(); return reply(realShape()); });
  await assert.rejects(module.readBrowserHostOriginalDigests(engagement, requestId), /UNVERIFIED/);
  assert.equal(requests.length, 1);
});

test('senior readback panel has no attack action, raw evidence, signer enrollment or secret', async () => {
  await login();
  const html = renderToStaticMarkup(createElement(panel.BrowserHostOriginalPanel));
  assert.match(html, /NOT PRODUCTION CERTIFIED/);
  assert.match(html, /READ FOUR ORIGINAL DIGESTS/);
  assert.match(html, /cannot navigate, scan, authorize/);
  assert.match(html, /UNVERIFIED/);
  assert.doesNotMatch(html, /memory-only-browser-host-test-bearer/);
  assert.doesNotMatch(html, /private original body/);
  assert.ok(!html.includes('mcp/execute'));
});
