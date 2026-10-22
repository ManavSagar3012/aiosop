/** Original Browser host-custody operator UI, offline, without app DB/targets. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const previousFetch = globalThis.fetch;
const previousWindow = globalThis.window;
const previousCryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const roots = Object.freeze({ hostCustody: publicRaw.toString('base64') });
const other = generateKeyPairSync('ed25519');
const domain = Buffer.from('ai-osop/browser-host-readonly-original-custody/v1\0', 'utf8');
const engagement = 'eng-original-owned';
const request = 'req-' + 'a'.repeat(48);
const originalSha = 'a'.repeat(64);
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value)
  ? '[' + value.map(canonical).join(',') + ']'
  : value !== null && typeof value === 'object'
    ? '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
    : JSON.stringify(value);

function originalManifest() {
  return {
    screenshot: { path: 'captures/' + '1'.repeat(32) + '.png', sha256: hash('raw original PNG'), size_bytes: 17 },
    dom: { path: 'captures/' + '2'.repeat(32) + '.html', sha256: hash('raw original HTML'), size_bytes: 18 },
    har: { path: 'captures/' + '3'.repeat(32) + '.har', sha256: hash('raw original HAR'), size_bytes: 17 },
  };
}
function attested({
  mutateClaims = () => {}, mutateResponse = () => {},
  signingKey = privateKey, kid = 'hostCustody',
} = {}) {
  const now = Math.floor(Date.now() / 1000);
  const manifest = originalManifest();
  const claims = {
    version: 1,
    request_id: request,
    engagement_id: engagement,
    flow_id: 'flow-current',
    task_id: 'task-original',
    subtask_id: 'step-original',
    action_id: 'action-original',
    owner_id: 'owner-current',
    preflight_id: 'nbp-' + 'b'.repeat(32),
    authorization_sha256: originalSha,
    original_intent_sha256: 'c'.repeat(64),
    evidence_attestation_sha256: 'd'.repeat(64),
    first_current_sha256: 'e'.repeat(64),
    last_current_sha256: 'f'.repeat(64),
    artifacts_sha256: hash(canonical(manifest)),
    checked_at: now,
    expires_at: now + 5,
    original_bytes_read: true,
    target_effect_verified: false,
    automatic_retry_authorized: false,
    purpose: 'host_readonly_original_custody',
  };
  mutateClaims(claims);
  const signature = sign(null, Buffer.concat([domain, Buffer.from(canonical(claims))]), signingKey);
  const reply = {
    status: 'CURRENT_ORIGINAL_CUSTODY_VERIFIED',
    current_original_artifact_bytes_verified: true,
    independent_target_effect_verified: false,
    automatic_retry_authorized: false,
    production_release_certified: false,
    custody_proof: { claims, kid, signature: signature.toString('base64url') },
    artifacts: manifest,
  };
  mutateResponse(reply);
  return reply;
}
const jsonReply = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', ...headers },
});
const unknown = reason => ({
  status: 'UNVERIFIED', reason,
  current_original_artifact_bytes_verified: false,
  independent_target_effect_verified: false,
  automatic_retry_authorized: false,
  production_release_certified: false,
});

let vite, auth, svc, panel;
let requests = [];
let queue = [];
before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  svc = await vite.ssrLoadModule('/src/services/browserCurrentCustodyReadback.ts');
  panel = await vite.ssrLoadModule('/src/components/BrowserCurrentCustodyPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = previousFetch;
  if (previousWindow === undefined) delete globalThis.window;
  else globalThis.window = previousWindow;
  if (previousCryptoDescriptor) Object.defineProperty(globalThis, 'crypto', previousCryptoDescriptor);
  else delete globalThis.crypto;
  await vite?.close();
});

async function login(role = 'senior_operator') {
  auth.signOut();
  requests = [];
  queue = [];
  globalThis.fetch = async (url, options = {}) => {
    const record = { url: new URL(String(url)), options };
    if (record.url.pathname === '/auth/me')
      return jsonReply({ sub: 'senior-browser-custody', role, exp: Math.floor(Date.now() / 1000) + 300 });
    requests.push(record);
    if (!queue.length) throw new Error('Unqueued custody endpoint');
    const next = queue.shift();
    if (next instanceof Error) throw next;
    return typeof next === 'function' ? await next(record) : next;
  };
  await auth.signIn('memory-only-original-browser-senior-token');
  requests = [];
}
const run = (pins = roots, signal) => svc.readBrowserCurrentCustodyReadback(engagement, request, pins, signal);

test('senior host readback sends exactly the two original identifiers over protected POST', async () => {
  await login();
  queue.push(jsonReply(attested()));
  const verified = await run();
  assert.equal(verified.status, 'CURRENT_ORIGINAL_CUSTODY_VERIFIED');
  assert.equal(verified.current_original_artifact_bytes_verified, true);
  assert.equal(verified.independent_target_effect_verified, false);
  assert.equal(verified.automatic_retry_authorized, false);
  assert.equal(verified.production_release_certified, false);
  assert.equal(verified.custody_signer_kid, 'hostCustody');
  assert.equal(verified.engagement_id, engagement);
  assert.equal(verified.request_id, request);
  assert.equal(verified.artifacts.dom.sha256, originalManifest().dom.sha256);
  assert.equal(verified.artifacts.screenshot.size_bytes, 17);
  assert.equal(requests.length, 1);
  const [{ url, options }] = requests;
  assert.equal(url.pathname, '/system/browser/custody/readback');
  assert.equal(url.search, '');
  assert.equal(options.method, 'POST');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.headers['Content-Type'], 'application/json');
  assert.equal(options.headers.Authorization, 'Bearer memory-only-original-browser-senior-token');
  assert.deepEqual(JSON.parse(options.body), { engagement_id: engagement, request_id: request });
  assert.deepEqual(Object.keys(JSON.parse(options.body)).sort(), ['engagement_id', 'request_id']);
  assert.doesNotMatch(JSON.stringify(verified), /captures\/|memory-only|raw original|original_uri|private/);
});

test('unverified 503 is surfaced by a fixed machine reason; no promotion, no retry', async () => {
  await login();
  queue.push(jsonReply({ detail: unknown('INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED') }, 503));
  await assert.rejects(run(), error =>
    error instanceof svc.BrowserCustodyUnverifiedError
      && error.reason === 'INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED');
  assert.equal(requests.length, 1);
  queue.push(jsonReply({ detail: unknown('CURRENT_ORIGINAL_CUSTODY_UNVERIFIED') }, 503));
  await assert.rejects(run(), error => error.reason === 'CURRENT_ORIGINAL_CUSTODY_UNVERIFIED');
  assert.equal(requests.length, 2);
  queue.push(jsonReply({ detail: { ...unknown('CURRENT_ORIGINAL_CUSTODY_UNVERIFIED'), raw_html: '<h1>exfil</h1>' } }, 503));
  await assert.rejects(run(), error => error.reason === 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED');
  queue.push(jsonReply({ detail: unknown('secret-internal-error') }, 503));
  await assert.rejects(run(), error => error.reason === 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED');
  assert.equal(requests.length, 4);
});

test('unsigned, provider-signed, altered, stale and wrong identity custody never verifies', async () => {
  await login();
  const forged = [
    attested({ signingKey: other.privateKey }),
    attested({ mutateResponse: x => { x.custody_proof.signature = 'a'.repeat(86); } }),
    attested({ mutateResponse: x => { x.custody_proof.kid = 'providerKey'; } }),
    attested({ mutateClaims: x => { x.engagement_id = 'eng-foreign'; } }),
    attested({ mutateClaims: x => { x.request_id = 'req-' + '9'.repeat(48); } }),
    attested({ mutateClaims: x => { x.checked_at -= 10; x.expires_at -= 10; } }),
    attested({ mutateClaims: x => { x.original_bytes_read = false; } }),
    attested({ mutateClaims: x => { x.target_effect_verified = true; } }),
    attested({ mutateClaims: x => { x.automatic_retry_authorized = true; } }),
    attested({ mutateClaims: x => { x.purpose = 'approve_release'; } }),
    attested({ mutateResponse: x => { x.artifacts.dom.sha256 = '0'.repeat(64); } }),
    attested({ mutateResponse: x => { x.artifacts.dom.path = '../../other.html'; } }),
    attested({ mutateResponse: x => { x.artifacts.har.size_bytes = 5 * 1024 * 1024; } }),
    attested({ mutateResponse: x => { x.custody_proof.claims.first_current_sha256 = 'X'.repeat(64); } }),
    attested({ mutateResponse: x => { x.production_release_certified = true; } }),
    attested({ mutateResponse: x => { x.independent_target_effect_verified = true; } }),
    attested({ mutateResponse: x => { x.automatic_retry_authorized = true; } }),
    attested({ mutateResponse: x => { x.extra_private_path = 'C:\\secret'; } }),
    attested({ mutateResponse: x => { x.custody_proof.claims.extra_auth = 'bypass'; } }),
  ];
  for (const forgedProof of forged) {
    queue.push(jsonReply(forgedProof));
    await assert.rejects(run(), error => error.reason === 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED');
  }
  assert.equal(requests.length, forged.length);
  assert.ok(requests.every(r => r.options.method === 'POST'));
});

test('requires explicit pinned independent Ed25519 root and WebCrypto availability', async () => {
  await login();
  await assert.rejects(run({}), /UNVERIFIED/);
  assert.equal(requests.length, 0);
  queue.push(jsonReply(attested()));
  await assert.rejects(run({ unrelatedKey: roots.hostCustody }), /UNVERIFIED/);
  queue.push(jsonReply(attested()));
  await assert.rejects(run({ hostCustody: 'invalid-key' }), /UNVERIFIED/);
  assert.equal(requests.length, 2);
  queue.push(jsonReply(attested()));
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
  try { await assert.rejects(run(), /UNVERIFIED/); }
  finally {
    if (previousCryptoDescriptor) Object.defineProperty(globalThis, 'crypto', previousCryptoDescriptor);
    else delete globalThis.crypto;
  }
  assert.equal(requests.length, 3);
});

test('malformed, duplicate-key, oversized, HTML or status-only responses fail closed', async () => {
  await login();
  const valid = JSON.stringify(attested());
  const bad = [
    new Response(valid.replace('"production_release_certified":false',
      '"production_release_certified":true,"production_release_certified":false'), { status: 200, headers: { 'content-type': 'application/json' } }),
    new Response(valid.replace('"request_id":"' + request + '"',
      '"request_id":"' + request + '","request_id":"' + request + '"'), { status: 200, headers: { 'content-type': 'application/json' } }),
    new Response('x'.repeat(17000), { status: 200, headers: { 'content-type': 'application/json' } }),
    new Response('invalid {', { status: 200, headers: { 'content-type': 'application/json' } }),
    new Response(valid, { status: 200, headers: { 'content-type': 'text/html' } }),
    new Response(valid, { status: 200, headers: { 'content-type': 'application/json', 'content-length': '80000' } }),
    jsonReply(attested(), 202),
    new Response(null, { status: 204 }),
    new Error('lost POST acknowledgement'),
  ];
  for (const candidate of bad) {
    queue.push(candidate);
    await assert.rejects(run(), /UNVERIFIED/);
  }
  assert.equal(requests.length, bad.length);
});

test('senior identity, secure origin, strict IDs and abort required before POST', async () => {
  auth.signOut();
  await assert.rejects(run(), /UNVERIFIED/);
  await login('operator');
  await assert.rejects(run(), /UNVERIFIED/);
  await login();
  await assert.rejects(svc.readBrowserCurrentCustodyReadback('eng-x', 'req-user-string', roots), /UNVERIFIED/);
  await assert.rejects(svc.readBrowserCurrentCustodyReadback('eng-x', 'req-' + 'A'.repeat(48), roots), /UNVERIFIED/);
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(run(roots, aborted.signal), /UNVERIFIED/);
  globalThis.window = { location: { protocol: 'http:', hostname: 'untrusted.company' } };
  try { await assert.rejects(run(), /UNVERIFIED/); }
  finally {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
  assert.equal(requests.length, 0);
});

test('lost auth session while reading response or signature denies and no implicit retry', async () => {
  await login();
  queue.push(() => { auth.signOut(); return jsonReply(attested()); });
  await assert.rejects(run(), /UNVERIFIED/);
  assert.equal(requests.length, 1);
  await login();
  const streamed = new Response(JSON.stringify(attested()), { status: 200, headers: { 'content-type': 'application/json' } });
  queue.push(() => {
    const existing = streamed.body.getReader();
    return new Response(new ReadableStream({
      async pull(controller) {
        const part = await existing.read();
        if (part.done) { controller.close(); return; }
        auth.signOut();
        controller.enqueue(part.value);
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  await assert.rejects(run(), /UNVERIFIED/);
  assert.equal(requests.length, 1);
});

test('standalone panel only presents bounded IDs and inert hashes; no image, DOM, URL or action', async () => {
  await login();
  const markup = renderToStaticMarkup(createElement(panel.BrowserCurrentCustodyPanel, {
    initialEngagementId: engagement, initialRequestId: request, trustedCustodyPublicKeys: roots,
  }));
  assert.match(markup, /Browser original-byte custody/);
  assert.match(markup, /Original Browser engagement ID/);
  assert.match(markup, /Original Browser request ID/);
  assert.match(markup, /READ ORIGINAL CUSTODY/);
  assert.match(markup, /NOT PRODUCTION CERTIFIED \/ NOT READY/);
  assert.match(markup, /UNVERIFIED/);
  assert.doesNotMatch(markup, /<img|<iframe|dangerouslySetInnerHTML|memory-only-original-browser-senior-token|http:\/\/127\.0\.0\.1:8200/);
  assert.doesNotMatch(markup, /original_uri|original_path|private_key|read screenshot|launch|execute now/i);
  const withoutRoots = renderToStaticMarkup(createElement(panel.BrowserCurrentCustodyPanel));
  assert.match(withoutRoots, /INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED/);
  assert.match(withoutRoots, /disabled=""/);
  const source = readFileSync(new URL('../src/services/browserCurrentCustodyReadback.ts', import.meta.url), 'utf8');
  const component = readFileSync(new URL('../src/components/BrowserCurrentCustodyPanel.tsx', import.meta.url), 'utf8');
  assert.match(source, /\/system\/browser\/custody\/readback/);
  assert.match(source, /method: 'POST'/);
  assert.doesNotMatch(source + component, /localStorage\.|sessionStorage\.|document\.cookie|dangerouslySetInnerHTML|<img|<iframe/);
  assert.equal(requests.length, 0);
});
