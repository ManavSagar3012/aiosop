import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let supervision;
let panel;

before(async () => {
  vite = await createServer({
    root,
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true },
  });
  supervision = await vite.ssrLoadModule('/src/services/supervision.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/SupervisionPanel.tsx');
});
after(async () => {
  globalThis.fetch = originalFetch;
  await vite?.close();
});

function fakeResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

test('authorization status only reads authenticated engagement-scoped resource', async () => {
  const captured = [];
  globalThis.fetch = async (url, init) => {
    captured.push({ url, init });
    return fakeResponse({
      status: 'revoked',
      version: 7,
      key_id: 'public-kid-1',
      expires_at: '2026-10-14T22:00:00Z',
      policy_sha256: 'a'.repeat(64),
      remote_execution_outcome: 'unknown',
    });
  };
  const data = await supervision.supervisionApi.authorizationStatus('eng-one/unsafe?');
  assert.equal(data.status, 'revoked');
  assert.equal(data.remote_execution_outcome, 'unknown');
  assert.equal(captured.length, 1);
  assert.match(captured[0].url, /\/engagements\/eng-one%2Funsafe%3F\/authorization\/status$/);
  assert.equal(captured[0].init.method, 'GET');
  assert.equal(captured[0].init.body, undefined);
  assert.doesNotMatch(captured[0].url, /token=|authorization_ref|signature|Bearer/);
  assert.ok(captured[0].init.headers && typeof captured[0].init.headers === 'object');
});

test('senior revoke posts only expected_version and meaningful reason, with header auth', async () => {
  const captured = [];
  globalThis.fetch = async (url, init) => {
    captured.push({ url, init });
    return fakeResponse({
      status: 'revoked',
      authorization_version: 7,
      halt_request_accepted: false,
      remote_execution_outcome: 'unknown',
    });
  };
  const result = await supervision.supervisionApi.revokeAuthorization(
    'eng-one', 7, '  Scope ownership was withdrawn  ',
  );
  assert.equal(result.status, 'revoked');
  assert.equal(result.halt_request_accepted, false);
  assert.equal(result.remote_execution_outcome, 'unknown');
  assert.equal(captured.length, 1);
  assert.match(captured[0].url, /\/engagements\/eng-one\/authorization\/revoke$/);
  assert.equal(captured[0].init.method, 'POST');
  assert.equal(captured[0].init.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(captured[0].init.body), {
    expected_version: 7,
    reason: 'Scope ownership was withdrawn',
  });
  assert.doesNotMatch(captured[0].url, /token=|Bearer|reason=/);
});

test('invalid stale versions and empty revocation reasons never issue fetch', async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return fakeResponse({});
  };
  for (const version of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN]) {
    assert.throws(
      () => supervision.supervisionApi.revokeAuthorization('eng-one', version, 'Meaningful reason'),
      /version/,
    );
  }
  for (const reason of ['', 'too short', ' '.repeat(50), 'x'.repeat(501)]) {
    assert.throws(
      () => supervision.supervisionApi.revokeAuthorization('eng-one', 7, reason),
      /10–500/,
    );
  }
  assert.equal(calls, 0);
});

test('409 CAS conflict never becomes claimed revocation acknowledgement', async () => {
  globalThis.fetch = async () => fakeResponse(
    { detail: 'Authorization version is stale' }, 409,
  );
  await assert.rejects(
    () => supervision.supervisionApi.revokeAuthorization('eng-one', 7, 'Ownership withdrawn'),
    (cause) => cause.status === 409,
  );
});

test('panel exposes remote UNKNOWN, legacy unverified and senior-only revoke semantics', () => {
  const markup = renderToStaticMarkup(createElement(panel.SupervisionPanel, {
    engagementId: 'eng-one',
    tasks: [],
    canControl: false,
  }));
  assert.match(markup, /SIGNED ROE AUTHORIZATION/);
  assert.match(markup, /POSTGRESQL/);
  assert.match(markup, /senior_operator access/);
  const src = readFileSync(
    new URL('../src/components/flows/SupervisionPanel.tsx', import.meta.url), 'utf8',
  );
  assert.match(src, /operatorRoleHint\(\) === 'senior_operator'/);
  assert.match(src, /authorization\.status === 'revoked'/);
  assert.match(src, /remote_execution_outcome !== 'unknown'/);
  assert.match(src, /Remote execution outcome UNKNOWN/);
  assert.match(src, /Revocation acknowledged/);
  assert.doesNotMatch(src, /revocation confirmed remote stopped|remote terminated successfully/i);
  assert.doesNotMatch(src, /dev-token|\?token=|&token=/);
});
