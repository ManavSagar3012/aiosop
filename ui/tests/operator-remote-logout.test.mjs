import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let api;

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

const verified = () => ({
  ok: true,
  json: async () => ({
    sub: 'operator-local',
    role: 'operator',
    exp: Math.floor(Date.now() / 1000) + 300,
  }),
});

test('explicit sign-out removes bearer before durable status response and never puts it in URL', async () => {
  const requests = [];
  let release;
  globalThis.fetch = (url, options) => {
    requests.push({ url, options });
    if (url.endsWith('/auth/me')) return Promise.resolve(verified());
    return new Promise((resolve) => { release = resolve; });
  };
  await api.signIn('signed-only-in-memory');
  assert.equal(api.AUTH_TOKEN, 'signed-only-in-memory');
  const pending = api.revokeAndSignOut();
  assert.equal(api.AUTH_TOKEN, '');
  assert.equal(api.currentOperator(), null);
  assert.equal(requests[1].url, api.API_BASE + '/auth/logout');
  assert.equal(requests[1].options.method, 'POST');
  assert.equal(requests[1].options.headers.Authorization, 'Bearer signed-only-in-memory');
  assert.equal(requests[1].options.credentials, 'omit');
  assert.equal(requests[1].options.redirect, 'error');
  assert.equal(requests[1].url.includes('signed-only-in-memory'), false);
  release({ ok: true, json: async () => ({ status: 'revoked' }) });
  assert.equal(await pending, true);
});

test('unavailable durable revocation stays unconfirmed while local sign-out remains immediate', async () => {
  globalThis.fetch = async (url) => {
    if (url.endsWith('/auth/me')) return verified();
    throw new Error('Untrusted provider error including bearer secret');
  };
  await api.signIn('second-signed-in-memory');
  assert.equal(await api.revokeAndSignOut(), false);
  assert.equal(api.AUTH_TOKEN, '');
  assert.equal(api.currentOperator(), null);
  assert.equal(await api.revokeAndSignOut(), false);
});

test('delayed revocation reply cannot sign out a newly admitted operator', async () => {
  let resolveLogout;
  globalThis.fetch = async (url) => {
    if (url.endsWith('/auth/me')) return verified();
    return new Promise((resolve) => { resolveLogout = resolve; });
  };
  await api.signIn('first-signed-token');
  const logout = api.revokeAndSignOut();
  await api.signIn('next-signed-token');
  resolveLogout({ ok: true, json: async () => ({ status: 'revoked' }) });
  assert.equal(await logout, true);
  assert.equal(api.AUTH_TOKEN, 'next-signed-token');
});
