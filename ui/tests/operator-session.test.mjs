import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
let vite;
let api;
let network;
let oldFetch;
let oldWebSocket;
let sockets = [];

class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 3;
  constructor(url) {
    this.url = url;
    this.readyState = FakeWebSocket.CONNECTING;
    this.sent = [];
    sockets.push(this);
  }
  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.({});
  }
  send(payload) {
    this.sent.push(JSON.parse(payload));
  }
  close(code = 1000) {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code });
  }
  receive(payload) {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }
}

before(async () => {
  oldFetch = globalThis.fetch;
  oldWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = FakeWebSocket;
  // A Vite credential, even when configured, must never become a bearer.
  process.env.VITE_OSOP_TOKEN = 'PUBLIC_BUILD_SECRET_MUST_BE_IGNORED';
  vite = await createServer({ root, logLevel: 'silent', appType: 'custom',
    server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  network = await vite.ssrLoadModule('/src/services/network.ts');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = oldFetch;
  globalThis.WebSocket = oldWebSocket;
  delete process.env.VITE_OSOP_TOKEN;
  await vite?.close();
});

test('build-time Vite bearer is ignored; no authentication before server verification', () => {
  api.signOut();
  assert.equal(api.AUTH_TOKEN, '');
  assert.deepEqual(api.authHeaders(), {});
  assert.equal(api.getRuntimeToken(), '');
  assert.equal(api.currentOperator(), null);
  assert.equal(api.isSecureApiBase('http://public.example'), false);
  assert.equal(api.isSecureApiBase('http://127.0.0.1:8081'), true);
  assert.equal(api.isSecureApiBase('https://api.example'), true);
  assert.equal(api.isSecureApiBase('https://user:password@api.example'), false);
  assert.equal(api.isSecureApiBase('https://api.example?token=secret'), false);
});

test('only /auth/me verified identity enables tab-memory bearer; sign-out erases it', async () => {
  api.signOut();
  const calls = [];
  const token = 'opaque-issued-test-bearer';
  const exp = Math.floor(Date.now() / 1000) + 3600;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, json: async () => ({ sub: 'operator-alice', role: 'operator', exp }) };
  };
  const seen = [];
  const unsubscribe = api.subscribeOperator((identity) => seen.push(identity?.sub ?? null));
  try {
    const identity = await api.signIn(token);
    assert.deepEqual(identity, { sub: 'operator-alice', role: 'operator', exp });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `${api.API_BASE}/auth/me`);
    assert.deepEqual(calls[0].options.headers, {
      Authorization: `Bearer ${token}`, Accept: 'application/json',
    });
    assert.equal(calls[0].options.cache, 'no-store');
    assert.equal(calls[0].options.credentials, 'omit');
    assert.equal(calls[0].options.redirect, 'error');
    assert.equal(api.authHeaders({ Accept: 'application/json' }).Authorization, `Bearer ${token}`);
    assert.equal(api.AUTH_TOKEN, token);
    api.signOut();
    assert.equal(api.AUTH_TOKEN, '');
    assert.deepEqual(api.authHeaders(), {});
    assert.equal(api.currentOperator(), null);
    assert.deepEqual(seen, [null, 'operator-alice', null]);
  } finally {
    unsubscribe();
    api.signOut();
  }
});

test('invalid server proof, expired identity, and logout during login fail closed', async () => {
  api.signOut();
  globalThis.fetch = async () => ({ ok: false, status: 401 });
  await assert.rejects(api.signIn('tampered'), /rejected or expired/);
  assert.equal(api.AUTH_TOKEN, '');
  globalThis.fetch = async () => ({ ok: true, json: async () => ({
    sub: 'alice', role: 'senior_operator', exp: 123,
  }) });
  await assert.rejects(api.signIn('expired'), /incomplete or expired/);
  assert.equal(api.AUTH_TOKEN, '');

  let finish;
  globalThis.fetch = () => new Promise((resolve) => { finish = resolve; });
  const attempting = api.signIn('valid-but-stale');
  api.signOut();
  finish({ ok: true, json: async () => ({ sub: 'alice', role: 'operator', exp: null }) });
  await assert.rejects(attempting, /cancelled/);
  assert.deepEqual(api.authHeaders(), {});
});

test('websocket uses runtime credential at connect and closes on sign-out', async () => {
  api.signOut();
  sockets = [];
  const service = new network.NetworkService(() => {});
  try {
    service.connect('eng-inert');
    assert.equal(sockets.length, 0);
    globalThis.fetch = async () => ({ ok: true, json: async () => ({
      sub: 'operator-bob', role: 'operator', exp: null,
    }) });
    await api.signIn('verified-ws-credential');
    service.connect('eng-inert');
    assert.equal(sockets.length, 1);
    const ws = sockets[0];
    assert.equal(ws.url, `${api.WS_BASE}/ws/engagements/eng-inert`);
    assert.equal(ws.url.includes('?'), false);
    ws.open();
    assert.deepEqual(ws.sent, [{ type: 'auth', token: 'verified-ws-credential' }]);
    assert.equal(service.getMetrics().status, 'reconnecting');
    ws.receive({ type: 'auth_ready', session_id: 'eng-inert' });
    assert.equal(service.getMetrics().status, 'connected');
    api.signOut();
    assert.equal(ws.readyState, FakeWebSocket.CLOSED);
    assert.equal(service.getMetrics().status, 'disconnected');
    assert.equal(service.sendCommand('status'), false);
    service.connect('eng-inert');
    assert.equal(sockets.length, 1);
  } finally {
    service.disconnect();
    api.signOut();
  }
});

test('late REST hydration cannot repopulate operator data after logout', async () => {
  api.signOut();
  globalThis.fetch = async () => ({ ok: true, json: async () => ({
    sub: 'operator-before-logout', role: 'operator', exp: null,
  }) });
  await api.signIn('first-session-token');
  let answer;
  let resolveRequest;
  globalThis.fetch = () => new Promise((resolve) => { resolveRequest = resolve; });
  const service = new network.NetworkService(() => {});
  try {
    const hydration = service.hydrate('eng-before-logout');
    api.signOut();
    resolveRequest({ ok: true, json: async () => ({ phase: 'sensitive-previous-phase' }) });
    await hydration;
    const store = await vite.ssrLoadModule('/src/store/useSwarmStore.ts');
    answer = store.useSwarmStore.getState().currentPhase;
    assert.notEqual(answer, 'sensitive-previous-phase');
  } finally {
    service.disconnect();
    api.signOut();
  }
});
