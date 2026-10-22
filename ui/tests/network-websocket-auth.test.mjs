import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const previousEnv = process.env.VITE_OSOP_TOKEN;
let vite;
let network;
let api;
let originalWebSocket;
let originalFetch;
let sockets = [];

class StubWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url) {
    this.url = url;
    this.readyState = StubWebSocket.CONNECTING;
    this.sent = [];
    this.closeCode = null;
    sockets.push(this);
  }

  open() {
    this.readyState = StubWebSocket.OPEN;
    this.onopen?.({});
  }

  send(body) {
    assert.equal(this.readyState, StubWebSocket.OPEN);
    this.sent.push(JSON.parse(body));
  }

  emit(message) {
    this.onmessage?.({ data: JSON.stringify(message) });
  }

  close(code = 1000) {
    if (this.readyState === StubWebSocket.CLOSED) return;
    this.closeCode = code;
    this.readyState = StubWebSocket.CLOSED;
    this.onclose?.({ code });
  }
}

before(async () => {
  process.env.VITE_OSOP_TOKEN = 'ws-test-only-bearer';
  originalWebSocket = globalThis.WebSocket;
  originalFetch = globalThis.fetch;
  globalThis.WebSocket = StubWebSocket;
  vite = await createServer({
    root, logLevel: 'silent', appType: 'custom',
    server: { middlewareMode: true },
  });
  network = await vite.ssrLoadModule('/src/services/network.ts');
  api = await vite.ssrLoadModule('/src/services/api.ts');
  // A build-time Vite variable no longer grants operator privileges.
  // The current runtime credential is admitted only after verified /auth/me.
  globalThis.fetch = async (url, options) => {
    assert.equal(url, api.API_BASE + '/auth/me');
    assert.equal(options.headers.Authorization, 'Bearer ws-test-only-bearer');
    return {
      ok: true,
      json: async () => ({
        sub: 'ws-test-operator',
        role: 'operator',
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    };
  };
  await api.signIn('ws-test-only-bearer');
});

after(async () => {
  api?.signOut();
  await vite?.close();
  globalThis.WebSocket = originalWebSocket;
  globalThis.fetch = originalFetch;
  if (previousEnv === undefined) delete process.env.VITE_OSOP_TOKEN;
  else process.env.VITE_OSOP_TOKEN = previousEnv;
});

test('never puts bearer in URL; only first auth frame, connected after explicit ready ack', () => {
  sockets = [];
  const statuses = [];
  const service = new network.NetworkService((value) => statuses.push(value));
  try {
    service.connect('eng-ws-safe');
    assert.equal(sockets.length, 1);
    const ws = sockets[0];
    assert.equal(ws.url, `${api.WS_BASE}/ws/engagements/eng-ws-safe`);
    assert.equal(ws.url.includes('?'), false);
    assert.equal(service.getMetrics().status, 'reconnecting');
    assert.equal(service.sendCommand('status'), false);
    ws.open();
    assert.deepEqual(ws.sent, [{ type: 'auth', token: api.AUTH_TOKEN }]);
    assert.equal(service.getMetrics().status, 'reconnecting');
    assert.equal(service.sendCommand('ping'), false);
    ws.emit({ type: 'auth_ready', session_id: 'eng-ws-safe' });
    assert.equal(service.getMetrics().status, 'connected');
    assert.equal(service.sendCommand('status'), true);
    assert.deepEqual(ws.sent[1], { action: 'status' });
    assert.equal(service.sendCommand('halt', 'x\nSECRET'), false);
    assert.equal(ws.sent.length, 2);
    ws.emit({ type: 'pong' });
    ws.emit({ type: 'status', session_id: 'eng-ws-safe', phase: 'reporting' });
    assert.equal(service.getMetrics().throughput, 0);
    assert.ok(statuses.includes('connected'));
  } finally {
    service.disconnect();
  }
});

test('unexpected pre-auth ack or unauthenticated event fails closed and does not retry', async () => {
  sockets = [];
  const service = new network.NetworkService(() => {});
  try {
    service.connect('eng-ws-safe');
    const ws = sockets.at(-1);
    ws.open();
    ws.emit({ event_type: 'finding_update', engagement_id: 'eng-ws-safe' });
    assert.equal(ws.closeCode, 1008);
    assert.equal(service.getMetrics().status, 'disconnected');
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(sockets.length, 1);
  } finally {
    service.disconnect();
  }
});

test('late events from obsolete sockets cannot authenticate a newer connection', () => {
  sockets = [];
  const service = new network.NetworkService(() => {});
  try {
    service.connect('eng-first');
    const first = sockets.at(-1);
    first.open();
    service.connect('eng-next');
    assert.equal(first.readyState, StubWebSocket.CLOSED);
    const latest = sockets.at(-1);
    first.emit({ type: 'auth_ready', session_id: 'eng-first' });
    assert.notEqual(service.getMetrics().status, 'connected');
    latest.open();
    latest.emit({ type: 'auth_ready', session_id: 'eng-next' });
    assert.equal(service.getMetrics().status, 'connected');
    latest.emit({ event_type: 'secret', engagement_id: 'different-tenant' });
    assert.equal(latest.closeCode, 1008);
    assert.equal(service.getMetrics().status, 'disconnected');
  } finally {
    service.disconnect();
  }
});

test('explicit disconnect cancels retry scheduling after a transient WS outage', async () => {
  sockets = [];
  const statuses = [];
  const service = new network.NetworkService((status) => statuses.push(status));
  service.connect('eng-ws-safe');
  const first = sockets.at(-1);
  first.open();
  first.emit({ type: 'auth_ready', session_id: 'eng-ws-safe' });
  first.close(1006);
  assert.equal(service.getMetrics().status, 'reconnecting');
  service.disconnect();
  await new Promise((resolve) => setTimeout(resolve, 1050));
  assert.equal(sockets.length, 1);
  assert.equal(service.getMetrics().status, 'disconnected');
});

test('invalid engagement ID is rejected locally; no socket or token URL produced', () => {
  sockets = [];
  const service = new network.NetworkService(() => {});
  try {
    service.connect('eng?token=should-not-leak');
    assert.equal(sockets.length, 0);
    assert.equal(service.getMetrics().status, 'error');
  } finally {
    service.disconnect();
  }
});

test('plaintext non-loopback WebSocket destinations cannot receive any bearer', () => {
  assert.equal(network.isSafeWebSocketBase('ws://public.example:8200'), false);
  assert.equal(network.isSafeWebSocketBase('https://public.example'), false);
  assert.equal(network.isSafeWebSocketBase('wss://public.example:8200'), true);
  assert.equal(network.isSafeWebSocketBase('ws://127.0.0.1:8081'), true);
  assert.equal(network.isSafeWebSocketBase('ws://localhost:8081'), true);
  assert.equal(network.isSafeWebSocketBase('wss://public.example?token=bad'), false);
  assert.equal(network.isSafeWebSocketBase('wss://user:secret@public.example'), false);
});
