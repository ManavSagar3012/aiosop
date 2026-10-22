/** Offline signed-operator leased SSE parser; no real network or provider. */
import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const scope = { engagementId: 'eng-local-stream', subscriberId: 'subscr-' + 'a'.repeat(32), taskId: 'task-local-stream' };
const lease = () => ({
  engagement_id: scope.engagementId, subscriber_id: scope.subscriberId,
  replica_id: 'replica-local-stream', lease_id: 'lease-' + 'b'.repeat(32),
  generation: 1, cursor: 0, lease_until: new Date(Date.now() + 60000).toISOString(),
  delivery_semantics: 'at_least_once', provider_effect: 'unobserved',
});
const event = (sequence, patch = {}) => ({
  sequence, id: 'evt-' + sequence, engagement_id: scope.engagementId,
  task_id: scope.taskId, kind: 'agent.message', actor_id: 'operator-fixture',
  payload: { test: true }, created_at: new Date().toISOString(), ...patch,
});
const frame = row => `id: ${row.sequence}\nevent: supervision\ndata: ${JSON.stringify(row)}\n\n`;
const complete = 'event: stream_complete\ndata: {"acknowledged":false,"client_receipt_verified":false}\n\n';
const reply = (body, status = 200, contentType = 'text/event-stream; charset=utf-8') => new Response(body, {
  status, headers: { 'Content-Type': contentType },
});

let vite, auth, client, requested, queued;
before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  client = await vite.ssrLoadModule('/src/services/leasedSupervisionStream.ts');
});
after(async () => { auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close(); });

async function login() {
  auth.signOut(); requested = []; queued = [];
  globalThis.fetch = async (url, options = {}) => {
    if (new URL(String(url)).pathname === '/auth/me') {
      return new Response(JSON.stringify({ sub: 'operator-fixture', role: 'operator', exp: Math.floor(Date.now() / 1000) + 3600 }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    requested.push({ url: new URL(String(url)), options });
    const next = queued.shift();
    if (!next) throw Error('Test-only unqueued call');
    return typeof next === 'function' ? next() : next;
  };
  await auth.signIn('memory-only-test-bearer');
}

test('mounted leased stream client posts scoped bearer once, parses frames, never ACKs', async () => {
  await login();
  queued.push(reply(frame(event(11)) + frame(event(19)) + complete));
  const rows = await client.readLeasedSupervisionStream(scope, lease());
  assert.deepEqual(rows.map(item => item.sequence), [11, 19]);
  assert.equal(requested.length, 1);
  assert.ok(requested[0].url.pathname.endsWith('/leased-stream'));
  assert.equal(requested[0].options.method, 'POST');
  assert.equal(requested[0].options.credentials, 'omit');
  assert.equal(requested[0].options.redirect, 'error');
  assert.equal(requested[0].options.headers.Authorization, 'Bearer memory-only-test-bearer');
  assert.equal(requested[0].options.headers.Accept, 'text/event-stream');
  assert.deepEqual(JSON.parse(requested[0].options.body), {
    replica_id: 'replica-local-stream', lease_id: 'lease-' + 'b'.repeat(32),
    generation: 1, cursor: 0, task_id: scope.taskId, limit: 20, wait_seconds: 5,
  });
  assert.ok(!requested[0].url.search);
});

test('foreign task, duplicate sequence, broken frame, HTML and forged extra rows deny', async () => {
  await login();
  const invalid = [
    frame(event(11, { task_id: 'task-other' })),
    frame(event(11)) + frame(event(11)),
    `event: success\ndata: {"verified":true}\n\n`,
    frame(event(11, { engagement_id: 'eng-other' })),
    frame(event(11)).slice(0, -1),
    frame(event(11)), // A physically truncated SSE batch cannot be called complete.
    complete + frame(event(11)),
  ];
  for (const value of invalid) {
    queued.push(reply(value));
    await assert.rejects(client.readLeasedSupervisionStream(scope, lease()));
  }
  queued.push(reply('<html>not an event</html>', 200, 'text/html'));
  await assert.rejects(client.readLeasedSupervisionStream(scope, lease()), /unavailable/);
  assert.equal(requested.length, invalid.length + 1);
});

test('oversized frame and bounded original HTTP body do not publish events', async () => {
  await login();
  queued.push(reply(frame(event(11, { payload: { text: 'x'.repeat(9000) } }))));
  await assert.rejects(client.readLeasedSupervisionStream(scope, lease()), /Oversized/);
  queued.push(reply('x'.repeat(256 * 1024 + 1)));
  await assert.rejects(client.readLeasedSupervisionStream(scope, lease()), /bounds/);
  assert.equal(requested.length, 2);
});

test('signout while stream opens discards frames and never retries', async () => {
  await login();
  queued.push(() => { auth.signOut(); return reply(frame(event(11))); });
  await assert.rejects(client.readLeasedSupervisionStream(scope, lease()), /Operator changed/);
  assert.equal(requested.length, 1);
  await assert.rejects(client.readLeasedSupervisionStream(scope, lease()), /verified human operator/);
  assert.equal(requested.length, 1);
});

test('forged lease claiming delivery guarantee or provider effects fails before fetch', async () => {
  await login();
  await assert.rejects(client.readLeasedSupervisionStream(scope, {
    ...lease(), delivery_semantics: 'exactly_once',
  }), /lease required/);
  await assert.rejects(client.readLeasedSupervisionStream(scope, {
    ...lease(), provider_effect: 'verified',
  }), /lease required/);
  assert.equal(requested.length, 0);
});
