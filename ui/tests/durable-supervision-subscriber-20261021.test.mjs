/** Offline contract tests of the real authenticated subscriber UI client. */
import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const expiry = Math.floor(Date.now() / 1000) + 3600;
const engagementId = 'eng-fixture';
const subscriberId = 'subscr-' + 'b'.repeat(32);
const replicaId = 'replica-readerfixture';
const leaseId = 'lease-' + 'c'.repeat(32);
const scope = { engagementId, subscriberId, taskId: 'task-fixture' };
const lease = (cursor = 0) => ({
  engagement_id: engagementId, subscriber_id: subscriberId,
  replica_id: replicaId, lease_id: leaseId, generation: 1, cursor,
  lease_until: new Date(Date.now() + 60000).toISOString(),
  delivery_semantics: 'at_least_once', provider_effect: 'unobserved',
});
const event = sequence => ({
  id: `evt-${sequence}`, sequence, engagement_id: engagementId,
  task_id: 'task-fixture', kind: 'task_observed', actor_id: 'operator',
  payload: { untrusted: true }, created_at: new Date().toISOString(),
});
const reply = (body, code = 200) => new Response(JSON.stringify(body), {
  status: code, headers: { 'Content-Type': 'application/json' },
});

let vite, auth, api, panel, requested, queued;
before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  api = await vite.ssrLoadModule('/src/services/durableSupervisionSubscribers.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/DurableSupervisionSubscribersPanel.tsx');
});
after(async () => { auth?.signOut(); globalThis.fetch = originalFetch; await vite?.close(); });

async function login() {
  requested = [];
  queued = [];
  auth.signOut();
  globalThis.fetch = async (url, options = {}) => {
    if (new URL(String(url)).pathname === '/auth/me') {
      return reply({ sub: 'operator-one', role: 'operator', exp: expiry });
    }
    requested.push({ url: new URL(String(url)), options });
    const next = queued.shift();
    if (!next) throw new Error('Unqueued test-only request');
    return typeof next === 'function' ? await next() : next;
  };
  await auth.signIn('verified-in-memory-bearer');
}

test('UI makes durable cursor, human manual ACK and non-effect status explicit', async () => {
  await login();
  const html = renderToStaticMarkup(createElement(panel.DurableSupervisionSubscribersPanel, {
    engagementId, taskId: 'task-fixture', canControl: true,
  }));
  assert.match(html, /MANUAL POSTGRESQL ACK/);
  assert.match(html, /Reading never acknowledges delivery/);
  assert.match(html, /target-owner effects/);
  assert.match(html, /PERMANENTLY REVOKE/);
  assert.doesNotMatch(html, /verified-in-memory-bearer/);
});

test('signed scoped acquire/read/ack posts strict original identities and no retry', async () => {
  await login();
  queued.push(reply({ lease: lease() }));
  const current = await api.durableSubscriberApi.acquire(scope, replicaId);
  assert.equal(current.cursor, 0);
  queued.push(reply({ events: [event(12), event(18)], cursor: 0, acknowledged: false,
    delivery_semantics: 'at_least_once' }));
  const data = await api.durableSubscriberApi.read(scope, current);
  assert.deepEqual(data.map(item => item.sequence), [12, 18]);
  queued.push(reply({ lease: lease(12), acknowledged: true }));
  const ack = await api.durableSubscriberApi.acknowledge(scope, current, data[0].sequence);
  assert.equal(ack.cursor, 12);
  assert.equal(requested.length, 3);
  assert.deepEqual(requested.map(item => item.url.pathname.split('/').at(-1)), ['acquire', 'read', 'ack']);
  for (const item of requested) {
    assert.equal(item.options.method, 'POST');
    assert.equal(item.options.headers.Authorization, 'Bearer verified-in-memory-bearer');
    assert.equal(item.options.credentials, 'omit');
    assert.equal(item.options.redirect, 'error');
    assert.ok(!item.url.search.includes('Bearer') && !item.url.search.includes('token'));
  }
  assert.deepEqual(JSON.parse(requested[2].options.body), {
    replica_id: replicaId, lease_id: leaseId, generation: 1, cursor: 0,
    task_id: 'task-fixture', expected_cursor: 0, next_sequence: 12,
  });
});

test('UNKNOWN ACK can only recover committed cursor by separate read-only fenced readback', async () => {
  await login();
  const observed = lease(0);
  const committed = lease(11);
  const payload = newLease => ({
    lease: newLease, cursor_readback: 'committed_database_state_only',
    acknowledgement_delivered_to_client_verified: false,
    safe_to_retry_unknown_ack: false, target_effect_verified: false,
  });
  queued.push(reply(payload(committed)));
  const result = await api.durableSubscriberApi.readCommittedCursor(scope, observed);
  assert.equal(result.cursor, 11);
  assert.equal(requested.length, 1);
  assert.equal(requested[0].url.pathname.split('/').at(-1), 'cursor-readback');
  assert.deepEqual(JSON.parse(requested[0].options.body), {
    replica_id: replicaId, lease_id: leaseId, generation: 1, cursor: 0,
    task_id: 'task-fixture',
  });
  // A backend claiming delivery, permission to resend, target effects, or a
  // different owner/lease/older cursor MUST NOT become a confirmed ACK.
  for (const forged of [
    { ...payload(committed), acknowledgement_delivered_to_client_verified: true },
    { ...payload(committed), safe_to_retry_unknown_ack: true },
    { ...payload(committed), target_effect_verified: true },
    payload({ ...committed, replica_id: 'replica-foreign' }),
    payload({ ...committed, cursor: 0 }),
    { ...payload(committed), verified_provider_execution: true },
  ]) {
    queued.push(reply(forged));
    if (forged.lease?.cursor === 0) {
      // Current equal to old is a legal truthful "no ACK committed" readback.
      assert.equal((await api.durableSubscriberApi.readCommittedCursor(scope, observed)).cursor, 0);
    } else {
      await assert.rejects(api.durableSubscriberApi.readCommittedCursor(scope, observed));
    }
  }
  assert.ok(requested.every(x => x.url.pathname.endsWith('/cursor-readback')));
  assert.equal(requested.length, 7);
});

test('forged provider effects, foreign tenants and stale readbacks fail closed', async () => {
  await login();
  for (const forged of [
    { ...lease(), provider_effect: 'verified' },
    { ...lease(), engagement_id: 'eng-other' },
    { ...lease(), lease_until: '2001-01-01T00:00:00Z' },
    { ...lease(), cursor: 1.2 },
  ]) {
    queued.push(reply({ lease: forged }));
    await assert.rejects(api.durableSubscriberApi.acquire(scope, replicaId), /lease was not proven/);
  }
  queued.push(reply({ events: [{ ...event(12), task_id: 'task-other' }], cursor: 0,
    acknowledged: false, delivery_semantics: 'at_least_once' }));
  await assert.rejects(api.durableSubscriberApi.read(scope, lease()), /not bound/);
  queued.push(reply({ lease: lease(13), acknowledged: true }));
  await assert.rejects(api.durableSubscriberApi.acknowledge(scope, lease(), 12), /ACK CAS mismatch/);
});

test('session switch during a successful server mutation discards stale response', async () => {
  await login();
  queued.push(async () => { auth.signOut(); return reply({ lease: lease() }); });
  await assert.rejects(api.durableSubscriberApi.acquire(scope, replicaId), /session changed/);
  assert.equal(requested.length, 1);
  await assert.rejects(api.durableSubscriberApi.acquire(scope, replicaId), /verified human operator/);
  assert.equal(requested.length, 1);
});

test('unknown mutation and rejected revocation never automatically retry', async () => {
  await login();
  queued.push(reply({ detail: 'stale CAS' }, 409));
  await assert.rejects(api.durableSubscriberApi.acquire(scope, replicaId), /UNKNOWN/);
  assert.equal(requested.length, 1);
  queued.push(reply({ revoked: true, safe_to_retry: true }));
  await assert.rejects(api.durableSubscriberApi.revoke(scope), /unconfirmed/);
  assert.equal(requested.length, 2);
  queued.push(reply({ revoked: true, safe_to_retry: false }));
  await api.durableSubscriberApi.revoke(scope);
  assert.equal(requested.length, 3);
});

test('oversize provider-shaped HTTP and missing JSON content type fail without ACK', async () => {
  await login();
  queued.push(new Response('x'.repeat(256 * 1024 + 1), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }));
  await assert.rejects(api.durableSubscriberApi.acquire(scope, replicaId), /exceeded bounds/);
  queued.push(new Response(JSON.stringify({ lease: lease() }), {
    status: 200, headers: { 'Content-Type': 'text/html' },
  }));
  await assert.rejects(api.durableSubscriberApi.acquire(scope, replicaId), /not JSON/);
  assert.equal(requested.length, 2);
});

test('invalid subscriber identifiers cannot access any storage or external URL', async () => {
  await login();
  for (const invalid of [
    { ...scope, engagementId: 'eng-foreign/../../scan' },
    { ...scope, subscriberId: 'subscr-not-a-uuid' },
    { ...scope, taskId: 'task-fixture?authorization=forged' },
  ]) {
    await assert.rejects(api.durableSubscriberApi.acquire(invalid, replicaId), /valid current engagement/);
  }
  assert.equal(requested.length, 0);
});
