/** Human-controlled durable subscriber cursor. Never interprets a lease as execution authority. */
import { API_BASE, getRuntimeToken, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const ENGAGEMENT = /^eng-[A-Za-z0-9._-]{1,60}$/;
const SUBSCRIBER = /^subscr-[a-f0-9]{32}$/;
const TASK = /^task-[A-Za-z0-9._:-]{1,59}$/;
const REPLICA = /^replica-[A-Za-z0-9._-]{1,90}$/;
const LEASE = /^lease-[a-f0-9]{32}$/;

export type SubscriberScope = {
  engagementId: string;
  subscriberId: string;
  taskId?: string;
};

export type DurableSubscriberLease = {
  engagement_id: string;
  subscriber_id: string;
  replica_id: string;
  lease_id: string;
  generation: number;
  cursor: number;
  lease_until: string;
  delivery_semantics: 'at_least_once';
  provider_effect: 'unobserved';
};

export type DurableSubscriberEvent = {
  id: string;
  engagement_id: string;
  task_id: string | null;
  sequence: number;
  kind: string;
  actor_id: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export function newDurableSubscriberId(): string {
  if (typeof crypto === 'undefined' || typeof crypto.randomUUID !== 'function') {
    throw new Error('Secure random subscriber identity unavailable.');
  }
  return 'subscr-' + crypto.randomUUID().replace(/-/g, '').toLowerCase();
}

function validScope(scope: SubscriberScope): void {
  if (!ENGAGEMENT.test(scope.engagementId) || !SUBSCRIBER.test(scope.subscriberId)
    || (scope.taskId !== undefined && !TASK.test(scope.taskId))) {
    throw new Error('A valid current engagement, subscriber and Task identity is required.');
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function validLease(scope: SubscriberScope, candidate: unknown): DurableSubscriberLease {
  if (!object(candidate) || candidate.engagement_id !== scope.engagementId
    || candidate.subscriber_id !== scope.subscriberId
    || typeof candidate.replica_id !== 'string' || !REPLICA.test(candidate.replica_id)
    || typeof candidate.lease_id !== 'string' || !LEASE.test(candidate.lease_id)
    || !Number.isSafeInteger(candidate.generation) || (candidate.generation as number) < 1
    || !Number.isSafeInteger(candidate.cursor) || (candidate.cursor as number) < 0
    || typeof candidate.lease_until !== 'string'
    || !Number.isFinite(Date.parse(candidate.lease_until))
    || Date.parse(candidate.lease_until) <= Date.now()
    || candidate.delivery_semantics !== 'at_least_once'
    || candidate.provider_effect !== 'unobserved') {
    throw new Error('A current PostgreSQL-fenced subscriber lease was not proven.');
  }
  return candidate as DurableSubscriberLease;
}

function binding(scope: SubscriberScope, lease: DurableSubscriberLease): Record<string, unknown> {
  validLease(scope, lease);
  return {
    replica_id: lease.replica_id, lease_id: lease.lease_id,
    generation: lease.generation, cursor: lease.cursor, task_id: scope.taskId ?? null,
  };
}

async function post(scope: SubscriberScope, action: string, body: object): Promise<unknown> {
  validScope(scope);
  if (!isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Durable subscriber operations require a secure API origin.');
  }
  const operator = currentOperator();
  const token = getRuntimeToken();
  if (!operator || !token || !['operator', 'senior_operator'].includes(operator.role)) {
    throw new Error('A current verified human operator session is required.');
  }
  // Never implicitly retry an unknown lease or ACK request: PostgreSQL may have committed it.
  const response = await fetch(
    `${API_BASE}/supervision/engagements/${encodeURIComponent(scope.engagementId)}`
      + `/subscriptions/${encodeURIComponent(scope.subscriberId)}/${action}`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
    },
  );
  // No stale response should cross a sign-out, expiry, or switch of verified operator.
  if (getRuntimeToken() !== token || currentOperator()?.sub !== operator.sub) {
    throw new Error('Operator session changed; lease outcome UNKNOWN. Do not retry automatically.');
  }
  if (!response.ok) {
    throw new Error(`Subscriber ${action} returned HTTP ${response.status}. The original outcome may be UNKNOWN.`);
  }
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
    response.headers.get('content-type')?.trim() ?? '',
  )) {
    throw new Error('Subscriber authority response is not JSON. Original outcome UNKNOWN.');
  }
  // Bound the original HTTP bytes before decoding/parsing. A malicious gateway
  // must not force unbounded buffering through Response.text().
  const limit = 256 * 1024;
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength)
    || !Number.isSafeInteger(Number(declaredLength)) || Number(declaredLength) > limit)) {
    throw new Error('Subscriber response exceeded bounds. Original outcome UNKNOWN.');
  }
  if (!response.body) throw new Error('Subscriber response body unavailable. Original outcome UNKNOWN.');
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let data = '';
  let received = 0;
  let finished = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) { finished = true; break; }
      received += value.byteLength;
      if (received > limit) throw new Error('Subscriber response exceeded bounds. Original outcome UNKNOWN.');
      data += decoder.decode(value, { stream: true });
    }
    data += decoder.decode();
  } catch (cause) {
    throw new Error(cause instanceof Error ? cause.message : 'Subscriber response cannot be read. Outcome UNKNOWN.');
  } finally {
    if (!finished) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  let parsed: unknown;
  try { parsed = JSON.parse(data); } catch { throw new Error('Subscriber response invalid. Original outcome UNKNOWN.'); }
  if (getRuntimeToken() !== token || currentOperator()?.sub !== operator.sub) {
    throw new Error('Operator identity changed before readback. Original outcome UNKNOWN.');
  }
  return parsed;
}

export const durableSubscriberApi = {
  acquire: async (scope: SubscriberScope, replicaId: string): Promise<DurableSubscriberLease> => {
    if (!REPLICA.test(replicaId)) throw new Error('Valid local reader replica identity required.');
    const data = await post(scope, 'acquire', { replica_id: replicaId, task_id: scope.taskId ?? null });
    if (!object(data)) throw new Error('Committed lease response missing.');
    return validLease(scope, data.lease);
  },
  read: async (scope: SubscriberScope, lease: DurableSubscriberLease): Promise<DurableSubscriberEvent[]> => {
    const data = await post(scope, 'read', { ...binding(scope, lease), limit: 20 });
    if (!object(data) || data.acknowledged !== false || data.delivery_semantics !== 'at_least_once'
      || data.cursor !== lease.cursor || !Array.isArray(data.events) || data.events.length > 20) {
      throw new Error('Committed event batch provenance unavailable. Cursor not acknowledged.');
    }
    let previous = lease.cursor;
    for (const event of data.events) {
      if (!object(event) || !Number.isSafeInteger(event.sequence)
        || (event.sequence as number) <= previous || event.engagement_id !== scope.engagementId
        || (scope.taskId !== undefined && event.task_id !== scope.taskId)
        || !object(event.payload) || typeof event.id !== 'string'
        || typeof event.kind !== 'string' || typeof event.created_at !== 'string') {
        throw new Error('Committed event is not bound to the current signed subscription.');
      }
      previous = event.sequence as number;
    }
    return data.events as DurableSubscriberEvent[];
  },
  acknowledge: async (scope: SubscriberScope, lease: DurableSubscriberLease, firstSequence: number): Promise<DurableSubscriberLease> => {
    if (!Number.isSafeInteger(firstSequence) || firstSequence <= lease.cursor) throw new Error('Only the next observed event may be ACKed.');
    const data = await post(scope, 'ack', { ...binding(scope, lease), expected_cursor: lease.cursor, next_sequence: firstSequence });
    if (!object(data) || data.acknowledged !== true) throw new Error('Durable ACK not confirmed. Do not retry automatically.');
    const updated = validLease(scope, data.lease);
    if (updated.generation !== lease.generation || updated.lease_id !== lease.lease_id
      || updated.replica_id !== lease.replica_id || updated.cursor !== firstSequence) {
      throw new Error('Durable ACK CAS mismatch. Original outcome UNKNOWN.');
    }
    return updated;
  },
  readCommittedCursor: async (scope: SubscriberScope, lastObservedLease: DurableSubscriberLease): Promise<DurableSubscriberLease> => {
    // The last ACK HTTP response may have been lost AFTER a committed cursor
    // update. This separate non-mutating owner-scoped readback does not resend
    // an ACK and must not be interpreted as a client delivery receipt.
    const data = await post(scope, 'cursor-readback', binding(scope, lastObservedLease));
    if (!object(data) || Object.keys(data).length !== 5
      || data.cursor_readback !== 'committed_database_state_only'
      || data.acknowledgement_delivered_to_client_verified !== false
      || data.safe_to_retry_unknown_ack !== false
      || data.target_effect_verified !== false) {
      throw new Error('Current committed cursor evidence unavailable; ACK remains UNKNOWN.');
    }
    const current = validLease(scope, data.lease);
    if (current.lease_id !== lastObservedLease.lease_id
      || current.replica_id !== lastObservedLease.replica_id
      || current.generation !== lastObservedLease.generation
      || current.cursor < lastObservedLease.cursor) {
      throw new Error('Persisted cursor belongs to a different or older fenced lease.');
    }
    return current;
  },
  renew: async (scope: SubscriberScope, lease: DurableSubscriberLease): Promise<DurableSubscriberLease> => {
    const data = await post(scope, 'renew', { ...binding(scope, lease), lease_seconds: 30 });
    if (!object(data)) throw new Error('Lease renewal not confirmed.');
    const updated = validLease(scope, data.lease);
    if (updated.lease_id !== lease.lease_id || updated.generation !== lease.generation
      || updated.cursor !== lease.cursor) throw new Error('Lease revision changed; renewal unconfirmed.');
    return updated;
  },
  release: async (scope: SubscriberScope, lease: DurableSubscriberLease): Promise<void> => {
    const data = await post(scope, 'release', binding(scope, lease));
    if (!object(data) || data.released !== true || data.safe_to_retry !== false) {
      throw new Error('Lease release unconfirmed.');
    }
  },
  revoke: async (scope: SubscriberScope): Promise<void> => {
    const data = await post(scope, 'revoke', { task_id: scope.taskId ?? null });
    if (!object(data) || data.revoked !== true || data.safe_to_retry !== false) {
      throw new Error('Permanent subscriber revocation unconfirmed.');
    }
  },
};
