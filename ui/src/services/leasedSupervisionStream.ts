/** Explicit human-authenticated 0040 stream. SSE bytes are never an ACK. */
import { API_BASE, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin } from './api';
import type { DurableSubscriberEvent, DurableSubscriberLease, SubscriberScope } from './durableSupervisionSubscribers';

const ENG = /^eng-[A-Za-z0-9._-]{1,60}$/;
const SUB = /^subscr-[0-9a-f]{32}$/;
const TASK = /^task-[A-Za-z0-9._:-]{1,59}$/;
const REPLICA = /^replica-[A-Za-z0-9._-]{1,90}$/;
const LEASE = /^lease-[0-9a-f]{32}$/;
const MAX_BYTES = 256 * 1024;

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function readLeasedSupervisionStream(
  scope: SubscriberScope, lease: DurableSubscriberLease, signal?: AbortSignal,
): Promise<DurableSubscriberEvent[]> {
  if (!ENG.test(scope.engagementId) || !SUB.test(scope.subscriberId)
    || (scope.taskId !== undefined && !TASK.test(scope.taskId))
    || lease.engagement_id !== scope.engagementId || lease.subscriber_id !== scope.subscriberId
    || !REPLICA.test(lease.replica_id) || !LEASE.test(lease.lease_id)
    || !Number.isSafeInteger(lease.generation) || lease.generation < 1
    || !Number.isSafeInteger(lease.cursor) || lease.cursor < 0
    || lease.delivery_semantics !== 'at_least_once'
    || lease.provider_effect !== 'unobserved'
    || !Number.isFinite(Date.parse(lease.lease_until)) || Date.parse(lease.lease_until) <= Date.now()
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current secure PostgreSQL-fenced subscriber lease required.');
  }
  const operator = currentOperator();
  const token = getRuntimeToken();
  if (!operator || !token || !['operator', 'senior_operator'].includes(operator.role)) {
    throw new Error('Current verified human operator required for leased events.');
  }
  const samePrincipal = () => getRuntimeToken() === token
    && currentOperator()?.sub === operator.sub && currentOperator()?.role === operator.role;
  const response = await fetch(
    `${API_BASE}/supervision/engagements/${encodeURIComponent(scope.engagementId)}`
      + `/subscriptions/${encodeURIComponent(scope.subscriberId)}/leased-stream`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify({ replica_id: lease.replica_id, lease_id: lease.lease_id,
        generation: lease.generation, cursor: lease.cursor, task_id: scope.taskId ?? null,
        limit: 20, wait_seconds: 5 }),
      cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal,
    },
  );
  if (!samePrincipal() || signal?.aborted) throw new Error('Operator changed; streamed events discarded.');
  if (!response.ok || !/^text\/event-stream(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')?.trim() ?? '')) {
    throw new Error('Signed lease stream unavailable; no event acknowledged.');
  }
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BYTES)) {
    throw new Error('Leased event stream exceeded bounds.');
  }
  if (!response.body) throw new Error('Leased event stream body missing.');
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let buffer = '';
  let consumed = 0;
  let previous = lease.cursor;
  let completed = false;
  let sawTerminator = false;
  const events: DurableSubscriberEvent[] = [];
  const accept = (frame: string) => {
    const lines = frame.split('\n');
    if (frame === 'event: stream_complete\ndata: {"acknowledged":false,"client_receipt_verified":false}') {
      if (sawTerminator) throw new Error('Duplicate leased stream completion.');
      sawTerminator = true;
      return;
    }
    if (sawTerminator) throw new Error('Committed event after stream completion.');
    if (lines.length !== 3 || !lines[0].startsWith('id: ') || lines[1] !== 'event: supervision'
      || !lines[2].startsWith('data: ')) throw new Error('Untrusted leased event frame.');
    const sequence = lines[0].slice(4);
    if (!/^[1-9]\d{0,18}$/.test(sequence) || !Number.isSafeInteger(Number(sequence))) {
      throw new Error('Untrusted leased event sequence.');
    }
    const row: unknown = JSON.parse(lines[2].slice(6));
    if (!object(row) || row.sequence !== Number(sequence) || Number(sequence) <= previous
      || row.engagement_id !== scope.engagementId
      || (scope.taskId !== undefined && row.task_id !== scope.taskId)
      || typeof row.id !== 'string' || typeof row.kind !== 'string'
      || typeof row.actor_id !== 'string' || typeof row.created_at !== 'string'
      || !object(row.payload) || events.length >= 20) {
      throw new Error('Leased event provenance or order changed.');
    }
    previous = Number(sequence);
    events.push(row as DurableSubscriberEvent);
  };
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (!samePrincipal() || signal?.aborted) throw new Error('Operator changed; streamed events discarded.');
      if (done) { completed = true; break; }
      consumed += value.byteLength;
      if (consumed > MAX_BYTES) throw new Error('Leased event stream exceeded bounds.');
      buffer += decoder.decode(value, { stream: true });
      while (buffer.includes('\n\n')) {
        const at = buffer.indexOf('\n\n');
        const frame = buffer.slice(0, at);
        buffer = buffer.slice(at + 2);
        if (frame.length > 8250) throw new Error('Oversized leased event frame.');
        accept(frame);
      }
      if (buffer.length > 8250) throw new Error('Incomplete or oversized leased event frame.');
    }
    buffer += decoder.decode();
    if (buffer.length !== 0) throw new Error('Incomplete leased event stream.');
    if (!sawTerminator) throw new Error('Leased event stream ended without current completion; original outcome UNKNOWN.');
    if (!samePrincipal()) throw new Error('Operator changed; streamed events discarded.');
    return events;
  } finally {
    if (!completed) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
