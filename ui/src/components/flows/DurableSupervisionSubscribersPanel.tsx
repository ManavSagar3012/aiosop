import { useEffect, useRef, useState } from 'react';
import { currentOperator, subscribeOperator } from '../../services/api';
import {
  durableSubscriberApi, newDurableSubscriberId,
  type DurableSubscriberEvent, type DurableSubscriberLease, type SubscriberScope,
} from '../../services/durableSupervisionSubscribers';

type Props = { engagementId: string; taskId?: string; canControl: boolean };
const style = 'border border-outline px-2 py-1.5 text-[11px] disabled:opacity-40';

/** Manual ACK is intentional: a displayed event is not client acceptance. */
export function DurableSupervisionSubscribersPanel({ engagementId, taskId, canControl }: Props) {
  const [actor, setActor] = useState(() => currentOperator()?.sub || '');
  const [subscriberId, setSubscriberId] = useState('');
  const [lease, setLease] = useState<DurableSubscriberLease | null>(null);
  const [unknownAckLease, setUnknownAckLease] = useState<DurableSubscriberLease | null>(null);
  const [events, setEvents] = useState<DurableSubscriberEvent[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);

  useEffect(() => {
    const invalidate = () => {
      ++epoch.current;
      setLease(null);
      setUnknownAckLease(null);
      setEvents([]);
      setError('');
      setNotice('');
      setBusy(false);
      setSubscriberId('');
    };
    invalidate();
    return () => { ++epoch.current; };
  }, [engagementId, taskId]);

  useEffect(() => subscribeOperator(identity => {
    ++epoch.current;
    setActor(identity?.sub || '');
    setLease(null);
    setUnknownAckLease(null);
    setEvents([]);
    setSubscriberId('');
    setNotice('');
    setError('');
    setBusy(false);
  }), []);

  const scope: SubscriberScope = { engagementId, subscriberId, ...(taskId ? { taskId } : {}) };

  async function perform(action: 'acquire' | 'read' | 'ack' | 'cursor-readback' | 'renew' | 'release' | 'revoke') {
    if (!actor || !canControl || busy) return;
    const stamp = ++epoch.current;
    setBusy(true);
    setNotice('');
    setError('');
    try {
      if (action === 'acquire') {
        if (!crypto?.randomUUID) throw new Error('Secure replica identity unavailable.');
        const next = await durableSubscriberApi.acquire(
          scope, 'replica-' + crypto.randomUUID().replace(/-/g, '').toLowerCase(),
        );
        if (stamp === epoch.current) {
          setLease(next);
          setUnknownAckLease(null);
          setEvents([]);
          setNotice('A PostgreSQL-fenced lease was returned. No events have been acknowledged.');
        }
      } else if (action === 'revoke') {
        await durableSubscriberApi.revoke(scope);
        if (stamp === epoch.current) {
          setLease(null);
          setUnknownAckLease(null);
          setEvents([]);
          setNotice('Permanent subscription tombstone confirmed; this subscriber ID cannot be reused.');
        }
      } else if (action === 'cursor-readback') {
        if (!unknownAckLease) throw new Error('No unknown ACK lease identity to reconcile.');
        const durable = await durableSubscriberApi.readCommittedCursor(scope, unknownAckLease);
        if (stamp === epoch.current) {
          setLease(durable);
          setUnknownAckLease(null);
          setEvents(previous => previous.filter(event => event.sequence > durable.cursor));
          setNotice('Current PostgreSQL cursor read back. This is NOT a receipt that the client saw the original ACK, nor authority to replay it.');
        }
      } else {
        if (!lease) throw new Error('A current fenced lease is required.');
        if (action === 'read') {
          const committed = await durableSubscriberApi.read(scope, lease);
          if (stamp === epoch.current) {
            setEvents(committed);
            setNotice('Committed events displayed without ACK. Explicitly acknowledge only the next event.');
          }
        } else if (action === 'ack') {
          if (events.length === 0) throw new Error('Read a committed event before acknowledging.');
          const next = await durableSubscriberApi.acknowledge(scope, lease, events[0].sequence);
          if (stamp === epoch.current) {
            setLease(next);
            setUnknownAckLease(null);
            setEvents(events.slice(1));
            setNotice('Next-event cursor CAS acknowledged in PostgreSQL; no target effect was verified.');
          }
        } else if (action === 'renew') {
          const next = await durableSubscriberApi.renew(scope, lease);
          if (stamp === epoch.current) { setLease(next); setNotice('Current reader lease renewed.'); }
        } else {
          await durableSubscriberApi.release(scope, lease);
          if (stamp === epoch.current) {
            setLease(null);
            setEvents([]);
            setNotice('Reader lease released. Cursor preserved, not an execution cancellation.');
          }
        }
      }
    } catch (cause) {
      if (stamp === epoch.current) {
        // A timed-out mutating HTTP request could have committed. Do not keep
        // an optimistic local lease or automatically retry it.
        if (action === 'ack' && lease) setUnknownAckLease(lease);
        setLease(null);
        setEvents([]);
        setError((cause instanceof Error ? cause.message : 'Subscriber authority unavailable')
          + ' State UNKNOWN; refresh independent server evidence before any new action.');
      }
    } finally {
      if (stamp === epoch.current) setBusy(false);
    }
  }

  return (
    <section aria-label="Durable named supervision subscriptions" className="border border-outline-variant p-3 mb-4 text-[11px] space-y-2">
      <h3 className="font-label-caps">DURABLE NAMED EVENT READER — MANUAL POSTGRESQL ACK</h3>
      <p className="text-on-surface-variant">
        A human-scoped subscription is distinct from the live SSE feed. Events are at-least-once and may
        reappear after crashes. Reading never acknowledges delivery, authorizes tools, restarts Tasks,
        verifies physical cancellation, or establishes target-owner effects.
      </p>
      {!actor && <p role="status">Sign in with a verified human operator account.</p>}
      <div className="flex flex-wrap gap-2 items-end">
        <label className="min-w-[240px] flex-1">Subscriber ID (copy it to resume later)
          <input aria-label="Durable subscriber ID" maxLength={38} value={subscriberId}
            onChange={event => { setSubscriberId(event.target.value); setLease(null); setUnknownAckLease(null); setEvents([]); }}
            disabled={busy || !!lease || !!unknownAckLease} className="w-full border border-outline bg-background px-2 py-1.5 font-mono" />
        </label>
        <button type="button" className={style} disabled={!actor || !canControl || busy || !!lease || !!unknownAckLease}
          onClick={() => {
            try { setSubscriberId(newDurableSubscriberId()); setError(''); setNotice(''); }
            catch { setError('Secure subscriber ID generation unavailable.'); }
          }}>NEW RANDOM ID</button>
      </div>
      <p>Scope: {engagementId}{taskId ? ` · Task ${taskId}` : ' · all permitted engagement events'}</p>
      {lease && <p role="status" className="break-all">
        Lease {lease.lease_id} · generation {lease.generation} · acknowledged cursor {lease.cursor}
        {' '}· expires {new Date(lease.lease_until).toLocaleString()} · provider effect UNOBSERVED
      </p>}
      {unknownAckLease && <p role="status" className="break-all">
        Unknown ACK response for lease {unknownAckLease.lease_id}. The previous
        cursor is remembered only to request current PostgreSQL readback; no ACK
        will be retried automatically.
      </p>}
      <div className="flex flex-wrap gap-2">
        <button type="button" className={style} disabled={!actor || !canControl || busy || !!lease || !subscriberId}
          onClick={() => void perform('acquire')}>ACQUIRE FENCED LEASE</button>
        <button type="button" className={style} disabled={!lease || busy || !canControl}
          onClick={() => void perform('read')}>READ COMMITTED (NO ACK)</button>
        <button type="button" className={style} disabled={!lease || !events.length || busy || !canControl}
          onClick={() => void perform('ack')}>ACK NEXT OBSERVED EVENT</button>
        <button type="button" className={style} disabled={!unknownAckLease || busy || !canControl || !actor}
          onClick={() => void perform('cursor-readback')}>READ BACK CURSOR AFTER UNKNOWN ACK (NO RETRY)</button>
        <button type="button" className={style} disabled={!lease || busy || !canControl}
          onClick={() => void perform('renew')}>RENEW</button>
        <button type="button" className={style} disabled={!lease || busy || !canControl}
          onClick={() => void perform('release')}>RELEASE</button>
        <button type="button" className={style + ' text-error'} disabled={!actor || !canControl || busy || !subscriberId}
          onClick={() => {
            if (window.confirm('Permanently revoke this one subscriber ID? The cursor and identity cannot be reused.'))
              void perform('revoke');
          }}>PERMANENTLY REVOKE</button>
      </div>
      {events.length > 0 && <ol className="space-y-1 max-h-32 overflow-y-auto" aria-label="Unacknowledged committed events">
        {events.map(event => <li key={event.id} className="border border-outline-variant p-1">
          Event #{event.sequence} · {event.kind} · {event.created_at}
          {' '}— displayed only, not acknowledged
        </li>)}
      </ol>}
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert" className="text-error">{error}</p>}
    </section>
  );
}
