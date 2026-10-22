import { useCallback, useEffect, useRef, useState } from 'react';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  readProviderVaultOperatorStatus,
  type ProviderVaultOperatorStatus,
} from '../services/providerVaultOperatorStatus';

const UNAVAILABLE =
  'Current independent provider vault status unavailable. Host enrollment, ' +
  'shared call fencing, authorization, provider contact and credential export are unverified.';

/**
 * Optional read-only senior Administration panel. No token prop, secrets,
 * provider names, grants, send/retry buttons, or retained backend payloads.
 *
 * Prime mount:
 *   import { ProviderVaultOperatorStatusPanel } from '../components/ProviderVaultOperatorStatusPanel';
 *   <ProviderVaultOperatorStatusPanel />
 */
export function ProviderVaultOperatorStatusPanel() {
  const [senior, setSenior] = useState(
    () => currentOperator()?.role === 'senior_operator',
  );
  const [status, setStatus] = useState<ProviderVaultOperatorStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(UNAVAILABLE);
  const epoch = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const invalidate = useCallback(() => {
    epoch.current += 1;
    controller.current?.abort();
    controller.current = null;
    setBusy(false);
    setStatus(null);
    setMessage(UNAVAILABLE);
  }, []);

  const refresh = useCallback(async () => {
    if (currentOperator()?.role !== 'senior_operator') {
      invalidate();
      return;
    }
    const attempt = ++epoch.current;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    setStatus(null);
    setBusy(true);
    setMessage('Reading current senior-only provider vault metadata.');
    try {
      const result = await readProviderVaultOperatorStatus(abort.signal);
      if (epoch.current !== attempt || abort.signal.aborted
        || currentOperator()?.role !== 'senior_operator') return;
      setStatus(result);
      setMessage('Read-only PENDING observation received. No independent provider send was authorized.');
    } catch {
      if (epoch.current === attempt && !abort.signal.aborted) {
        setStatus(null);
        setMessage(UNAVAILABLE);
      }
    } finally {
      if (epoch.current === attempt) {
        controller.current = null;
        setBusy(false);
      }
    }
  }, [invalidate]);

  useEffect(() => {
    const unsubscribe = subscribeOperator(identity => {
      invalidate();
      const allowed = identity?.role === 'senior_operator';
      setSenior(allowed);
      if (allowed) void refresh();
    });
    if (currentOperator()?.role === 'senior_operator') void refresh();
    return () => {
      epoch.current += 1;
      controller.current?.abort();
      controller.current = null;
      unsubscribe();
    };
  }, [invalidate, refresh]);

  const flags = [
    { label: 'Host enrollment independently verified', value: false },
    { label: 'Shared one-use call fence enrolled', value: false },
    { label: 'Provider dispatch authorized', value: false },
    { label: 'Provider contacted', value: false },
    { label: 'Credential exported', value: false },
  ] as const;

  return (
    <section
      aria-label="Provider vault operator status"
      className="rounded-lg border border-outline-variant bg-surface p-4 space-y-3"
    >
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-on-surface">Provider vault trust status</h2>
          <p className="text-xs text-on-surface-variant">
            Senior operator · read-only GET · nonsecret pending metadata
          </p>
        </div>
        <button
          type="button"
          disabled={!senior || busy}
          aria-label="Refresh provider vault pending status"
          onClick={() => { void refresh(); }}
          className="rounded border border-outline-variant px-3 py-1.5 text-xs text-on-surface disabled:opacity-50"
        >
          {busy ? 'Reading…' : 'Refresh status'}
        </button>
      </header>
      <p className="font-semibold text-sm text-error" role="status">
        NOT READY — PENDING HOST TRUST
      </p>
      <p className="text-sm text-on-surface-variant">
        {senior ? message : 'A verified senior operator session is required to read provider vault status.'}
      </p>
      <p className="text-xs text-on-surface-variant">
        A pending status cannot grant provider access or prove that a vault key,
        runtime route, current revocation fence, or committed model usage is usable.
      </p>
      <dl className="grid gap-2 sm:grid-cols-2">
        {flags.map(flag => (
          <div key={flag.label} className="rounded border border-outline-variant/50 p-2">
            <dt className="text-xs text-on-surface-variant">{flag.label}</dt>
            <dd className="text-sm font-semibold text-error">
              {status ? (flag.value ? 'Verified' : 'Not verified') : 'Unknown — not verified'}
            </dd>
          </div>
        ))}
      </dl>
      <p className="text-xs text-on-surface-variant">
        {status
          ? (
            <>
              Current pending category: {status.code.replace(/_/g, ' ').toLowerCase()}.
              {' '}Operator next step: {status.next_action}
            </>
          )
          : 'No authenticated current pending category was accepted.'}
      </p>
    </section>
  );
}
