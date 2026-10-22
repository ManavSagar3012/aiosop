import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  BrowserCustodyUnverifiedError,
  readBrowserCurrentCustodyReadback,
  validBrowserEngagementId,
  validOriginalBrowserRequestId,
  type BrowserCustodyVerified,
} from '../services/browserCurrentCustodyReadback';

interface BrowserCurrentCustodyPanelProps {
  /** Pre-enrolled host custodian Ed25519 public keys, supplied outside Browser MCP. */
  trustedCustodyPublicKeys?: Readonly<Record<string, string>>;
  initialEngagementId?: string;
  initialRequestId?: string;
}

/**
 * Optional, manual senior-only READ ONLY host custody operator panel.
 * Mount in an authorized operator page, with separately provisioned public
 * keys; this component never accepts an artifact URL, path, proof or file.
 */
export function BrowserCurrentCustodyPanel({
  trustedCustodyPublicKeys,
  initialEngagementId = '',
  initialRequestId = '',
}: BrowserCurrentCustodyPanelProps) {
  const [senior, setSenior] = useState(
    () => currentOperator()?.role === 'senior_operator',
  );
  const [engagementId, setEngagementId] = useState(initialEngagementId.slice(0, 80));
  const [requestId, setRequestId] = useState(initialRequestId.slice(0, 52));
  const [reading, setReading] = useState(false);
  const [verified, setVerified] = useState<BrowserCustodyVerified | null>(null);
  const [notice, setNotice] = useState(
    'UNVERIFIED — no fresh independently signed original Browser custody readback.',
  );
  const epoch = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const hasIndependentRoots = !!trustedCustodyPublicKeys
    && Object.keys(trustedCustodyPublicKeys).length > 0;

  const clear = useCallback(() => {
    epoch.current += 1;
    controller.current?.abort();
    controller.current = null;
    setReading(false);
    setVerified(null);
    setNotice('UNVERIFIED — current host original-byte custody has not been confirmed.');
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeOperator(identity => {
      clear();
      setSenior(identity?.role === 'senior_operator');
    });
    return () => {
      epoch.current += 1;
      controller.current?.abort();
      controller.current = null;
      unsubscribe();
    };
  }, [clear]);

  // A key-pin change invalidates any previously displayed signed observation.
  useEffect(() => { clear(); }, [clear, trustedCustodyPublicKeys]);

  // A CURRENT custody witness lives for at most five seconds. Expiration
  // clears the displayed positive observation even without user interaction.
  useEffect(() => {
    if (!verified) return;
    const remaining = verified.expires_at * 1000 - Date.now();
    if (remaining <= 0) { clear(); return; }
    const expiry = window.setTimeout(clear, remaining);
    const discardIfExpired = () => {
      if (Date.now() >= verified.expires_at * 1000) clear();
    };
    window.addEventListener('focus', discardIfExpired);
    document.addEventListener('visibilitychange', discardIfExpired);
    return () => {
      window.clearTimeout(expiry);
      window.removeEventListener('focus', discardIfExpired);
      document.removeEventListener('visibilitychange', discardIfExpired);
    };
  }, [clear, verified]);

  const requestAllowed = senior && hasIndependentRoots && !reading
    && validBrowserEngagementId(engagementId)
    && validOriginalBrowserRequestId(requestId);

  async function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requestAllowed || !trustedCustodyPublicKeys
      || currentOperator()?.role !== 'senior_operator') {
      clear();
      return;
    }
    const generation = ++epoch.current;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    const identity = currentOperator();
    const tuple = { engagementId, requestId };
    setReading(true);
    setVerified(null);
    setNotice('Reading signed original-host custody (bounded READ ONLY POST).');
    try {
      const result = await readBrowserCurrentCustodyReadback(
        tuple.engagementId, tuple.requestId, trustedCustodyPublicKeys, abort.signal,
      );
      const live = currentOperator();
      if (generation !== epoch.current || abort.signal.aborted
        || !live || live.role !== 'senior_operator' || live.sub !== identity?.sub
        || live.exp !== identity?.exp) return;
      setVerified(result);
      setNotice('Original screenshot, DOM and HAR SHA metadata matched a fresh host custody witness. Target effects and release remain UNVERIFIED.');
    } catch (error) {
      if (generation !== epoch.current || abort.signal.aborted) return;
      setVerified(null);
      const reason = error instanceof BrowserCustodyUnverifiedError
        ? error.reason : 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED';
      setNotice(`UNVERIFIED — ${reason}. No original image/DOM content, target effect, retry or release verified.`);
    } finally {
      if (generation === epoch.current) {
        controller.current = null;
        setReading(false);
      }
    }
  }

  return (
    <section
      aria-label="Browser current original custody readback"
      className="rounded-lg border border-outline-variant bg-surface p-4 space-y-3"
    >
      <header className="space-y-1">
        <h2 className="text-lg font-semibold text-on-surface">Browser original-byte custody</h2>
        <p className="text-xs text-on-surface-variant">
          Senior operator only · READ ONLY reconciliation · original screenshot / DOM / HAR SHA
        </p>
      </header>
      <p className="font-semibold text-sm text-error">NOT PRODUCTION CERTIFIED / NOT READY</p>
      <p className="text-sm text-on-surface-variant">
        This reads existing, host-held Browser evidence for one original request.
        It cannot navigate, rescan, prove target effects, automatically retry an UNKNOWN
        action or certify a release. No screenshot, DOM, HAR bytes or paths are opened here.
      </p>
      <form onSubmit={event => { void inspect(event); }} className="grid gap-3">
        <label className="block text-sm text-on-surface-variant">
          Original engagement ID
          <input
            aria-label="Original Browser engagement ID"
            className="mt-1 w-full rounded border border-outline-variant bg-background px-2 py-1.5 font-mono text-xs"
            type="text"
            maxLength={80}
            autoComplete="off"
            spellCheck={false}
            value={engagementId}
            onChange={event => { clear(); setEngagementId(event.target.value.slice(0, 80)); }}
            placeholder="eng-original"
          />
        </label>
        <label className="block text-sm text-on-surface-variant">
          Original dispatch request ID
          <input
            aria-label="Original Browser request ID"
            className="mt-1 w-full rounded border border-outline-variant bg-background px-2 py-1.5 font-mono text-xs"
            type="text"
            maxLength={52}
            autoComplete="off"
            spellCheck={false}
            value={requestId}
            onChange={event => { clear(); setRequestId(event.target.value.slice(0, 52)); }}
            placeholder="req-(48 lowercase hex)"
          />
        </label>
        <button
          type="submit"
          aria-label="Read original Browser custody"
          disabled={!requestAllowed}
          className="w-fit rounded border border-outline-variant px-3 py-2 text-xs text-on-surface disabled:opacity-50"
        >
          {reading ? 'Reading current host evidence…' : 'READ ORIGINAL CUSTODY'}
        </button>
      </form>
      {!senior && <p className="text-xs text-error">Verified senior operator bearer session required.</p>}
      {!hasIndependentRoots && <p className="text-xs text-error">
        INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED — a separate trusted host Ed25519 public-key pin is required.
      </p>}
      <p role="status" aria-live="polite" className="text-sm text-on-surface-variant">{notice}</p>
      {verified && verified.expires_at * 1000 > Date.now() && (
        <div className="space-y-2 border-t border-outline-variant pt-3" aria-label="Signed host original-custody metadata">
          <p className="font-semibold text-sm text-on-surface">
            CURRENT ORIGINAL CUSTODY VERIFIED — original bytes and independent host signature only
          </p>
          <p className="text-xs text-on-surface-variant">
            One fresh signed host custody proof matched this exact request.
            Independent target effect: NOT VERIFIED · Automatic retry: NOT AUTHORIZED ·
            Production release: NOT CERTIFIED.
          </p>
          <p className="text-xs text-on-surface-variant">
            Observation expires at {new Date(verified.expires_at * 1000).toLocaleTimeString()}.
            Readback is not cached as a current authorization.
          </p>
          <div className="grid gap-2">
            {(['screenshot', 'dom', 'har'] as const).map(kind => (
              <p key={kind} className="text-xs font-mono break-all text-on-surface-variant">
                {kind.toUpperCase()}: {verified.artifacts[kind].size_bytes} original bytes;
                {' '}SHA-256 {verified.artifacts[kind].sha256}
              </p>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
