import { useEffect, useRef, useState, type FormEvent } from 'react';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  validBrowserEngagementId, validOriginalBrowserRequestId,
} from '../services/browserCurrentCustodyReadback';
import {
  BrowserHostOriginalUnverified, readBrowserHostOriginalDigests,
  type BrowserHostOriginalDigestReadback,
} from '../services/browserHostOriginalReadback';

const originalKinds = ['http_raw', 'screenshot', 'dom', 'har'] as const;

/** Senior host proof digest readback only; never an authorizing Browser action. */
export function BrowserHostOriginalPanel() {
  const [senior, setSenior] = useState(currentOperator()?.role === 'senior_operator');
  const [engagementId, setEngagementId] = useState('');
  const [requestId, setRequestId] = useState('');
  const [result, setResult] = useState<BrowserHostOriginalDigestReadback | null>(null);
  const [notice, setNotice] = useState('UNVERIFIED — no independent four-original host readback.');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const aborter = useRef<AbortController | null>(null);

  const clear = () => {
    ++generation.current;
    aborter.current?.abort();
    aborter.current = null;
    setResult(null);
    setBusy(false);
    setNotice('UNVERIFIED — independent four-original host custody not established.');
  };

  useEffect(() => {
    const unsubscribe = subscribeOperator(actor => {
      ++generation.current;
      aborter.current?.abort();
      aborter.current = null;
      setSenior(actor?.role === 'senior_operator');
      setEngagementId('');
      setRequestId('');
      setResult(null);
      setBusy(false);
      setNotice('UNVERIFIED — human operator session changed.');
    });
    return () => {
      ++generation.current;
      aborter.current?.abort();
      aborter.current = null;
      unsubscribe();
    };
  }, []);

  // The 200 response itself does not carry a signed expiry to the browser:
  // never retain the time-of-check digest in the UI as CURRENT indefinitely.
  useEffect(() => {
    if (!result) return;
    const timer = window.setTimeout(() => {
      setResult(null);
      setNotice('UNVERIFIED — prior host readback expired. Obtain new independent evidence.');
    }, 5000);
    return () => window.clearTimeout(timer);
  }, [result]);

  const allowed = senior && !busy && validBrowserEngagementId(engagementId)
    && validOriginalBrowserRequestId(requestId);

  async function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!allowed || currentOperator()?.role !== 'senior_operator') return;
    const marker = ++generation.current;
    aborter.current?.abort();
    const controller = new AbortController();
    aborter.current = controller;
    const original = currentOperator();
    setBusy(true);
    setResult(null);
    setNotice('Checking independently enrolled host originals (READ ONLY).');
    try {
      const receipt = await readBrowserHostOriginalDigests(engagementId, requestId, controller.signal);
      const current = currentOperator();
      if (marker !== generation.current || controller.signal.aborted
        || current?.role !== 'senior_operator' || current.sub !== original?.sub
        || current.exp !== original?.exp) return;
      setResult(receipt);
      setNotice('Host-reported four-original digest readback. No target effect, original bytes or release verified.');
    } catch (error) {
      if (marker !== generation.current || controller.signal.aborted) return;
      setResult(null);
      setNotice(error instanceof BrowserHostOriginalUnverified
        ? error.message
        : 'UNVERIFIED — host digest result unavailable. Do not retry unknown actions.');
    } finally {
      if (marker === generation.current) {
        aborter.current = null;
        setBusy(false);
      }
    }
  }

  return (
    <section aria-label="Browser four-original host custody digest readback"
      className="rounded-lg border border-outline-variant bg-surface p-4 space-y-3">
      <h2 className="text-lg font-semibold text-on-surface">Browser four-original host digest readback</h2>
      <p className="text-sm font-semibold text-error">NOT PRODUCTION CERTIFIED / NOT READY</p>
      <p className="text-xs text-on-surface-variant">
        Signed senior operator only. Reconcile a pre-existing host-enrolled original HTTP response,
        screenshot, DOM and HAR by SHA-256/size. This cannot navigate, scan, authorize an original
        Action, retry UNKNOWN, certify a target effect or verify physical HTTP client receipt.
      </p>
      <form className="grid gap-2" onSubmit={event => { void inspect(event); }}>
        <label className="text-xs text-on-surface-variant">Original engagement ID
          <input aria-label="Four-original Browser engagement ID" className="mt-1 w-full border border-outline-variant bg-background px-2 py-1.5 font-mono"
            value={engagementId} onChange={event => { clear(); setEngagementId(event.target.value.slice(0, 80)); }}
            maxLength={80} autoComplete="off" spellCheck={false} placeholder="eng-original" />
        </label>
        <label className="text-xs text-on-surface-variant">Original request ID
          <input aria-label="Four-original Browser request ID" className="mt-1 w-full border border-outline-variant bg-background px-2 py-1.5 font-mono"
            value={requestId} onChange={event => { clear(); setRequestId(event.target.value.slice(0, 52)); }}
            maxLength={52} autoComplete="off" spellCheck={false} placeholder="req-(48 lowercase hex)" />
        </label>
        <button type="submit" disabled={!allowed} className="border border-outline px-3 py-1.5 text-xs disabled:opacity-40">
          {busy ? 'CHECKING HOST READBACK' : 'READ FOUR ORIGINAL DIGESTS (NO EXECUTE)'}
        </button>
      </form>
      <p role="status" className="text-xs text-on-surface-variant">{notice}</p>
      {result && (
        <div aria-label="Verified-shape Browser host digest observations" className="space-y-1 text-xs">
          <p>Host enrollment SHA: {result.host_enrollment_sha256.slice(0, 16)}…</p>
          <p>Host custody claims SHA: {result.custody_claims_sha256.slice(0, 16)}…</p>
          {originalKinds.map(kind => (
            <p key={kind}>{kind}: SHA-256 {result.artifacts[kind].sha256.slice(0, 16)}… ·
              {' '}{result.artifacts[kind].size_bytes} original bytes</p>
          ))}
          <p className="text-error">Independent target effect UNVERIFIED; release denied.</p>
        </div>
      )}
    </section>
  );
}
