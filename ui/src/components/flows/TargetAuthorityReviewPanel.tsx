import { useEffect, useRef, useState, type FormEvent } from 'react';

import { currentOperator, subscribeOperator } from '../../services/api';
import type { Engagement, FlowRecord } from '../../services/flows';
import { reverifyStoredTargetAssertion, submitTargetAssertion } from '../../services/targetAuthority';

interface Props {
  engagement: Engagement | null;
  flow: FlowRecord | null;
  disabled?: boolean;
}

const inputStyle = 'w-full border border-outline-variant bg-background px-3 py-2 text-[12px] text-on-surface font-code-sm';

export function TargetAuthorityReviewPanel({ engagement, flow, disabled = false }: Props) {
  const [role, setRole] = useState(() => currentOperator()?.role ?? '');
  const [original, setOriginal] = useState('');
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');
  const [claim, setClaim] = useState('');
  const [signature, setSignature] = useState('');
  const [ownershipAudit, setOwnershipAudit] = useState('');
  const [ownershipSignature, setOwnershipSignature] = useState('');
  const [accessAudit, setAccessAudit] = useState('');
  const [accessSignature, setAccessSignature] = useState('');
  const [reverifySha, setReverifySha] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [receipt, setReceipt] = useState('');
  const [sourceReview, setSourceReview] = useState('');
  const running = useRef(false);
  const contextRef = useRef('');
  contextRef.current = `${engagement?.session_id ?? ''}/${flow?.id ?? ''}/${flow?.revision ?? ''}/${role}`;

  useEffect(() => subscribeOperator(identity => {
    setRole(identity?.role ?? '');
    setConfirmed(false);
    setReceipt('');
  }), []);
  useEffect(() => {
    setOriginal(''); setSource(''); setTarget(''); setClaim(''); setSignature('');
    setOwnershipAudit(''); setOwnershipSignature(''); setAccessAudit(''); setAccessSignature('');
    setReverifySha('');
    setConfirmed(false); setError(''); setReceipt(''); setSourceReview('');
  }, [engagement?.session_id, flow?.id, flow?.revision, flow?.status]);

  const senior = role === 'senior_operator' && currentOperator()?.role === 'senior_operator';
  const active = Boolean(engagement && flow && engagement.session_id === flow.engagement_id
    && !['completed', 'halted'].includes(engagement.phase)
    && ['pending', 'running'].includes(flow.status));
  const task = /^task-[A-Za-z0-9._-]{1,58}$/;
  const auditValues = [ownershipAudit, ownershipSignature, accessAudit, accessSignature];
  const auditComplete = auditValues.every(value => value.length > 0);
  const auditEmpty = auditValues.every(value => value.length === 0);
  const auditValid = auditEmpty || (auditComplete
    && [ownershipAudit, accessAudit].every(value => new TextEncoder().encode(value).length <= 4096)
    && [ownershipSignature, accessSignature].every(value => /^[A-Za-z0-9_-]{86}$/.test(value)));
  const ready = senior && active && confirmed && !disabled && !busy
    && auditValid
    && (reverifySha.length === 0 || /^[0-9a-f]{64}$/.test(reverifySha))
    && task.test(original) && task.test(source) && task.test(target)
    && new Set([original, source, target]).size === 3
    && claim.length >= 2 && new TextEncoder().encode(claim).length <= 4096 && /^[A-Za-z0-9_-]{86}$/.test(signature);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || running.current || !engagement || !flow) return;
    running.current = true;
    setBusy(true); setError(''); setReceipt('');
    const sourceFlow = contextRef.current;
    try {
      const result = await submitTargetAssertion({
        engagementId: engagement.session_id,
        flowId: flow.id,
        originalTaskId: original,
        sourceTaskId: source,
        targetTaskId: target,
        canonicalClaims: claim,
        signature,
        ...(auditComplete ? {
          ownershipAuditJson: ownershipAudit,
          ownershipAuditSignature: ownershipSignature,
          accessAuditJson: accessAudit,
          accessAuditSignature: accessSignature,
        } : {}),
      }, reverifySha || undefined);
      if (sourceFlow !== contextRef.current || currentOperator()?.role !== 'senior_operator') return;
      setReceipt(result.proof_sha256);
      setClaim(''); setSignature(''); setConfirmed(false);
      setOwnershipAudit(''); setOwnershipSignature(''); setAccessAudit(''); setAccessSignature('');
      setReverifySha('');
    } catch (cause) {
      if (sourceFlow === contextRef.current) {
        setError(cause instanceof Error ? cause.message : 'Target-owned proof admission unavailable.');
      }
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  async function recheckStored() {
    if (!senior || !active || disabled || busy || running.current || !engagement || !flow
      || !/^[0-9a-f]{64}$/.test(reverifySha)) return;
    running.current = true;
    setBusy(true); setError(''); setReceipt(''); setSourceReview('');
    const selected = contextRef.current;
    try {
      const result = await reverifyStoredTargetAssertion(engagement.session_id, flow.id, reverifySha);
      if (selected !== contextRef.current || currentOperator()?.role !== 'senior_operator') return;
      setReceipt(result.proof_sha256);
      setSourceReview(result.durable_source_review_status ?? 'UNKNOWN');
    } catch (cause) {
      if (selected === contextRef.current) setError(cause instanceof Error ? cause.message : 'Existing immutable source unavailable.');
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  return (
    <section className="space-y-2 border-t border-outline-variant pt-3" aria-label="Independent target-owned assertion review" data-testid="target-authority-review">
      <p className="font-label-caps text-on-surface">Target-owned detached evidence · candidate only</p>
      <p>Senior-only review of an independently configured target-owned signature. The target must separately provide exact ownership and response provenance. No target request or model call is made here. Provider testimony is insufficient. Even an accepted signature does not verify a finding or approve a report.</p>
      <form className="space-y-2" onSubmit={(event) => void submit(event)}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <label>ORIGINAL SOURCE TASK<input className={inputStyle} aria-label="Authority original source task" value={original} onChange={event => setOriginal(event.target.value)} disabled={busy || !senior} /></label>
          <label>APPROVED SOURCE GET TASK<input className={inputStyle} aria-label="Authority source task" value={source} onChange={event => setSource(event.target.value)} disabled={busy || !senior} /></label>
          <label>APPROVED TARGET GET TASK<input className={inputStyle} aria-label="Authority target task" value={target} onChange={event => setTarget(event.target.value)} disabled={busy || !senior} /></label>
        </div>
        <label className="block">CANONICAL TARGET-SIGNED ASSERTION (NO RESPONSE BODIES)
          <textarea className={inputStyle} rows={3} value={claim} aria-label="Canonical target assertion" onChange={event => setClaim(event.target.value)} disabled={busy || !senior} />
        </label>
        <label className="block">DETACHED ED25519 SIGNATURE
          <input className={inputStyle} value={signature} aria-label="Target authority signature" onChange={event => setSignature(event.target.value)} disabled={busy || !senior} />
        </label>
        <details className="space-y-2 border border-outline-variant p-2">
          <summary>Optional independent ownership and access audit pair (both required together)</summary>
          <p>Use only separately authenticated target-owned canonical records. Their accepted digests remain candidate evidence, not verified findings.</p>
          <label className="block">OWNERSHIP CANONICAL AUDIT<textarea className={inputStyle} rows={2} value={ownershipAudit} aria-label="Independent ownership audit" onChange={event => setOwnershipAudit(event.target.value)} disabled={busy || !senior} /></label>
          <label className="block">OWNERSHIP AUDIT SIGNATURE<input className={inputStyle} value={ownershipSignature} aria-label="Ownership audit signature" onChange={event => setOwnershipSignature(event.target.value)} disabled={busy || !senior} /></label>
          <label className="block">ACCESS CANONICAL AUDIT<textarea className={inputStyle} rows={2} value={accessAudit} aria-label="Independent access audit" onChange={event => setAccessAudit(event.target.value)} disabled={busy || !senior} /></label>
          <label className="block">ACCESS AUDIT SIGNATURE<input className={inputStyle} value={accessSignature} aria-label="Access audit signature" onChange={event => setAccessSignature(event.target.value)} disabled={busy || !senior} /></label>
        </details>
        <label className="block">EXISTING IMMUTABLE PROOF SHA-256 (OPTIONAL — REVERIFY WITHOUT NEW NONCE)
          <input className={inputStyle} aria-label="Reverify original proof digest" value={reverifySha} onChange={event => setReverifySha(event.target.value)} disabled={busy || !senior} />
        </label>
        <button type="button" className="border border-outline px-3 py-2 text-[11px] font-label-caps disabled:opacity-40"
          disabled={!senior || !active || disabled || busy || !/^[0-9a-f]{64}$/.test(reverifySha)}
          onClick={() => void recheckStored()}>
          RECHECK ARCHIVED SIGNED SOURCE (NO REUPLOAD)
        </button>
        <label className="flex items-start gap-2"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={!active || busy || !senior} />
          Confirm these exact approved Task IDs and separately supplied target signature. This records a non-promotable assertion only.
        </label>
        <button type="submit" className="border border-outline px-3 py-2 text-[11px] font-label-caps disabled:opacity-40" disabled={!ready}>{busy ? 'VERIFYING SOURCE...' : reverifySha ? 'REVERIFY EXISTING SIGNED CANDIDATE' : 'RECORD TARGET-OWNED ASSERTION (CANDIDATE ONLY)'}</button>
      </form>
      {(!active || !senior) && <p role="status">Select an active Flow with an authenticated senior operator to review target-owned evidence.</p>}
      {error && <p role="alert" className="text-error">{error}</p>}
      {receipt && <p role="status">Immutable target-signer assertion received: {receipt.slice(0, 16)}… Finding verified: NO. Report release approved: NO.</p>}
      {sourceReview && <p role="status">Durable source inspection: {sourceReview}. Candidate evidence only; no finding or senior report release authorized.</p>}
    </section>
  );
}
