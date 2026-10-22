import { useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import { preflightReviewedLibrarySource, recordReviewedLibraryCitation, readbackReviewedLibraryCitation, storeReviewedFlowOriginal, readbackStoredReviewedFlowOriginal, type PendingReviewedCitation, type RecordedReviewedCitation, type StoredReviewedFlowOriginal, type ReviewedFlowPreflightInput } from '../../services/reviewedLibraryFlowImport';

interface Props { flowId: string; engagementId: string; revision: number; authorizationId?: string }

/** Explicit human intent. The host independently verifies FOUR current roots;
 * no historical source claim or stored original grants agent/target authority. */
export function ReviewedLibraryFlowImportPanel({ flowId, engagementId, revision, authorizationId: signedRoeId }: Props) {
  const [documentId, setDocumentId] = useState('');
  const [documentRevision, setDocumentRevision] = useState('');
  const [documentSha, setDocumentSha] = useState('');
  const [taskId, setTaskId] = useState('');
  const [authorizationId, setAuthorizationId] = useState(signedRoeId ?? '');
  const [authorizationVersion, setAuthorizationVersion] = useState('');
  const [authorizationSha, setAuthorizationSha] = useState('');
  const [error, setError] = useState('');
  const [citation, setCitation] = useState<PendingReviewedCitation | null>(null);
  const [recorded, setRecorded] = useState<RecordedReviewedCitation | null>(null);
  const [storedOriginal, setStoredOriginal] = useState<StoredReviewedFlowOriginal | null>(null);
  const [inspectedScope, setInspectedScope] = useState('');
  const [uncertainScope, setUncertainScope] = useState<ReviewedFlowPreflightInput | null>(null);
  const [uncertainAction, setUncertainAction] = useState<'citation' | 'original' | null>(null);
  const [confirmImmutable, setConfirmImmutable] = useState(false);
  const [confirmInertOriginal, setConfirmInertOriginal] = useState(false);
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  const attempted = useRef(new Set<string>());

  useEffect(() => {
    ++epoch.current;
    setCitation(null);
    setRecorded(null); setStoredOriginal(null); setInspectedScope(''); setUncertainScope(null);
    setUncertainAction(null); setConfirmImmutable(false); setConfirmInertOriginal(false);
    setError('');
    setBusy(false);
    setAuthorizationId(signedRoeId ?? '');
    setAuthorizationVersion('');
    setAuthorizationSha('');
    const unsubscribe = subscribeOperator(() => {
      ++epoch.current;
      setCitation(null);
      setRecorded(null); setStoredOriginal(null); setInspectedScope(''); setUncertainScope(null);
      setUncertainAction(null); setConfirmImmutable(false); setConfirmInertOriginal(false);
      setError('');
      setBusy(false);
      setAuthorizationVersion('');
      setAuthorizationSha('');
    });
    return () => { ++epoch.current; unsubscribe(); };
  }, [flowId, engagementId, revision, signedRoeId]);

  async function readCurrentSignedRoe() {
    if (busy || !signedRoeId || !currentOperator()) return;
    const actor = currentOperator();
    const index = ++epoch.current;
    setBusy(true); setError(''); setCitation(null); setRecorded(null); setStoredOriginal(null);
    setInspectedScope(''); setConfirmImmutable(false); setConfirmInertOriginal(false);
    setAuthorizationVersion(''); setAuthorizationSha('');
    try {
      const current = await supervisionApi.authorizationStatus(engagementId);
      if (current.status !== 'active' || !Number.isSafeInteger(current.version) ||
          !current.version || current.version <= 0 ||
          typeof current.policy_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(current.policy_sha256)) {
        throw new Error('Signed current ROE not active or original SHA unavailable.');
      }
      if (index === epoch.current && currentOperator()?.sub === actor?.sub) {
        setAuthorizationVersion(String(current.version));
        setAuthorizationSha(current.policy_sha256);
      }
    } catch (cause) {
      if (index === epoch.current) setError(cause instanceof Error ? cause.message : 'Signed ROE unavailable.');
    } finally { if (index === epoch.current) setBusy(false); }
  }

  function currentInput(): ReviewedFlowPreflightInput {
    return {
      flowId, engagement_id: engagementId, expected_flow_revision: revision,
      task_id: taskId.trim(), authorization_id: authorizationId.trim(),
      authorization_version: Number(authorizationVersion),
      authorization_sha256: authorizationSha.trim().toLowerCase(),
      global_document_id: documentId.trim(), global_revision: Number(documentRevision),
      global_sha256: documentSha.trim().toLowerCase(),
    };
  }

  async function inspect() {
    if (busy) return;
    const actor = currentOperator();
    if (!actor || !['operator', 'senior_operator'].includes(actor.role)) {
      setError('Signed human operator login required.'); return;
    }
    const index = ++epoch.current;
    setCitation(null); setRecorded(null); setStoredOriginal(null); setInspectedScope('');
    setConfirmImmutable(false); setConfirmInertOriginal(false); setError(''); setBusy(true);
    try {
      const scope = currentInput();
      const result = await preflightReviewedLibrarySource(scope);
      if (index === epoch.current && currentOperator()?.sub === actor.sub) {
        setCitation(result); setInspectedScope(JSON.stringify(scope));
      }
    } catch (cause) {
      if (index === epoch.current) setError(cause instanceof Error ? cause.message : 'Reviewed preflight denied.');
    } finally { if (index === epoch.current) setBusy(false); }
  }

  async function recordCitation() {
    const actor = currentOperator();
    const input = currentInput();
    const key = JSON.stringify(input);
    if (busy || !citation || !confirmImmutable || !actor ||
        inspectedScope !== key || attempted.current.has(key)) return;
    attempted.current.add(key); // burn BEFORE first async operation
    const index = ++epoch.current;
    setBusy(true); setError(''); setRecorded(null); setStoredOriginal(null);
    setConfirmImmutable(false); setConfirmInertOriginal(false);
    try {
      // This is one irreversible attempt, never automatically retried on
      // timeout, disconnect or malformed response. No user text is copied.
      const result = await recordReviewedLibraryCitation(input);
      if (index === epoch.current && currentOperator()?.sub === actor.sub) {
        setRecorded(result); setCitation(null); setInspectedScope('');
        setUncertainScope(null); setUncertainAction(null);
      }
    } catch (cause) {
      if (index === epoch.current) {
        setUncertainScope(input);
        setUncertainAction('citation');
        setError((cause instanceof Error ? cause.message : 'Citation completion UNKNOWN.') +
          ' Do not resend. Use fresh signed citation readback below.');
      }
    } finally { if (index === epoch.current) setBusy(false); }
  }

  async function reconcileUncertainCitation() {
    const scope = uncertainScope;
    const actor = currentOperator();
    if (!scope || !actor || busy) return;
    const index = ++epoch.current;
    setBusy(true); setError(''); setRecorded(null); setStoredOriginal(null);
    try {
      const confirmed = uncertainAction === 'original'
        ? await readbackStoredReviewedFlowOriginal(scope)
        : await readbackReviewedLibraryCitation(scope);
      if (index === epoch.current && currentOperator()?.sub === actor.sub) {
        if (uncertainAction === 'original') setStoredOriginal(confirmed as StoredReviewedFlowOriginal);
        else setRecorded(confirmed as RecordedReviewedCitation);
        setCitation(null); setUncertainScope(null); setUncertainAction(null); setInspectedScope('');
      }
    } catch (cause) {
      if (index === epoch.current) setError(
        (cause instanceof Error ? cause.message : 'Readback unavailable.') +
        ' Previous commit remains UNKNOWN; no automatic or manual write retry from this screen.',
      );
    } finally { if (index === epoch.current) setBusy(false); }
  }

  async function storeInertReviewedOriginal() {
    const actor = currentOperator();
    const input = currentInput();
    const key = JSON.stringify(input);
    if (!actor || !citation || !confirmInertOriginal || busy ||
        inspectedScope !== key || attempted.current.has(key)) return;
    attempted.current.add(key); // irrevocable for this scope before any I/O
    const index = ++epoch.current;
    setBusy(true); setError(''); setStoredOriginal(null); setRecorded(null);
    setConfirmInertOriginal(false); setConfirmImmutable(false);
    try {
      const result = await storeReviewedFlowOriginal(input);
      if (index === epoch.current && currentOperator()?.sub === actor.sub) {
        setStoredOriginal(result); setCitation(null); setInspectedScope('');
        setUncertainScope(null); setUncertainAction(null);
      }
    } catch (cause) {
      if (index === epoch.current) {
        setUncertainScope(input); setUncertainAction('original');
        setError((cause instanceof Error ? cause.message : 'Reviewed original completion UNKNOWN.') +
          ' The previous original-storage transaction must NOT be resent; use signed readback.');
      }
    } finally { if (index === epoch.current) setBusy(false); }
  }

  return <Card title="User library → Flow: independent review and inert original">
    <div className="space-y-3 text-xs">
      <p>Read the exact user-owned Library original ID, revision and SHA, and current Flow/Task/signed ROE.
        Preflight is read-only. A separately confirmed write can permanently record metadata or the reviewed original
        in a Flow-local inert store. Neither write makes user text agent instructions, trusted evidence or MCP authority.</p>
      <button type="button" disabled={busy || !signedRoeId} onClick={() => void readCurrentSignedRoe()}
        className="rounded border border-outline p-2 disabled:opacity-40">
        Load current signed ROE version and policy digest (read-only)
      </button>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        <label>Original library ID<input className="w-full border p-2" value={documentId} maxLength={40} onChange={e => setDocumentId(e.target.value)} placeholder="lib-…" /></label>
        <label>Original revision<input className="w-full border p-2" value={documentRevision} type="number" min="1" onChange={e => setDocumentRevision(e.target.value)} /></label>
        <label className="md:col-span-2">Original SHA-256<input className="w-full border p-2 font-mono" value={documentSha} maxLength={64} onChange={e => setDocumentSha(e.target.value)} /></label>
        <label>Current Task ID<input className="w-full border p-2" value={taskId} maxLength={128} onChange={e => setTaskId(e.target.value)} /></label>
        <label>Signed ROE ID<input className="w-full border p-2" value={authorizationId} maxLength={128} onChange={e => setAuthorizationId(e.target.value)} readOnly={Boolean(signedRoeId)} /></label>
        <label>Signed ROE version<input className="w-full border p-2" type="number" min="1" value={authorizationVersion} readOnly={Boolean(signedRoeId)} onChange={e => setAuthorizationVersion(e.target.value)} /></label>
        <div>Flow revision <strong>{revision}</strong> (read-only current selection)</div>
        <label className="md:col-span-2">Current signed ROE SHA-256<input className="w-full border p-2 font-mono" value={authorizationSha} maxLength={64} readOnly={Boolean(signedRoeId)} onChange={e => setAuthorizationSha(e.target.value)} /></label>
      </div>
      <button type="button" onClick={() => void inspect()} disabled={busy} className="rounded border border-outline p-2">
        {busy ? 'Checking independently signed roots…' : 'Inspect pending review (no import)'}
      </button>
      {error && <p role="alert" className="text-error">{error}</p>}
      {citation && <div role="status" className="border border-outline rounded p-3">
        <p><strong>PENDING</strong> — review preflight does not create a Flow document or authorize an agent.</p>
        <p className="font-mono break-all">Source {citation.source_id} · revision {citation.original_revision} · {citation.original_sha256}</p>
        <p>Agent context approved: no. Flow document created: no. Target effects verified: no.</p>
        <label className="flex items-start gap-2 mt-2">
          <input type="checkbox" checked={confirmImmutable} onChange={e => setConfirmImmutable(e.target.checked)} />
          Explicitly record a permanent source metadata citation only, under a fresh independent review. No content import, approval or scanner execution.
        </label>
        <button type="button" className="rounded border border-outline p-2 mt-2 disabled:opacity-40"
          disabled={busy || !confirmImmutable || inspectedScope !== JSON.stringify(currentInput()) || attempted.current.has(JSON.stringify(currentInput()))}
          onClick={() => void recordCitation()}>
          Record immutable reviewed citation (single attempt; no retry)
        </button>
        <label className="flex items-start gap-2 mt-3">
          <input type="checkbox" checked={confirmInertOriginal} onChange={e => setConfirmInertOriginal(e.target.checked)} />
          I explicitly choose a permanent, immutable copy of the exact independently reviewed source original into a Flow-local
          inert storage table and its atomic signed citation. The text will NOT be loaded into any AI agent or tool.
        </label>
        <button type="button" className="rounded border border-outline p-2 mt-2 disabled:opacity-40"
          disabled={busy || !confirmInertOriginal || inspectedScope !== JSON.stringify(currentInput()) || attempted.current.has(JSON.stringify(currentInput()))}
          onClick={() => void storeInertReviewedOriginal()}>
          Store exact reviewed original as inert Flow resource (one attempt)
        </button>
      </div>}
      {uncertainScope && <div className="rounded border border-outline p-3">
        <p>One {uncertainAction === 'original' ? 'original + citation' : 'citation'} transaction was attempted;
          outcome UNKNOWN. Never resend this operation.</p>
        <button type="button" className="rounded border border-outline p-2 mt-2 disabled:opacity-40"
          disabled={busy} onClick={() => void reconcileUncertainCitation()}>
          Read committed {uncertainAction === 'original' ? 'Flow original and citation' : 'citation'} (fresh current review, no write)
        </button>
      </div>}
      {recorded && <div role="status" className="border border-outline rounded p-3">
        <p><strong>Database citation committed — agent import NOT approved.</strong></p>
        <p className="font-mono break-all">Citation {recorded.citation_id}</p>
        <p>Only original SHA/revision metadata was bound. User text was not delivered to an agent; target effects remain unverified.</p>
      </div>}
      {storedOriginal && <div role="status" className="border border-outline rounded p-3">
        <p><strong>Atomic reviewed Flow original committed — explicitly INERT, not agent-approved.</strong></p>
        <p className="font-mono break-all">Original citation {storedOriginal.citation_id}</p>
        <p>Stored {storedOriginal.original_utf8_bytes} original UTF-8 bytes under current signed Flow/Task/ROE.
          Content remains inside PostgreSQL, is not returned by this API, and cannot be auto-promoted to agent context or target evidence.</p>
      </div>}
    </div>
  </Card>;
}
