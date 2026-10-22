import { useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import { preflightReviewedLibrarySource, type PendingReviewedCitation } from '../../services/reviewedLibraryFlowImport';

interface Props { flowId: string; engagementId: string; revision: number; authorizationId?: string }

/** Explicit operator intent only. The server independently checks FOUR signed
 * current authorities, but still cannot import until the atomic bind exists. */
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
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);

  useEffect(() => {
    ++epoch.current;
    setCitation(null);
    setError('');
    setBusy(false);
    setAuthorizationId(signedRoeId ?? '');
    setAuthorizationVersion('');
    setAuthorizationSha('');
    const unsubscribe = subscribeOperator(() => {
      ++epoch.current;
      setCitation(null);
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
    setBusy(true); setError(''); setCitation(null);
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

  async function inspect() {
    if (busy) return;
    const actor = currentOperator();
    if (!actor || !['operator', 'senior_operator'].includes(actor.role)) {
      setError('Signed human operator login required.'); return;
    }
    const index = ++epoch.current;
    setCitation(null); setError(''); setBusy(true);
    try {
      const result = await preflightReviewedLibrarySource({
        flowId, engagement_id: engagementId, expected_flow_revision: revision,
        task_id: taskId.trim(), authorization_id: authorizationId.trim(),
        authorization_version: Number(authorizationVersion),
        authorization_sha256: authorizationSha.trim().toLowerCase(),
        global_document_id: documentId.trim(), global_revision: Number(documentRevision),
        global_sha256: documentSha.trim().toLowerCase(),
      });
      if (index === epoch.current && currentOperator()?.sub === actor.sub) setCitation(result);
    } catch (cause) {
      if (index === epoch.current) setError(cause instanceof Error ? cause.message : 'Reviewed preflight denied.');
    } finally { if (index === epoch.current) setBusy(false); }
  }

  return <Card title="User library → Flow: independent review preflight">
    <div className="space-y-3 text-xs">
      <p>Read-only. Supply the exact original ID, revision and SHA from your user-owned Library,
        plus current Flow/Task/signed ROE identities. Client-supplied fields never grant approval.
        This does not copy private text, create Flow knowledge or authorize an agent.</p>
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
        <p><strong>PENDING ONLY</strong> — independent atomic reviewed bind is not implemented.</p>
        <p className="font-mono break-all">Source {citation.source_id} · revision {citation.original_revision} · {citation.original_sha256}</p>
        <p>Agent context approved: no. Flow document created: no. Target effects verified: no.</p>
      </div>}
    </div>
  </Card>;
}
