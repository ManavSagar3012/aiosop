import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator } from '../../services/api';
import { flowArtifactReviewsApi, type ReviewCandidate, type FlowArtifactReviewReceipt, type ReviewBoundary } from '../../services/flowArtifactReviews';
import { supervisionApi } from '../../services/supervision';

interface Props {
  flowId: string;
  engagementId: string;
  revision: number;
  authorizationId: string | null | undefined;
}

/** Artifact review is a distinct senior-human data decision, not a report or scan approval. */
export function FlowArtifactReviewPanel({ flowId, engagementId, revision, authorizationId }: Props) {
  const [files, setFiles] = useState<ReviewCandidate[]>([]);
  const [pageOffset, setPageOffset] = useState(0);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [version, setVersion] = useState<number | null>(null);
  const [policyHash, setPolicyHash] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [review, setReview] = useState<FlowArtifactReviewReceipt | null>(null);
  const [reviewChecked, setReviewChecked] = useState(false);
  const [downloadedSha, setDownloadedSha] = useState('');
  const [hasInspected, setHasInspected] = useState(false);
  const [decision, setDecision] = useState<'approve' | 'reject'>('reject');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const generation = useRef(0);

  const isSenior = currentOperator()?.role === 'senior_operator';
  const selected = files.find((file) => file.artifact_id === selectedId);

  const clearLocalReview = () => {
    setReview(null);
    setReviewChecked(false);
    setDownloadedSha('');
    setHasInspected(false);
    setDecision('reject');
    setReason('');
    setNotice('');
  };

  const reload = useCallback(async (offset = 0) => {
    const seq = ++generation.current;
    setBusy(true);
    setError('');
    setFiles([]);
    setPageOffset(offset);
    setNextOffset(null);
    setSelectedId('');
    setVersion(null);
    setPolicyHash('');
    setReview(null);
    setReviewChecked(false);
    setDownloadedSha('');
    setHasInspected(false);
    setReason('');
    setNotice('');
    try {
      if (currentOperator()?.role !== 'senior_operator' || !authorizationId) {
        throw new Error('A verified senior operator and current ROE identity are required.');
      }
      const signed = await supervisionApi.authorizationStatus(engagementId);
      if (signed.status !== 'active' || !Number.isSafeInteger(signed.version) || !signed.version
        || !/^[0-9a-f]{64}$/.test(signed.policy_sha256 ?? '')) {
        throw new Error('Current independently verified signed authorization is unavailable.');
      }
      const page = await flowArtifactReviewsApi.candidates({
        flowId, engagementId, revision, authorizationVersion: signed.version,
        authorizationId, authorizationSha256: signed.policy_sha256!,
      }, offset);
      if (generation.current !== seq) return;
      setVersion(signed.version);
      setPolicyHash(signed.policy_sha256!);
      setNextOffset(page.next_offset);
      setFiles(page.items);
    } catch (cause) {
      if (generation.current === seq) {
        setError(cause instanceof Error ? cause.message : 'Artifact review inventory could not be verified.');
      }
    } finally {
      if (generation.current === seq) setBusy(false);
    }
  }, [engagementId, flowId, revision, authorizationId]);

  useEffect(() => {
    void reload(0);
    return () => { ++generation.current; };
  }, [reload]);

  function boundary(file: ReviewCandidate): ReviewBoundary {
    if (version === null || !authorizationId || !policyHash) {
      throw new Error('Signed review boundary has not been verified.');
    }
    return {
      flowId, artifactId: file.artifact_id, artifactSha256: file.sha256,
      engagementId, revision, authorizationVersion: version,
      authorizationId, authorizationSha256: policyHash,
    };
  }

  async function latestSignedBoundary(file: ReviewCandidate): Promise<ReviewBoundary> {
    const previouslyChecked = boundary(file);
    const signed = await supervisionApi.authorizationStatus(engagementId);
    if (signed.status !== 'active' || signed.version !== previouslyChecked.authorizationVersion
      || signed.policy_sha256 !== previouslyChecked.authorizationSha256) {
      throw new Error('Signed authorization changed after review inventory. Refresh the Flow.');
    }
    const current = await flowArtifactReviewsApi.candidates(previouslyChecked, pageOffset);
    const exact = current.items.find((item) => item.artifact_id === file.artifact_id);
    if (!exact || exact.sha256 !== file.sha256 || exact.size_bytes !== file.size_bytes
      || exact.flow_revision !== revision
      || exact.authorization_version !== signed.version) {
      throw new Error('Artifact digest or Flow revision changed after inspection.');
    }
    return previouslyChecked;
  }

  async function inspect() {
    if (!selected || busy || currentOperator()?.role !== 'senior_operator') return;
    const seq = generation.current;
    setBusy(true);
    setError('');
    setNotice('');
    setReviewChecked(false);
    setHasInspected(false);
    setDownloadedSha('');
    setReview(null);
    try {
      const signed = await latestSignedBoundary(selected);
      // The shared artifact service bounds and hashes the entire immutable
      // response before the browser receives a single downloadable Blob.
      const inert = await flowArtifactReviewsApi.source(signed, selected.size_bytes);
      if (generation.current !== seq || selectedId !== selected.artifact_id) return;
      const url = URL.createObjectURL(inert);
      try {
        const link = document.createElement('a');
        link.href = url;
        link.download = selected.name;
        link.rel = 'noopener noreferrer';
        link.click();
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      setDownloadedSha(selected.sha256);
      setNotice('Inert bytes verified and downloaded. Read the exact file before you attest to its content.');
    } catch (cause) {
      if (generation.current === seq) {
        setError(cause instanceof Error ? cause.message : 'Artifact integrity verification failed.');
      }
    } finally {
      if (generation.current === seq) setBusy(false);
    }
  }

  async function lookup() {
    if (!selected || busy || currentOperator()?.role !== 'senior_operator') return;
    const seq = generation.current;
    setBusy(true);
    setError('');
    setNotice('');
    setReviewChecked(false);
    setReview(null);
    try {
      const signed = await latestSignedBoundary(selected);
      const receipt = await flowArtifactReviewsApi.inspect(signed);
      if (generation.current !== seq) return;
      setReview(receipt);
      setReviewChecked(true);
      setNotice(receipt
        ? `Previous independent review ${receipt.decision} is recorded. No second decision is permitted.`
        : 'No durable reviewer decision for this exact SHA-256 and signed Flow snapshot.');
    } catch (cause) {
      if (generation.current === seq) {
        setError(cause instanceof Error ? cause.message : 'Signed review receipt could not be read.');
      }
    } finally {
      if (generation.current === seq) setBusy(false);
    }
  }

  async function submit() {
    if (!selected || busy || review || !reviewChecked || downloadedSha !== selected.sha256
      || !hasInspected || reason.trim().length < 10 || currentOperator()?.role !== 'senior_operator') return;
    const seq = generation.current;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const signed = await latestSignedBoundary(selected);
      const existing = await flowArtifactReviewsApi.inspect(signed);
      if (existing) throw new Error('This immutable artifact already has a human review decision.');
      const record = await flowArtifactReviewsApi.decide(signed, decision, reason);
      if (generation.current !== seq) return;
      setReview(record);
      setReason('');
      setHasInspected(false);
      setNotice(`Recorded human ${record.decision} decision. This is neither a verified vulnerability nor automatic agent knowledge.`);
    } catch (cause) {
      if (generation.current === seq) {
        setError(cause instanceof Error ? cause.message : 'Human artifact review was not confirmed.');
      }
    } finally {
      if (generation.current === seq) setBusy(false);
    }
  }

  return (
    <Card title="Independent Flow artifact review — senior only">
      <p className="text-on-surface-variant text-[11px] mb-3">
        An immutable human decision about specific owner-uploaded bytes. The SHA-256 file hash,
        Flow revision and current signed ROE must all match. Approval is not target verification,
        remote execution consent, malware validation or permission to use a document as agent instructions.
      </p>
      {!isSenior ? <p className="text-on-surface-variant text-[11px]">Only a verified senior operator can inspect or create review receipts.</p> : (
        <div className="space-y-3">
          {error && <p role="alert" className="text-error text-[11px]">{error}</p>}
          {notice && <p role="status" className="text-secondary text-[11px]">{notice}</p>}
          <p className="text-on-surface-variant text-[11px]">
            Flow revision {revision} · ROE version {version ?? 'unverified'} · {files.length} immutable artifacts
          </p>
          <div className="flex flex-wrap gap-2">
            <button className="border border-outline px-3 py-2 text-[11px]" type="button" disabled={busy}
              onClick={() => void reload(0)}>REFRESH SIGNED REVIEW INVENTORY</button>
            <button className="border border-outline px-3 py-2 text-[11px]" type="button"
              disabled={busy || pageOffset <= 0} onClick={() => void reload(Math.max(0, pageOffset - 10))}>PREVIOUS 10</button>
            <button className="border border-outline px-3 py-2 text-[11px]" type="button"
              disabled={busy || nextOffset === null} onClick={() => { if (nextOffset !== null) void reload(nextOffset); }}>NEXT 10</button>
          </div>
          <label className="block text-on-surface-variant text-[11px]">SELECT EXACT ARTIFACT
            <select className="block w-full min-w-0 border border-outline bg-background px-3 py-2 mt-1 text-[11px]"
              aria-label="Artifact to review" value={selectedId} disabled={busy || !version}
              onChange={(event) => { setSelectedId(event.target.value); clearLocalReview(); }}>
              <option value="">Select an immutable file</option>
              {files.map((file) => <option key={file.artifact_id} value={file.artifact_id}>{file.name} · {file.sha256.slice(0, 12)}</option>)}
            </select>
          </label>
          {selected && (
            <div className="space-y-3 border border-outline-variant p-3 text-[11px]">
              <p className="break-words text-on-surface">File: {selected.name}</p>
              <p className="break-all font-code-sm text-on-surface-variant">Expected SHA-256: {selected.sha256}</p>
              <div className="flex flex-wrap gap-2">
                <button className="border border-outline px-3 py-2" type="button" disabled={busy}
                  onClick={() => void inspect()}>VERIFY &amp; DOWNLOAD EXACT BYTES</button>
                <button className="border border-outline px-3 py-2" type="button" disabled={busy}
                  onClick={() => void lookup()}>LOOK UP REVIEW RECEIPT</button>
              </div>
              {review && (
                <p role="status" className="text-on-surface-variant break-words">
                  Signed snapshot human decision: {review.decision} · reviewer {review.reviewer_sub} ·
                  {review.reviewed_at} · receipt {review.review_id}. Immutable; cannot repeat.
                </p>
              )}
              {!review && (
                <div className="space-y-2">
                  <p className="text-on-surface-variant">No approval action may be taken from metadata alone. Download, inspect and explicitly attest to the exact bytes.</p>
                  <label className="flex items-start gap-2 text-on-surface">
                    <input type="checkbox" checked={hasInspected} disabled={busy || downloadedSha !== selected.sha256}
                      onChange={(event) => setHasInspected(event.target.checked)} />
                    I independently inspected the downloaded file matching the full SHA-256 above.
                  </label>
                  <label className="block text-on-surface-variant">EXPLICIT HUMAN DECISION
                    <select className="block border border-outline bg-background px-3 py-2 mt-1"
                      value={decision} disabled={busy}
                      onChange={(event) => setDecision(event.target.value === 'approve' ? 'approve' : 'reject')}>
                      <option value="reject">Reject artifact content</option>
                      <option value="approve">Approve artifact content for future controlled use</option>
                    </select>
                  </label>
                  <label className="block text-on-surface-variant">REVIEW RATIONALE (10–512 CHARACTERS)
                    <textarea className="block w-full border border-outline bg-background px-3 py-2 mt-1 text-on-surface"
                      rows={2} minLength={10} maxLength={512} value={reason} disabled={busy}
                      onChange={(event) => setReason(event.target.value)} />
                  </label>
                  <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
                    disabled={busy || !reviewChecked || downloadedSha !== selected.sha256
                      || !hasInspected || reason.trim().length < 10 || reason.trim().length > 512}
                    onClick={() => void submit()}>SAVE ONE-TIME HUMAN REVIEW DECISION</button>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
