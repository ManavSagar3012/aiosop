import { useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import { candidateFindingReviews, type CandidateFindingReviewRequest } from '../../services/candidateFindingReviews';

interface Props { engagementId: string; flowId: string; revision: number }
type StringField = 'finding_id' | 'report_id' | 'original_source_task_id' | 'source_task_id'
  | 'target_task_id' | 'proof_sha256' | 'audit_sha256' | 'report_source_evidence_sha256';

const FIELDS: { key: StringField; title: string }[] = [
  { key: 'finding_id', title: 'Finding ID in exact signed report' },
  { key: 'report_id', title: 'Signed report ID' },
  { key: 'original_source_task_id', title: 'Original source Task' },
  { key: 'source_task_id', title: 'Approved source replay Task' },
  { key: 'target_task_id', title: 'Separately approved target replay Task' },
  { key: 'proof_sha256', title: 'Target assertion SHA-256' },
  { key: 'audit_sha256', title: 'Independent signed-audit SHA-256' },
  { key: 'report_source_evidence_sha256', title: 'Signed report source evidence SHA-256' },
];

const empty: CandidateFindingReviewRequest = {
  finding_id: '', report_id: '', original_source_task_id: '', source_task_id: '',
  target_task_id: '', proof_sha256: '', audit_sha256: '', report_source_evidence_sha256: '',
  expected_authorization_version: 0, expected_flow_revision: 0, expected_review_revision: 0,
  decision_status: 'independent_verification_required',
};

/** A manual signed candidate review; it never endorses an authorization flaw. */
export function CandidateFindingReviewPanel({ engagementId, flowId, revision }: Props) {
  const [value, setValue] = useState<CandidateFindingReviewRequest>(empty);
  const [authorizedVersion, setAuthorizedVersion] = useState<number | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [effectAcknowledged, setEffectAcknowledged] = useState(false);
  const [reviewSource, setReviewSource] = useState<{
    decision_id: string; decision_sha256: string; source: string;
  } | null>(null);
  const [effectSource, setEffectSource] = useState<{
    qualification_id: string; qualification_sha256: string; revision: number;
    source: string;
  } | null>(null);
  const [liveAcknowledged, setLiveAcknowledged] = useState(false);
  const [effectRevision, setEffectRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState('');
  const [verifiedReceipt, setVerifiedReceipt] = useState<{
    finding: string; report: string; source: string; id: string; digest: string; authorization: number;
  } | null>(null);
  const epoch = useRef(0);
  const senior = currentOperator()?.role === 'senior_operator';

  useEffect(() => {
    const current = ++epoch.current;
    setAuthorizedVersion(null); setResult(''); setError(''); setAcknowledged(false);
    setEffectAcknowledged(false); setReviewSource(null); setEffectRevision(0);
    setEffectSource(null); setLiveAcknowledged(false); setVerifiedReceipt(null);
    setValue({ ...empty, expected_flow_revision: revision });
    if (!senior) return;
    void supervisionApi.authorizationStatus(engagementId).then((policy) => {
      if (epoch.current !== current) return;
      if (policy.status !== 'active' || !policy.version) throw new Error('Signed ROE is not active.');
      setAuthorizedVersion(policy.version);
    }).catch((reason: unknown) => {
      if (epoch.current === current) setError(reason instanceof Error ? reason.message : 'Cannot verify current signed ROE.');
    });
    return () => { epoch.current++; };
  }, [engagementId, flowId, revision, senior]);

  async function submit(readOnly: boolean) {
    if (!senior || authorizedVersion === null || busy) return;
    if (!readOnly && !acknowledged) { setError('Explicit candidate-only acknowledgement required.'); return; }
    const current = epoch.current;
    const request = { ...value, expected_authorization_version: authorizedVersion,
      expected_flow_revision: revision };
    setBusy(true); setResult(''); setError(''); setVerifiedReceipt(null);
    try {
      const reply = readOnly
        ? await candidateFindingReviews.read(engagementId, flowId, request.finding_id, request.report_id, authorizedVersion)
        : await candidateFindingReviews.create(engagementId, flowId, request);
      if (current !== epoch.current) return;
      if (typeof reply.decision_id === 'string' && /^vfdec-[0-9a-f]{32}$/.test(reply.decision_id)
        && typeof reply.decision_sha256 === 'string' && /^[0-9a-f]{64}$/.test(reply.decision_sha256)) {
        setReviewSource({ decision_id: reply.decision_id,
          decision_sha256: reply.decision_sha256, source: JSON.stringify(request) });
      } else {
        setReviewSource(null);
      }
      setEffectAcknowledged(false); setEffectRevision(0);
      setEffectSource(null); setLiveAcknowledged(false);
      setResult(`Candidate source review: ${String(reply.decision_status ?? reply.status ?? 'pending')}. `
        + 'Vulnerability verified: NO. Senior report release approved: NO.');
    } catch (reason) {
      if (current === epoch.current) setError(reason instanceof Error ? reason.message : 'Candidate review unavailable.');
    } finally { if (current === epoch.current) setBusy(false); }
  }

  async function effect(readOnly: boolean) {
    if (!senior || busy || authorizedVersion === null) return;
    if (!readOnly && (!effectAcknowledged || !reviewSource)) {
      setError('Explicit UNKNOWN-only evidence qualification acknowledgement and a fresh signed review are required.');
      return;
    }
    const current = epoch.current;
    const request = { ...value, expected_authorization_version: authorizedVersion,
      expected_flow_revision: revision };
    if (!readOnly && reviewSource?.source !== JSON.stringify(request)) {
      setReviewSource(null);
      setError('Review source fields changed. Reverify the signed finding review before qualification.');
      return;
    }
    setBusy(true); setResult(''); setError(''); setVerifiedReceipt(null);
    try {
      const reply = readOnly
        ? await candidateFindingReviews.readEffectUnknown(
          engagementId, flowId, request.finding_id, request.report_id, authorizedVersion)
        : await candidateFindingReviews.qualifyUnknown(engagementId, flowId, {
          ...request, review_decision_id: reviewSource!.decision_id,
          review_decision_sha256: reviewSource!.decision_sha256,
          expected_qualification_revision: effectRevision,
        });
      if (epoch.current !== current) return;
      if (typeof reply.revision === 'number' && Number.isSafeInteger(reply.revision)
        && reply.revision >= 0) setEffectRevision(reply.revision);
      if (typeof reply.qualification_id === 'string' && /^teqa-[0-9a-f]{32}$/.test(reply.qualification_id)
        && typeof reply.qualification_sha256 === 'string' && /^[0-9a-f]{64}$/.test(reply.qualification_sha256)
        && typeof reply.revision === 'number' && Number.isSafeInteger(reply.revision) && reply.revision > 0) {
        setEffectSource({ qualification_id: reply.qualification_id,
          qualification_sha256: reply.qualification_sha256,
          revision: reply.revision, source: JSON.stringify(request) });
      } else setEffectSource(null);
      setLiveAcknowledged(false);
      setResult('Independent target-effect qualification: UNKNOWN. An independently deployed owner-of-record verifier is still required. Vulnerability verified: NO. Senior report release approved: NO.');
    } catch (reason) {
      if (epoch.current === current) setError(reason instanceof Error ? reason.message : 'Target-effect qualification unavailable.');
    } finally { if (epoch.current === current) setBusy(false); }
  }

  async function verifyLive() {
    if (!senior || busy || authorizedVersion === null || !effectSource || !reviewSource
      || !liveAcknowledged) return;
    const current = epoch.current;
    const request = { ...value, expected_authorization_version: authorizedVersion,
      expected_flow_revision: revision };
    if (reviewSource.source !== JSON.stringify(request)
      || effectSource.source !== JSON.stringify(request)) {
      setReviewSource(null); setEffectSource(null);
      setError('Signed report/source changed. Reverify the candidate and UNKNOWN evidence.');
      return;
    }
    setBusy(true); setError(''); setResult(''); setVerifiedReceipt(null);
    try {
      const verdict = await candidateFindingReviews.verifyIndependent(engagementId, flowId, {
        ...request, review_decision_id: reviewSource.decision_id,
        review_decision_sha256: reviewSource.decision_sha256,
        expected_qualification_revision: effectSource.revision,
        qualification_id: effectSource.qualification_id,
        qualification_sha256: effectSource.qualification_sha256,
      });
      if (current !== epoch.current) return;
      setLiveAcknowledged(false);
      setEffectSource(null);
      if (verdict.durable_readback_verified !== true) throw new Error('Durable signed verification readback unavailable.');
      setVerifiedReceipt({ finding: request.finding_id, report: request.report_id,
        source: request.report_source_evidence_sha256, id: String(verdict.verification_id),
        digest: String(verdict.verification_sha256), authorization: authorizedVersion });
      setResult(`Independent finding VERIFIED by current signed GET readback (${String(verdict.verification_id)}). Final signed report release: NOT APPROVED. Separate senior final signoff required.`);
    } catch (reason) {
      if (current === epoch.current) { setVerifiedReceipt(null); setResult('Finding status: UNKNOWN. Final signed report release: NOT APPROVED.');
        setError(reason instanceof Error ? reason.message : 'Separately operated witness unavailable; finding remains UNKNOWN.'); }
    } finally { if (current === epoch.current) setBusy(false); }
  }

  async function refreshVerification() {
    if (!senior || busy || authorizedVersion === null || !verifiedReceipt) return;
    const current = epoch.current;
    const receipt = verifiedReceipt;
    if (receipt.finding !== value.finding_id || receipt.report !== value.report_id
      || receipt.source !== value.report_source_evidence_sha256 || receipt.authorization !== authorizedVersion) {
      setVerifiedReceipt(null); setResult('Finding status: UNKNOWN. Final signed report release: NOT APPROVED.');
      setError('Signed finding fields changed; previous verification no longer applies.'); return;
    }
    setBusy(true); setResult(''); setError('');
    try {
      const verdict = await candidateFindingReviews.readIndependent(engagementId, flowId,
        receipt.finding, receipt.report, authorizedVersion, receipt.id, receipt.digest, receipt.source);
      if (current !== epoch.current) return;
      if (verdict.durable_readback_verified !== true) throw new Error('Current verification unavailable.');
      setResult(`Independent finding VERIFIED by refreshed signed GET readback (${receipt.id}). Final signed report release: NOT APPROVED.`);
    } catch (reason) {
      if (current === epoch.current) { setVerifiedReceipt(null);
        setResult('Finding status: UNKNOWN. Final signed report release: NOT APPROVED.');
        setError(reason instanceof Error ? reason.message : 'Current verification revoked or unavailable.'); }
    } finally { if (current === epoch.current) setBusy(false); }
  }

  if (!senior) return null;
  return <Card title="Independent finding source review — candidate only">
    <div className="space-y-3 text-xs">
      <p>Senior review records the exact signed report, PostgreSQL Task ancestry and independent audit digests. It does NOT establish a vulnerability, execute tools, or permit final report release.</p>
      {error && <p role="alert" className="text-error">{error}</p>}
      {result && <p role="status">{result}</p>}
      <p>Flow revision: {revision}. Signed authorization: {authorizedVersion ?? 'Unavailable'}.</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {FIELDS.map(({ key, title }) => <label key={key}>{title}
          <input className="w-full border border-outline bg-background p-2 font-mono" value={value[key]}
            onChange={event => { setVerifiedReceipt(null); setResult('');
              setValue(previous => ({ ...previous, [key]: event.target.value.trim() })); }}
            disabled={busy || authorizedVersion === null} autoComplete="off" />
        </label>)}
        <label>Current expected finding-review revision
          <input className="w-full border border-outline bg-background p-2" type="number" min={0}
            value={value.expected_review_revision} disabled={busy}
            onChange={event => { setVerifiedReceipt(null); setResult('');
              setValue(previous => ({ ...previous,
                expected_review_revision: Number(event.target.value) })); }} />
        </label>
        <label>Review outcome
          <select value={value.decision_status} disabled={busy}
            onChange={event => { setVerifiedReceipt(null); setResult('');
              setValue(previous => ({ ...previous,
                decision_status: event.target.value as CandidateFindingReviewRequest['decision_status'] })); }}>
            <option value="independent_verification_required">Independent verification required</option>
            <option value="candidate_only">Candidate only</option>
            <option value="UNKNOWN">UNKNOWN — evidence inconclusive</option>
          </select>
        </label>
      </div>
      <label className="flex items-start gap-2"><input type="checkbox" checked={acknowledged}
        onChange={event => setAcknowledged(event.target.checked)} />
        I understand this is only a signed-source candidate review; no finding is verified or released.
      </label>
      <div className="flex flex-wrap gap-2">
        <button type="button" disabled={busy || authorizedVersion === null} onClick={() => void submit(true)}>Reverify existing candidate (GET)</button>
        <button type="button" disabled={busy || !acknowledged || authorizedVersion === null}
          onClick={() => void submit(false)}>Record explicitly reviewed candidate (POST)</button>
      </div>
      <div className="border-t border-outline pt-3 space-y-2">
        <p><strong>Independent target-effect qualification (UNKNOWN only).</strong> This audits the signed candidate against durable current source receipts. It does not perform a remote request, validate a vulnerability, or authorize final report release.</p>
        <p>Current qualification revision: {effectRevision}. The operator must explicitly record or reverify this state.</p>
        <label className="flex items-start gap-2"><input type="checkbox" checked={effectAcknowledged}
          onChange={event => setEffectAcknowledged(event.target.checked)} disabled={busy} />
          I understand this records UNKNOWN only; separate target-owner validation and senior release remain necessary.
        </label>
        <div className="flex flex-wrap gap-2">
          <button type="button" disabled={busy || authorizedVersion === null}
            onClick={() => void effect(true)}>Reverify target-effect UNKNOWN (GET)</button>
          <button type="button" disabled={busy || !effectAcknowledged || !reviewSource || authorizedVersion === null}
            onClick={() => void effect(false)}>Record unresolved target-effect qualification (POST)</button>
        </div>
        <div className="border-t border-outline pt-3 space-y-2">
          <p><strong>Separately operated live owner-of-record verification.</strong> This checks pre-existing independently signed owner/access events, including a separately approved anonymous-denial Task. It cannot send a new target request. Without an independently deployed witness and current immutable approval records, the backend denies verification. Even a verified finding does not authorize final report release.</p>
          <label className="flex items-start gap-2"><input type="checkbox" checked={liveAcknowledged}
            onChange={event => setLiveAcknowledged(event.target.checked)} disabled={busy || !effectSource} />
            I approve querying the preconfigured read-only independent audit witness for this exact reviewed UNKNOWN finding; no target execution or final report release is authorized.
          </label>
          <button type="button" disabled={busy || authorizedVersion === null || !effectSource || !reviewSource || !liveAcknowledged}
            onClick={() => void verifyLive()}>Verify independent owner-of-record effects</button>
          <button type="button" disabled={busy || authorizedVersion === null || !verifiedReceipt}
            onClick={() => void refreshVerification()}>Refresh independent VERIFIED readback (GET)</button>
        </div>
      </div>
    </div>
  </Card>;
}
