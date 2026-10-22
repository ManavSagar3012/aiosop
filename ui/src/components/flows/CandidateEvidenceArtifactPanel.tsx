import { useEffect, useRef, useState } from 'react';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import {
  associateCompletedSignedNavigationCandidate,
  readCandidateEvidenceArtifacts, signedNavigationAssociationAlreadyAttempted,
  validCandidateFindingId, validSignedNavigationSourceTaskId,
  type CandidateEvidenceReadback,
} from '../../services/candidateEvidenceArtifacts';
import { Card } from '../shared/Card';

interface Props {
  engagementId: string;
  flowId: string;
  revision: number;
  flowStatus: string;
}

/** Signed/Flow-fenced digest references, deliberately not a verification panel. */
export function CandidateEvidenceArtifactPanel({ engagementId, flowId, revision, flowStatus }: Props) {
  const [operator, setOperator] = useState(() => currentOperator());
  const [findingId, setFindingId] = useState('');
  const [sourceTaskId, setSourceTaskId] = useState('');
  const [associateConfirmed, setAssociateConfirmed] = useState(false);
  const [associationOutcome, setAssociationOutcome] = useState('');
  const [readback, setReadback] = useState<CandidateEvidenceReadback | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  const associationInFlight = useRef(false);
  // Deliberately retain attempted tuples after a 503/lost reply. Blindly
  // repeating the same signed navigation association may duplicate a write.
  // Manual GET can recover the record, but never triggers or unlocks a POST.
  const attemptedAssociations = useRef(new Set<string>());
  const senior = operator?.role === 'senior_operator'
    && currentOperator()?.sub === operator.sub
    && currentOperator()?.role === 'senior_operator';
  const activeFlow = flowStatus === 'pending' || flowStatus === 'running';

  useEffect(() => {
    ++epoch.current;
    setFindingId('');
    setSourceTaskId('');
    setAssociateConfirmed(false);
    setAssociationOutcome('');
    setReadback(null);
    setError('');
    setBusy(false);
    return () => { ++epoch.current; };
  }, [engagementId, flowId, revision, flowStatus]);

  useEffect(() => subscribeOperator(identity => {
    ++epoch.current;
    setReadback(null);
    setError('');
    setBusy(false);
    setAssociateConfirmed(false);
    setAssociationOutcome('');
    setOperator(identity);
  }), []);

  async function inspect() {
    if (busy || associationInFlight.current || !senior || !activeFlow || !validCandidateFindingId(findingId)
      || !Number.isSafeInteger(revision) || revision < 0 || !operator?.sub) return;
    const requestId = ++epoch.current;
    const reviewedFinding = findingId;
    const reviewer = operator.sub;
    setReadback(null);
    setError('');
    setBusy(true);
    try {
      const policy = await supervisionApi.authorizationStatus(engagementId);
      if (policy.status !== 'active' || !Number.isSafeInteger(policy.version)
        || policy.version === null || policy.version < 1) {
        throw new Error('Current signed authorization unavailable.');
      }
      const result = await readCandidateEvidenceArtifacts(
        engagementId, reviewedFinding, flowId, revision, policy.version,
      );
      // Fail closed if the signer changed while the candidate GET was in flight.
      const checked = await supervisionApi.authorizationStatus(engagementId);
      if (checked.status !== 'active' || checked.version !== policy.version) {
        throw new Error('Signed authorization changed during evidence readback.');
      }
      if (requestId !== epoch.current || currentOperator()?.sub !== reviewer
        || currentOperator()?.role !== 'senior_operator') return;
      setReadback(result);
    } catch {
      if (requestId === epoch.current) {
        setReadback(null);
        // Never show an untrusted error body, URL, header or private witness.
        setError('Current signed candidate evidence unavailable, stale or rejected. No finding verified or report released.');
      }
    } finally {
      if (requestId === epoch.current) setBusy(false);
    }
  }

  function associationKey(): string {
    // Context is a bounded in-memory key, never a request to a new browser.
    return [engagementId, flowId, String(revision), findingId, sourceTaskId].join('|');
  }

  async function associateExistingNavigation() {
    if (busy || associationInFlight.current || !senior || !activeFlow
      || !validCandidateFindingId(findingId) || !validSignedNavigationSourceTaskId(sourceTaskId)
      || !associateConfirmed || !Number.isSafeInteger(revision) || revision < 0
      || !operator?.sub) return;
    const tuple = associationKey();
    if (attemptedAssociations.current.has(tuple) || signedNavigationAssociationAlreadyAttempted(
      engagementId, findingId, flowId, sourceTaskId,
    )) {
      setAssociationOutcome('UNKNOWN or already associated. Use separate manual GET readback; do NOT repeat this POST.');
      return;
    }
    if (!window.confirm(
      `Associate an ALREADY COMPLETED, human-approved signed navigation with candidate finding ${findingId}?\n`
      + `Source Task: ${sourceTaskId}\nFlow: ${flowId} (revision ${revision}).\n`
      + 'This writes inert candidate metadata only: NO browser call, no vulnerability verification, no report release. '
      + 'An unknown POST outcome MUST be checked with manual GET, NOT retried.'
    )) return;

    associationInFlight.current = true;
    const requestId = ++epoch.current;
    const currentFinding = findingId;
    const currentSource = sourceTaskId;
    const reviewer = operator.sub;
    let dispatched = false;
    setReadback(null);
    setError('');
    setAssociationOutcome('');
    setBusy(true);
    try {
      const policy = await supervisionApi.authorizationStatus(engagementId);
      if (policy.status !== 'active' || !Number.isSafeInteger(policy.version)
        || policy.version === null || policy.version < 1) {
        throw new Error('Current signed authorization unavailable before association.');
      }
      if (requestId !== epoch.current || currentOperator()?.sub !== reviewer
        || currentOperator()?.role !== 'senior_operator') return;

      // Fencing happens BEFORE the only POST. Even a lost HTTP response or
      // malformed receipt can mean PostgreSQL committed successfully.
      attemptedAssociations.current.add(tuple);
      dispatched = true;
      const recorded = await associateCompletedSignedNavigationCandidate({
        engagementId, findingId: currentFinding, flowId, sourceTaskId: currentSource,
        expectedFlowRevision: revision,
        expectedAuthorizationVersion: policy.version,
        explicitHumanConfirmation: true,
      });
      if (requestId !== epoch.current || currentOperator()?.sub !== reviewer
        || currentOperator()?.role !== 'senior_operator') return;

      // A POST acknowledgement is not independent persistence evidence.
      // Demand current signed GET readback, with the exact source and leaf.
      const result = await readCandidateEvidenceArtifacts(
        engagementId, currentFinding, flowId, revision, policy.version,
      );
      const checked = await supervisionApi.authorizationStatus(engagementId);
      if (checked.status !== 'active' || checked.version !== policy.version
        || !result.artifacts.some(artifact => artifact.artifact_id === recorded.artifact_id
          && artifact.merkle_leaf_sha256 === recorded.merkle_leaf_sha256
          && artifact.source_task_id === currentSource)) {
        throw new Error('Current signed readback does not corroborate the candidate metadata association.');
      }
      if (requestId !== epoch.current || currentOperator()?.sub !== reviewer
        || currentOperator()?.role !== 'senior_operator') return;
      setReadback(result);
      setAssociationOutcome('Candidate association matched independent GET readback. CANDIDATE_UNVERIFIED; no target effect or report release verified.');
      setAssociateConfirmed(false);
    } catch {
      if (requestId === epoch.current) {
        setReadback(null);
        setAssociationOutcome(dispatched
          ? 'UNKNOWN: POST may have committed. Manually select READ CANDIDATE EVIDENCE (GET ONLY). NO automatic or repeated POST for this tuple.'
          : 'BLOCKED before association: current signed authorization unavailable. No POST was attempted.');
      }
    } finally {
      associationInFlight.current = false;
      if (requestId === epoch.current) setBusy(false);
    }
  }

  return <Card title="Signed candidate evidence — digest-only operator readback">
    <div className="space-y-3 text-xs" aria-label="Candidate evidence artifact readback">
      <p className="text-on-surface-variant">
        Read-only PostgreSQL candidate artifact references for this selected signed Flow.
        Merkle leaf hashes identify records; they do NOT verify a vulnerability, independently
        prove target effects, authorize execution, or approve signed report release.
        Private URLs, headers, responses, replay recipes and witness bodies are never displayed.
      </p>
      <p>Selected Flow: {flowId} · revision {revision} · state {flowStatus}.</p>
      <label className="block text-on-surface-variant">CANDIDATE FINDING ID (bounded, explicit)
        <input aria-label="Candidate finding ID" className="w-full border border-outline bg-background p-2 mt-1 font-mono"
          value={findingId} maxLength={128} autoComplete="off"
          onChange={event => {
            ++epoch.current;
            setFindingId(event.target.value.slice(0, 128));
            setAssociateConfirmed(false); setAssociationOutcome('');
            setReadback(null); setError(''); setBusy(false);
          }} placeholder="finding-candidate-1" />
      </label>
      <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
        disabled={!senior || !activeFlow || busy || !validCandidateFindingId(findingId)
          || !Number.isSafeInteger(revision) || revision < 0}
        onClick={() => void inspect()}>
        {busy ? 'READING CURRENT SIGNED CANDIDATE…' : 'READ CANDIDATE EVIDENCE (GET ONLY)'}
      </button>
      {!senior && <p>Verified senior operator authentication required for this readback.</p>}
      {!activeFlow && <p>Current signed Flow must be pending or running. No stale evidence read is allowed.</p>}
      {error && <p role="alert" className="text-error">{error}</p>}
      <div className="border-t border-outline-variant pt-3 space-y-2">
        <p><strong>SEPARATE SENIOR ACTION — ASSOCIATE EXISTING SIGNED NAVIGATION CANDIDATE.</strong>
          This only records redacted metadata from an already completed, human-approved signed GET Task.
          The server independently checks persisted Task approval, provider event, signed Flow and authorization.
          No browser, target request, exploit verification, or signed report release is triggered.</p>
        <label className="block text-on-surface-variant">EXISTING SIGNED NAVIGATION SOURCE TASK ID
          <input aria-label="Existing signed navigation source Task ID"
            className="w-full border border-outline bg-background p-2 mt-1 font-mono"
            value={sourceTaskId} maxLength={96} autoComplete="off"
            onChange={event => {
              ++epoch.current;
              setSourceTaskId(event.target.value.slice(0, 96));
              setAssociateConfirmed(false); setAssociationOutcome('');
              setReadback(null); setError(''); setBusy(false);
            }} placeholder="task-signed-navigation-1" />
        </label>
        <label className="flex gap-2 items-start">
          <input type="checkbox" checked={associateConfirmed} disabled={!senior || !activeFlow || busy}
            onChange={event => setAssociateConfirmed(event.target.checked)} />
          I explicitly authorize associating only this ALREADY COMPLETED, human-approved signed navigation
          with the candidate finding; evidence remains unverified and a lost response must NOT be retried.
        </label>
        <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
          disabled={!senior || !activeFlow || busy || associationInFlight.current || !associateConfirmed
            || !validCandidateFindingId(findingId) || !validSignedNavigationSourceTaskId(sourceTaskId)
            || !Number.isSafeInteger(revision) || revision < 0
            || attemptedAssociations.current.has(associationKey())
            || signedNavigationAssociationAlreadyAttempted(engagementId, findingId, flowId, sourceTaskId)}
          onClick={() => void associateExistingNavigation()}>
          ASSOCIATE EXISTING SIGNED NAVIGATION — HUMAN CONFIRMATION REQUIRED
        </button>
        {associationOutcome && <p role="status" className="text-on-surface-variant">{associationOutcome}</p>}
      </div>
      {readback && <div role="status" className="border-t border-outline pt-3 space-y-2">
        <p><strong>CANDIDATE_UNVERIFIED ONLY</strong> · finding verified: NO ·
          independent target effect verified: NO · final report release: NOT APPROVED BY THIS READ.</p>
        <p className="font-mono break-all">Finding: {readback.finding_id} · Signed authorization version: {readback.authorization_version} ·
          Flow revision: {readback.flow_revision}.</p>
        {readback.artifacts.length === 0 ? <p>No current signed candidate artifacts returned for this finding.</p> :
          <ul className="space-y-2">
            {readback.artifacts.map(artifact => <li key={artifact.artifact_id}
              className="border border-outline-variant p-2 font-mono break-all">
              <p>Candidate artifact: {artifact.artifact_id}</p>
              <p>Source Task: {artifact.source_task_id}</p>
              <p>Merkle leaf SHA-256: {artifact.merkle_leaf_sha256}</p>
              <p>Candidate only · independent target effect: NOT VERIFIED.</p>
            </li>)}
          </ul>}
        <p>These references are inert metadata, not evidence-content downloads and not human release approval.</p>
      </div>}
    </div>
  </Card>;
}
