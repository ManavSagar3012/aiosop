import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import {
  Activity, AlertTriangle, ClipboardList, GitBranch, Play, Plus,
  RefreshCw, Save, ShieldAlert, Sparkles, CheckCircle2, XCircle, Clock3,
  PauseCircle, RotateCcw, Ban,
} from 'lucide-react';

import { Card } from '../components/shared/Card';
import { SupervisionPanel } from '../components/flows/SupervisionPanel';
import { FlowArtifactsPanel } from '../components/flows/FlowArtifactsPanel';
import { FlowArtifactReviewPanel } from '../components/flows/FlowArtifactReviewPanel';
import { FlowModelAnalyticsPanel } from '../components/flows/FlowModelAnalyticsPanel';
import { OperatorKnowledgePanel } from '../components/flows/OperatorKnowledgePanel';
import { ReviewedLibraryFlowImportPanel } from '../components/flows/ReviewedLibraryFlowImportPanel';
import { SignedWorkflowReplayPanel } from '../components/flows/FlowOperations';
import { CandidateFindingReviewPanel } from '../components/flows/CandidateFindingReviewPanel';
import { CandidateEvidenceArtifactPanel } from '../components/flows/CandidateEvidenceArtifactPanel';
import { McpToolCatalogPanel } from '../components/flows/McpToolCatalogPanel';
import { ProviderPolicyReviewPanel } from '../components/flows/ProviderPolicyReviewPanel';
import { ProviderCredentialProfilesPanel } from '../components/flows/ProviderCredentialProfilesPanel';
import { FlowResourceAliasesPanel } from '../components/flows/FlowResourceAliasesPanel';
import { FlowResourceFoldersPanel } from '../components/flows/FlowResourceFoldersPanel';
import { FlowMcpActionsPanel } from '../components/flows/FlowMcpActionsPanel';
import { FlowMcpActionPreflightPanel } from '../components/flows/FlowMcpActionPreflightPanel';
import { FlowMcpProviderReadinessPanel } from '../components/flows/FlowMcpProviderReadinessPanel';
import { NativeMcpGrantLedgerPanel } from '../components/flows/NativeMcpGrantLedgerPanel';
import { useIntelligenceStore } from '../store/useIntelligenceStore';
import { currentOperator, subscribeOperator } from '../services/api';
import {
  signedReportsApi, sameSignedSnapshot,
  type HumanReleaseReceipt, type SignedReportPreview, type SignedReportReview,
} from '../services/signedReports';
import { readProviderCapabilities, type ProviderCapabilityStatus } from '../services/providerCapabilities';
import {
  Engagement, EngagementDiagnostics, FlowAction, FlowDetail, FlowObjective,
  AdaptiveFollowupAdmission, AdaptivePlannerProposal, FlowApiError, FlowProposalResult, FlowRecord, FlowSubtask, PendingFlowApproval,
  flowApi, operatorRoleHint,
} from '../services/flows';

const buttonStyle =
  'inline-flex items-center gap-2 border border-outline px-3 py-2 text-[11px] font-label-caps text-on-surface hover:bg-surface-container-high disabled:opacity-40 disabled:cursor-not-allowed';
const inputStyle =
  'w-full min-w-0 border border-outline-variant bg-background px-3 py-2 text-[12px] text-on-surface font-code-sm';

function message(error: unknown): string {
  return error instanceof Error ? error.message : 'An unexpected request error occurred';
}

function displayTime(value?: string | null): string {
  if (!value) return 'Unknown';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function statusColor(status: string): string {
  if (status === 'completed' || status === 'success') return 'text-primary-fixed';
  if (['failed', 'error', 'halted', 'cancelled'].includes(status)) return 'text-error';
  if (['running', 'dispatched', 'awaiting_approval', 'paused'].includes(status)) return 'text-secondary';
  return 'text-on-surface-variant';
}

function proposalNotice(action: string, outcome: FlowProposalResult): string {
  if (outcome.status === 'awaiting_planner_approval') {
    return `${action}: internal planner request ${outcome.approval_id ?? 'pending'} is awaiting a senior-operator decision. No model inference or agent execution was started. Refresh approvals and, if approved, explicitly resume the proposal.`;
  }
  if (outcome.status === 'proposed') {
    const count = outcome.added_subtask_ids?.length ?? 0;
    return `${action}: ${count} proposal${count === 1 ? '' : 's'} saved as pending. Review and dispatch each step explicitly.`;
  }
  if (outcome.status === 'unchanged') {
    return `${action}: no new steps proposed${outcome.reason ? ` (${outcome.reason.replace(/_/g, ' ')})` : ''}.`;
  }
  throw new Error(`${action} ${outcome.status.replace(/_/g, ' ')}${outcome.reason ? `: ${outcome.reason.replace(/_/g, ' ')}` : ''}`);
}

/** Explicit, single-snapshot senior review, not an inferred signoff from hashes. */
export function SignedReportOperatorPanel({ engagementId }: { engagementId: string }) {
  const [identity, setIdentity] = useState(() => currentOperator());
  const [reportId, setReportId] = useState('');
  const [preview, setPreview] = useState<SignedReportPreview | null>(null);
  const [release, setRelease] = useState<HumanReleaseReceipt | null>(null);
  const [review, setReview] = useState<SignedReportReview | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [typedDigest, setTypedDigest] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  const senior = identity?.role === 'senior_operator';

  const clearVerification = useCallback(() => {
    ++epoch.current;
    setPreview(null);
    setRelease(null);
    setReview(null);
    setAcknowledged(false);
    setTypedDigest('');
    setReason('');
    setBusy(false);
  }, []);

  useEffect(() => {
    clearVerification();
    setReportId('');
    setError('');
  }, [engagementId, clearVerification]);
  useEffect(() => subscribeOperator(next => {
    clearVerification();
    setIdentity(next);
    setError('Signed report review reset after operator identity changed.');
  }), [clearVerification]);

  function currentSenior(sub: string): boolean {
    return currentOperator()?.role === 'senior_operator' && currentOperator()?.sub === sub;
  }

  async function inspect() {
    if (busy || !senior || !identity?.sub || !reportId.trim()) return;
    const requestId = ++epoch.current;
    const operatorSub = identity.sub;
    setBusy(true);
    setError('');
    setPreview(null);
    setRelease(null);
    setReview(null);
    setAcknowledged(false);
    setTypedDigest('');
    try {
      const verified = await signedReportsApi.inspect(engagementId, reportId.trim());
      const independentlyRead = await signedReportsApi.status(engagementId, verified.report_id);
      if (requestId !== epoch.current || !currentSenior(operatorSub)) return;
      if (!sameSignedSnapshot(verified, independentlyRead)) {
        throw new Error('Signed snapshot differs from current release GET readback.');
      }
      setPreview(verified);
      setRelease(independentlyRead);
    } catch {
      if (requestId === epoch.current) {
        clearVerification();
        setError('Signed report or current human release readback unavailable. State UNKNOWN; no approval is implied.');
      }
    } finally {
      if (requestId === epoch.current) setBusy(false);
    }
  }

  async function downloadForHumanReview() {
    if (busy || !preview || !senior || !identity?.sub) return;
    const requestId = ++epoch.current;
    const operatorSub = identity.sub;
    setBusy(true);
    setError('');
    setReview(null);
    setAcknowledged(false);
    setTypedDigest('');
    try {
      // The browser validates the original signed SHA-256 before allowing a
      // private download. Never render unredacted witness/report bytes in DOM.
      const verified = await signedReportsApi.reviewExactSnapshot(engagementId, preview);
      if (requestId !== epoch.current || !currentSenior(operatorSub)) return;
      const download = document.createElement('a');
      const privateUrl = URL.createObjectURL(new Blob(
        [new Uint8Array(verified.bytes)], { type: 'text/plain' },
      ));
      try {
        download.href = privateUrl;
        download.download = `${preview.report_id}.md`;
        download.rel = 'noopener noreferrer';
        document.body.appendChild(download);
        download.click();
      } finally {
        download.remove();
        // Let the browser begin its download before revoking the private
        // object URL; no report text is inserted into the rendered document.
        window.setTimeout(() => URL.revokeObjectURL(privateUrl), 0);
      }
      setReview(verified.review);
    } catch {
      if (requestId === epoch.current) {
        setReview(null);
        setError('Original nonempty report bytes could not be verified/downloaded. Approval remains disabled.');
      }
    } finally {
      if (requestId === epoch.current) setBusy(false);
    }
  }

  async function approve() {
    if (!preview || !review || !senior || !identity?.sub || busy ||
      release?.status !== 'awaiting_human_release' || !acknowledged ||
      typedDigest !== preview.attestation_sha256 || reason.trim().length < 20 ||
      reason.trim().length > 256) return;
    const operatorSub = identity.sub;
    if (!window.confirm(
      `Human approval of the exact privately reviewed signed report?\n${preview.report_id}\nAttestation SHA-256: ${preview.attestation_sha256}\n` +
      'Approval does NOT certify finding authenticity, vulnerability exploitation or report completeness.'
    )) return;
    const requestId = ++epoch.current;
    setBusy(true);
    setError('');
    setRelease(null); // A POST success or old GET cannot assert durable approval.
    try {
      // Revalidate both independent GET surfaces immediately before release.
      // Backend alone performs atomic signed-ROE/Task/owner release admission.
      const fresh = await signedReportsApi.inspect(engagementId, preview.report_id);
      const before = await signedReportsApi.status(engagementId, preview.report_id);
      if (requestId !== epoch.current || !currentSenior(operatorSub)) return;
      if (fresh.attestation_sha256 !== preview.attestation_sha256 ||
        fresh.authorization_version !== preview.authorization_version ||
        fresh.artifact_sha256.md !== review.artifact_sha256 ||
        !sameSignedSnapshot(fresh, before) || before.status !== 'awaiting_human_release') {
        throw new Error('Original reviewed signed report snapshot is stale or unavailable.');
      }
      const posted = await signedReportsApi.approve(engagementId, fresh, reason, review);
      const readback = await signedReportsApi.status(engagementId, fresh.report_id);
      if (requestId !== epoch.current || !currentSenior(operatorSub)) return;
      if (!sameSignedSnapshot(fresh, readback) ||
        readback.status !== 'human_release_approved' ||
        posted.release_event_id !== readback.release_event_id ||
        posted.operator_approval_recorded !== true ||
        !readback.release_event_id ||
        readback.external_effect_verified !== posted.external_effect_verified) {
        throw new Error('Separate signed release GET could not verify human signoff.');
      }
      setRelease(readback);
      setReason('');
      setAcknowledged(false);
      setTypedDigest('');
    } catch {
      if (requestId === epoch.current) {
        clearVerification();
        setError('Release outcome UNKNOWN or signed snapshot revoked. Reinspect both server GETs; never retry automatically.');
      }
    } finally {
      if (requestId === epoch.current) setBusy(false);
    }
  }

  return <section aria-label="Signed report private human review" className="border border-outline-variant p-4 mb-5 text-xs space-y-3">
    <h3 className="font-label-caps">SIGNED REPORT — PRIVATE HUMAN REVIEW / SEPARATE RELEASE READBACK</h3>
    <p className="text-on-surface-variant">
      The unsigned printable mission summary is NOT a signed report. A signed Task snapshot alone
      does not verify target effects. Original report bytes are delivered as a private file,
      never displayed here as raw witness or authenticated response bodies.
    </p>
    <label className="block">SIGNED REPORT ID
      <input className={inputStyle} value={reportId} maxLength={140}
        placeholder={`report-${engagementId}-v1`}
        onChange={event => { clearVerification(); setReportId(event.target.value.slice(0, 140)); }} />
    </label>
    <button type="button" className={buttonStyle} disabled={!senior || busy || !reportId.trim()}
      onClick={() => void inspect()}>VERIFY SNAPSHOT + SEPARATE SIGNED RELEASE GET</button>
    {error && <p role="alert" className="text-error">{error}</p>}
    {!senior && <p>Only the authenticated senior engagement owner may review and approve a signed report. The server checks ownership.</p>}
    {preview && release && sameSignedSnapshot(preview, release) && <div className="space-y-3 border-t border-outline pt-3">
      <p role="status">Signed generation snapshot read. Human release: {release.status === 'human_release_approved'
        ? 'RECORDED at last independent release GET' : 'AWAITING HUMAN REVIEW'}.</p>
      <p className="font-code-sm break-all">Report: {preview.report_id} · Attestation SHA-256: {preview.attestation_sha256}</p>
      <p>Signed ROE version: {preview.authorization_version}; artifact MD SHA-256: {preview.artifact_sha256.md}.</p>
      {preview.flow_binding && <p>Signed Flow: {preview.flow_binding.flow_id}; generation revision: {preview.flow_binding.flow_revision}.</p>}
      <p>Independent target-effect verification and report completeness are NOT established by this UI or human signature.</p>
      {release.status === 'human_release_approved' ? <p className="font-code-sm break-all">
        Release audit event (last checked): {release.release_event_id}. Refresh to revalidate revocation.
      </p> : <>
        <button type="button" className={buttonStyle} disabled={busy}
          onClick={() => void downloadForHumanReview()}>DOWNLOAD NONEMPTY SHA-256-VERIFIED REPORT FOR PRIVATE HUMAN REVIEW</button>
        {review && <div className="space-y-2">
          <p>Downloaded exact signed Markdown: {review.byte_length} bytes; SHA-256: {review.artifact_sha256}.</p>
          <label className="flex items-start gap-2">
            <input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />
            I personally opened and reviewed the downloaded nonempty signed report snapshot; I understand this does not certify target effects.
          </label>
          <label className="block">TYPE FULL ATTESTATION SHA-256 TO CONFIRM THIS EXACT SNAPSHOT
            <input className={inputStyle} value={typedDigest} maxLength={64} autoComplete="off"
              onChange={event => setTypedDigest(event.target.value)} />
          </label>
          <label className="block">HUMAN FINAL-RELEASE REASON (20–256 CHARACTERS)
            <textarea className={inputStyle} value={reason} maxLength={256} rows={2}
              onChange={event => setReason(event.target.value)} />
          </label>
          <button type="button" className={buttonStyle}
            disabled={busy || !acknowledged || typedDigest !== preview.attestation_sha256 ||
              reason.trim().length < 20 || reason.trim().length > 256}
            onClick={() => void approve()}>
            HUMAN: APPROVE EXACT REVIEWED SNAPSHOT — RECHECK SIGNED RELEASE GET
          </button>
        </div>}
      </>}
    </div>}
  </section>;
}

export function FlowOperations() {
  const storeSessionId = useIntelligenceStore((s) => s.sessionId);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementId, setEngagementId] = useState('');
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [flowId, setFlowId] = useState('');
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  const [createdObjectives, setCreatedObjectives] = useState<FlowObjective[]>([]);
  const [actions, setActions] = useState<FlowAction[] | null>(null);
  const [diagnostics, setDiagnostics] = useState<EngagementDiagnostics | null>(null);
  const [flowError, setFlowError] = useState('');
  const [diagnosticsError, setDiagnosticsError] = useState('');
  const [approvalsError, setApprovalsError] = useState('');
  const [readyApprovalsError, setReadyApprovalsError] = useState('');
  const [adaptiveProposalsError, setAdaptiveProposalsError] = useState('');
  const [pendingApprovals, setPendingApprovals] = useState<PendingFlowApproval[]>([]);
  const [approvedPlannerApprovals, setApprovedPlannerApprovals] = useState<PendingFlowApproval[]>([]);
  const [adaptiveProposals, setAdaptiveProposals] = useState<Record<string, AdaptivePlannerProposal>>({});
  const [confirmedAdaptiveFollowups, setConfirmedAdaptiveFollowups] = useState<Record<string, AdaptiveFollowupAdmission>>({});
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const mutationInFlight = useRef(false);
  const [approvalNotes, setApprovalNotes] = useState<Record<string, string>>({});
  const [emergencyReason, setEmergencyReason] = useState('');
  const [newFlowObjective, setNewFlowObjective] = useState('');
  const [newObjectiveTitle, setNewObjectiveTitle] = useState('');
  const [parentId, setParentId] = useState('');
  const [subtaskTitle, setSubtaskTitle] = useState('');
  const [subtaskDescription, setSubtaskDescription] = useState('');
  const [subtaskType, setSubtaskType] = useState('recon');
  const [subtaskAgent, setSubtaskAgent] = useState('recon');
  const [requiresApproval, setRequiresApproval] = useState(false);
  const [dependencies, setDependencies] = useState<string[]>([]);
  const [editing, setEditing] = useState('');
  const [editTitle, setEditTitle] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [priorities, setPriorities] = useState<Record<string, number>>({});
  const [providerCapabilities, setProviderCapabilities] = useState<ProviderCapabilityStatus | null>(null);
  const [providerCapabilitiesError, setProviderCapabilitiesError] = useState('');
  const [providerCapabilitiesBusy, setProviderCapabilitiesBusy] = useState(false);
  const providerEpoch = useRef(0);

  const selectedEngagement = engagements.find((item) => item.session_id === engagementId);
  const selectedFlow = detail?.flow.id === flowId ? detail.flow : flows.find((item) => item.id === flowId);
  const flowStepCount = detail?.subtasks.length ?? 0;
  const engagementClosed = ['halted', 'completed'].includes(selectedEngagement?.phase ?? '');
  const flowTerminal = ['halted', 'completed', 'cancelled', 'failed'].includes(selectedFlow?.status ?? '');
  const flowPaused = selectedFlow?.status === 'paused';
  const isClosed = engagementClosed || flowTerminal || flowPaused;
  const flowDetailsCurrent = detail?.flow.id === flowId;
  const flowHasSubmittedWork = (flowDetailsCurrent && detail?.subtasks.some((step) =>
    !['pending', 'completed', 'failed', 'cancelled'].includes(step.status))) || false;
  const roleHint = operatorRoleHint();
  const verifiedApprover = currentOperator();
  const canAttemptFlowControl = roleHint === null || ['operator', 'senior_operator'].includes(roleHint);
  const canAttemptHalt = roleHint === null || roleHint === 'senior_operator';
  const canAttemptCancel = canAttemptHalt;
  const canAttemptApproval = verifiedApprover?.role === 'senior_operator';
  useEffect(() => {
    ++providerEpoch.current;
    setProviderCapabilities(null);
    setProviderCapabilitiesError('');
  }, [engagementId, verifiedApprover?.sub, verifiedApprover?.role]);

  const refreshProviderCapabilities = useCallback(async () => {
    if (!engagementId || currentOperator()?.role !== 'senior_operator') return;
    const current = ++providerEpoch.current;
    const engagement = engagementId;
    setProviderCapabilities(null);
    setProviderCapabilitiesError('');
    setProviderCapabilitiesBusy(true);
    try {
      const result = await readProviderCapabilities(engagement);
      if (current !== providerEpoch.current) return;
      setProviderCapabilities(result);
    } catch (reason) {
      if (current === providerEpoch.current) setProviderCapabilitiesError(message(reason));
    } finally {
      if (current === providerEpoch.current) setProviderCapabilitiesBusy(false);
    }
  }, [engagementId]);
  const authorizedScope = Boolean(
    selectedEngagement?.scope.authorization_ref &&
    ((selectedEngagement.scope.domains?.length ?? 0) > 0 || (selectedEngagement.scope.ips?.length ?? 0) > 0),
  );

  const objectives = useMemo(() => {
    const fromServer = detail?.tasks ?? [];
    const known = new Map<string, FlowObjective>();
    for (const task of fromServer) {
      if (task.flow_id === flowId && task.type === 'flow_objective') known.set(task.id, task);
    }
    for (const task of createdObjectives) {
      if (task.flow_id === flowId && !known.has(task.id)) known.set(task.id, task);
    }
    return Array.from(known.values()).sort((a, b) => a.created_at.localeCompare(b.created_at));
  }, [detail, flowId, createdObjectives]);

  const flowApprovals = useMemo(() => {
    if (!detail || detail.flow.id !== flowId) return [];
    const taskIds = new Set(detail.subtasks.map((step) => step.execution_task_id).filter(
      (id): id is string => Boolean(id)));
    return pendingApprovals.filter((approval) =>
      approval.engagement_id === engagementId && (
        taskIds.has(approval.task_id) ||
        (approval.action_type === 'planner_inference' && approval.flow_id === flowId)
      ));
  }, [detail, flowId, engagementId, pendingApprovals]);

  const pendingEngagementApprovals = pendingApprovals.filter(
    (approval) => approval.engagement_id === engagementId);
  const readyFlowApprovals = approvedPlannerApprovals.filter(
    (approval) => approval.engagement_id === engagementId
      && approval.action_type === 'planner_inference'
      && approval.flow_id === flowId
      && approval.status === 'approved');
  const unmappedApprovalCount = Math.max(0, pendingEngagementApprovals.length - flowApprovals.length);

  const refreshApprovals = useCallback(async (id?: string) => {
    const session = id ?? engagementId;
    const [pendingResult, readyResult, proposalsResult] = await Promise.allSettled([
      flowApi.listPendingApprovals(),
      session ? flowApi.listApprovedPlannerApprovals(session) : Promise.resolve([]),
      session ? flowApi.listAdaptivePlannerProposals(session) : Promise.resolve([]),
    ]);
    if (pendingResult.status === 'fulfilled') {
      setPendingApprovals(pendingResult.value.filter((item) => item.status === 'pending'));
      setApprovalsError('');
    } else {
      setPendingApprovals([]);
      setApprovalsError(message(pendingResult.reason));
    }
    if (readyResult.status === 'fulfilled') {
      setApprovedPlannerApprovals(readyResult.value.filter((item) => item.status === 'approved'));
      setReadyApprovalsError('');
    } else {
      setApprovedPlannerApprovals([]);
      setReadyApprovalsError(message(readyResult.reason));
    }
    if (proposalsResult.status === 'fulfilled') {
      setAdaptiveProposals(Object.fromEntries(
        proposalsResult.value.filter((item) => item.status === 'proposal_ready')
          .map((item) => [item.approval_id, item]),
      ));
      setAdaptiveProposalsError('');
    } else {
      setAdaptiveProposals({});
      setAdaptiveProposalsError(message(proposalsResult.reason));
    }
  }, [engagementId]);

  const refreshEngagement = useCallback(async (id: string) => {
    const [flowResult, diagnosticResult] = await Promise.allSettled([
      flowApi.listFlows(id),
      flowApi.getDiagnostics(id),
    ]);
    if (flowResult.status === 'fulfilled') {
      const next = flowResult.value;
      setFlows(next);
      setFlowError('');
      setFlowId((current) => next.some((flow) => flow.id === current) ? current : next[0]?.id ?? '');
    } else {
      setFlowError(message(flowResult.reason));
      setFlows([]);
      setFlowId('');
    }
    if (diagnosticResult.status === 'fulfilled') {
      setDiagnostics(diagnosticResult.value);
      setDiagnosticsError('');
    } else {
      setDiagnostics(null);
      setDiagnosticsError(message(diagnosticResult.reason));
    }
    setLoading(false);
  }, []);

  const refreshFlow = useCallback(async (id: string) => {
    const [detailResult, actionsResult] = await Promise.allSettled([
      flowApi.getFlow(id),
      flowApi.listActions(id),
    ]);
    if (detailResult.status === 'fulfilled') {
      const data = detailResult.value;
      // Older API instances omit task objectives. Recover parents referenced
      // by subtasks through the existing authenticated GET /tasks/:id.
      if (!data.tasks) {
        const parentIds = [...new Set(data.subtasks.map((task) => task.task_id))];
        const recovered = await Promise.allSettled(parentIds.map((taskId) => flowApi.getTask(taskId)));
        data.tasks = recovered
          .filter((entry): entry is PromiseFulfilledResult<FlowObjective> => entry.status === 'fulfilled')
          .map((entry) => entry.value)
          .filter((task) => task.flow_id === id && task.type === 'flow_objective');
      }
      setDetail(data);
      setFlowError('');
    } else {
      setDetail(null);
      setFlowError(message(detailResult.reason));
    }
    if (actionsResult.status === 'fulfilled') {
      setActions(actionsResult.value.actions);
    } else {
      setActions(null);
      setFlowError((previous) => [previous, `Action history: ${message(actionsResult.reason)}`].filter(Boolean).join(' • '));
    }
  }, []);

  useEffect(() => {
    let alive = true;
    flowApi.listEngagements().then((items) => {
      if (!alive) return;
      setEngagements(items);
      setEngagementId((current) => items.some((e) => e.session_id === current)
        ? current : items.find((e) => e.session_id === storeSessionId)?.session_id ?? items[0]?.session_id ?? '');
    }).catch((err: unknown) => {
      if (alive) setError(`Unable to load engagements: ${message(err)}`);
    }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [storeSessionId]);

  useEffect(() => {
    setDetail(null);
    setActions(null);
    setDiagnostics(null);
    setFlows([]);
    setFlowId('');
    setCreatedObjectives([]);
    setPendingApprovals([]);
    setApprovedPlannerApprovals([]);
    setAdaptiveProposals({});
    setConfirmedAdaptiveFollowups({});
    setEditing('');
    setParentId('');
    if (engagementId) {
      setLoading(true);
      void refreshEngagement(engagementId);
    }
  }, [engagementId, refreshEngagement]);

  useEffect(() => {
    setDetail(null);
    setActions(null);
    setEditing('');
    setParentId('');
    if (flowId) void refreshFlow(flowId);
    if (engagementId) void refreshApprovals();
  }, [engagementId, flowId, refreshFlow, refreshApprovals]);

  useEffect(() => {
    if (objectives.length && !objectives.some((item) => item.id === parentId)) {
      setParentId(objectives[0].id);
      setDependencies([]);
    }
  }, [objectives, parentId]);

  useEffect(() => {
    if (!engagementId) return;
    // External operators may resolve approvals or finish dependencies while
    // this page is open. Poll the same authenticated read routes, not guesses.
    const timer = window.setInterval(() => {
      if (busy) return;
      void refreshApprovals();
      if (flowId) void refreshFlow(flowId);
    }, 20_000);
    return () => window.clearInterval(timer);
  }, [engagementId, flowId, busy, refreshApprovals, refreshFlow]);

  const run = async (key: string, operation: () => Promise<string>) => {
    // React state updates can lag a double click; this lock prevents duplicate
    // approval resolutions, dispatches, or emergency halts in one UI session.
    if (mutationInFlight.current) return;
    mutationInFlight.current = true;
    setBusy(key);
    setError('');
    setNotice('');
    try {
      setNotice(await operation());
    } catch (err: unknown) {
      // A 409 means the flow revision or safety conditions changed. Never
      // imply the requested operation succeeded; refresh authoritative state.
      if (flowId) await refreshFlow(flowId);
      if (engagementId && err instanceof FlowApiError && err.status === 409) {
        await refreshEngagement(engagementId);
      }
      await refreshApprovals();
      setError(err instanceof FlowApiError && err.status === 409
        ? `409 Conflict: ${err.message}. Flow status and revision were refreshed; inspect active work before retrying.`
        : message(err));
    } finally {
      mutationInFlight.current = false;
      setBusy('');
    }
  };

  const refresh = async () => {
    setError('');
    setNotice('');
    setBusy('refresh');
    try {
      const updated = await flowApi.listEngagements();
      setEngagements(updated);
      if (engagementId) await refreshEngagement(engagementId);
      if (flowId) await refreshFlow(flowId);
      await refreshApprovals();
    } catch (err: unknown) {
      setError(message(err));
    } finally {
      setBusy('');
    }
  };

  const createFlow = (event: FormEvent) => {
    event.preventDefault();
    const objective = newFlowObjective.trim();
    if (!engagementId || !objective) return;
    void run('new-flow', async () => {
      const created = await flowApi.createFlow(engagementId, objective);
      setNewFlowObjective('');
      setFlows((current) => [created, ...current]);
      setFlowId(created.id);
      await refreshEngagement(engagementId);
      return `Created flow ${created.id}`;
    });
  };

  const createObjective = (event: FormEvent) => {
    event.preventDefault();
    const title = newObjectiveTitle.trim();
    if (!flowId || !title) return;
    void run('new-objective', async () => {
      const task = await flowApi.createObjective(flowId, title);
      setCreatedObjectives((existing) => [...existing, task]);
      setNewObjectiveTitle('');
      setParentId(task.id);
      await refreshFlow(flowId);
      return `Added objective: ${title}`;
    });
  };

  const generateProposals = (objective: FlowObjective) => {
    if (!flowId || !engagementId || !authorizedScope || isClosed || busy) return;
    void run(`generate-${objective.id}`, async () => {
      const outcome = await flowApi.generateProposals(flowId, objective.id);
      await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      await refreshApprovals(engagementId);
      return proposalNotice(`Generate for ${objective.payload?.title || objective.id}`, outcome);
    });
  };

  const refineProposals = (step: FlowSubtask) => {
    if (!flowId || !engagementId || !authorizedScope || isClosed || busy ||
      step.status !== 'completed' || (step.refinement_count ?? 0) >= 3) return;
    void run(`refine-${step.id}`, async () => {
      const outcome = await flowApi.refineProposals(flowId, step.id);
      await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      await refreshApprovals(engagementId);
      return proposalNotice(`Refine ${step.title}`, outcome);
    });
  };

  const createSubtask = (event: FormEvent) => {
    event.preventDefault();
    const title = subtaskTitle.trim();
    if (!flowId || !parentId || !title) return;
    void run('new-subtask', async () => {
      await flowApi.createSubtask(flowId, {
        task_id: parentId,
        title,
        description: subtaskDescription.trim(),
        task_type: subtaskType,
        agent_type: subtaskAgent,
        approval_required: requiresApproval,
        dependencies,
      });
      setSubtaskTitle('');
      setSubtaskDescription('');
      setDependencies([]);
      await refreshFlow(flowId);
      return `Added pending subtask: ${title}`;
    });
  };

  const revise = (step: FlowSubtask) => {
    if (!flowId || !selectedFlow || !editTitle.trim()) return;
    void run(`revise-${step.id}`, async () => {
      await flowApi.reviseSubtask(flowId, step.id, {
        title: editTitle.trim(),
        description: editDescription.trim(),
        expected_revision: selectedFlow.revision,
      });
      setEditing('');
      await refreshFlow(flowId);
      return `Revised subtask: ${step.id}`;
    });
  };

  const dispatch = (step: FlowSubtask) => {
    if (!flowId || !authorizedScope || isClosed) return;
    const target = (targets[step.id] || '').trim();
    const priority = priorities[step.id] ?? 5;
    if (['recon', 'vuln_analysis'].includes(step.agent_type) && !target) {
      setError('A scoped target is required for reconnaissance and vulnerability analysis.');
      return;
    }
    if (!window.confirm(
      `Dispatch "${step.title}" to ${step.agent_type}?\n` +
      `Target: ${target || 'None supplied'}\nPriority: ${priority}\n` +
      'This schedules execution through the platform approval and scope checks.',
    )) return;
    void run(`dispatch-${step.id}`, async () => {
      const dispatched = await flowApi.dispatchSubtask(flowId, step.id, {
        payload: target ? { target } : {},
        priority,
      });
      await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      await refreshApprovals();
      return `Dispatched ${step.title} as ${dispatched.task_id} (${dispatched.status})`;
    });
  };

  const changeFlowPlanning = (action: 'pause' | 'resume' | 'cancel') => {
    if (!flowId || !selectedFlow || !flowDetailsCurrent || engagementClosed || busy) return;
    if (!canAttemptFlowControl || (action === 'cancel' && !canAttemptCancel)) return;
    const eligible = action === 'pause'
      ? ['pending', 'running'].includes(selectedFlow.status)
      : action === 'resume'
        ? selectedFlow.status === 'paused'
        : ['pending', 'running', 'paused'].includes(selectedFlow.status);
    if (!eligible) return;
    if (action === 'resume' && !authorizedScope) {
      setError('Resume requires a currently authorized engagement scope; the API also checks its testing window.');
      return;
    }
    if (flowHasSubmittedWork) {
      setError('This flow contains submitted or unresolved work. Planning pause/cancel/resume cannot stop external execution; use senior emergency halt if needed.');
      return;
    }
    const currentId = selectedFlow.id;
    const currentRevision = selectedFlow.revision;
    const description = action === 'pause'
      ? 'Pause new planning and dispatch only. No running execution will be stopped.'
      : action === 'resume'
        ? 'Resume planning and dispatch subject to authorization, testing window, dependencies and approvals.'
        : 'Cancel the flow plan and its pending, unsubmitted subtasks. This does not cancel live work and cannot be undone.';
    if (!window.confirm(
      `${action.toUpperCase()} flow ${currentId} (revision ${currentRevision})?\n${description}\n` +
      'The server rejects stale revisions and unresolved execution with HTTP 409.',
    )) return;
    void run(`flow-${action}`, async () => {
      const outcome = action === 'pause'
        ? await flowApi.pauseFlow(currentId, currentRevision)
        : action === 'resume'
          ? await flowApi.resumeFlow(currentId, currentRevision)
          : await flowApi.cancelFlow(currentId, currentRevision);
      const expectedStatus = action === 'resume' ? 'pending' : action === 'pause' ? 'paused' : 'cancelled';
      await refreshFlow(currentId);
      await refreshEngagement(engagementId);
      await refreshApprovals();
      if (outcome.flow_id !== currentId || outcome.status !== expectedStatus) {
        throw new Error(`Flow control API returned ${outcome.status} for ${outcome.flow_id}; expected ${expectedStatus}. Review refreshed state.`);
      }
      return action === 'resume'
        ? `API confirmed flow ${currentId} resumed to ${outcome.status}. Scheduling remains subject to scope, dependencies and approvals.`
        : `API confirmed flow ${currentId} ${outcome.status}. This changes planning only; it does not stop active execution.`;
    });
  };

  const halt = () => {
    if (!flowId || !canAttemptHalt || engagementClosed || busy) return;
    if (!window.confirm(
      `Senior operator action: halt flow ${flowId} AND engagement ${engagementId}?\nActive agents may be stopped.`,
    )) return;
    void run('halt-flow', async () => {
      const result = await flowApi.haltFlow(flowId);
      const updatedEngagements = await flowApi.listEngagements();
      setEngagements(updatedEngagements);
      await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      await refreshApprovals();
      return `API confirmed flow ${result.flow_id} status: ${result.status}. Refreshed status is shown above.`;
    });
  };

  const emergencyHalt = () => {
    const reason = emergencyReason.trim();
    if (!engagementId || !canAttemptHalt || engagementClosed || busy) return;
    if (reason.length < 10 || reason.length > 500) {
      setError('Enter an emergency halt reason between 10 and 500 characters.');
      return;
    }
    if (!window.confirm(
      `EMERGENCY HALT engagement ${engagementId}?\nReason: ${reason}\n` +
      'This affects every flow in the engagement and is different from planning-only pause/cancel.',
    )) return;
    void run('emergency-halt', async () => {
      const result = await flowApi.haltEngagement(engagementId, reason);
      const updatedEngagements = await flowApi.listEngagements();
      setEngagements(updatedEngagements);
      await refreshEngagement(engagementId);
      if (flowId) await refreshFlow(flowId);
      await refreshApprovals();
      return `Emergency halt API result for ${result.session_id}: ${result.status}. Review refreshed engagement and flow statuses.`;
    });
  };

  const decideApproval = (approval: PendingFlowApproval, decision: 'approved' | 'rejected') => {
    if (!canAttemptApproval || busy || isClosed || approval.status !== 'pending' ||
      approval.engagement_id !== engagementId || !flowApprovals.some((item) => item.id === approval.id)) return;
    const plannerRevision = approval.action_type === 'planner_inference' ? (
      Number.isInteger(approval.authorization_version) && (approval.authorization_version ?? 0) > 0 &&
      Number.isInteger(approval.flow_revision) && (approval.flow_revision ?? -1) >= 0
        ? {
            expected_authorization_version: approval.authorization_version as number,
            expected_flow_revision: approval.flow_revision as number,
          }
        : null
    ) : undefined;
    if (approval.action_type === 'planner_inference' && !plannerRevision) {
      setError('Planner approval has no authoritative signed/Flow revision. Refresh its persisted status.');
      return;
    }
    const notes = approvalNotes[approval.id]?.trim() || '';
    if (decision === 'rejected' && !notes) {
      setError('Add a reason before rejecting an approval request.');
      return;
    }
    if (!window.confirm(
      `${decision === 'approved' ? 'Approve' : 'Reject'} request ${approval.id} for task ${approval.task_id}?\n` +
      (approval.action_type === 'planner_inference'
        ? 'This decision will NOT dispatch an agent or call a model. Approved planning must be explicitly resumed under a new authorization check.\n'
        : `${decision === 'approved' ? 'Approval may allow the task to execute when dependencies are satisfied.' : 'Rejection may fail the waiting task.'}\n`) +
      'The server validates your senior-operator permission.',
    )) return;
    void run(`approval-${approval.id}`, async () => {
      const response = await flowApi.resolveApproval(approval.id, decision, notes, plannerRevision ?? undefined);
      await refreshApprovals();
      if (flowId) await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      if (response.status !== decision) {
        throw new Error(`Approval API returned ${response.status}; requested ${decision}. Verify refreshed state.`);
      }
      return approval.action_type === 'planner_inference'
        ? `Recorded ${response.status} for the internal planner. This did NOT run an agent or spend model tokens; explicitly re-run generation/refinement after approval.`
        : `API recorded ${response.status} for request ${response.id}. Task execution status is shown separately.`;
    });
  };

  const resumeApprovedPlanner = (approval: PendingFlowApproval) => {
    if (
      mutationInFlight.current || busy || !authorizedScope || isClosed
      || approval.engagement_id !== engagementId || approval.flow_id !== flowId
      || approval.action_type !== 'planner_inference' || approval.status !== 'approved'
      || approval.flow_revision_current !== true || !readyFlowApprovals.some((item) => item.id === approval.id)
    ) return;
    const purpose = approval.planner_purpose;
    const objective = objectives.find((item) => item.id === approval.parent_task_id);
    const source = detail?.subtasks.find((step) => step.id === approval.source_subtask_id);
    if (purpose === 'flow_generation' && (!objective || objective.status !== 'planned')) {
      setError('Approved planner objective is no longer available. Refresh and review before continuing.');
      return;
    }
    if (purpose === 'flow_refinement' && (!source || source.status !== 'completed')) {
      setError('Approved refinement source is no longer completed. Refresh and review before continuing.');
      return;
    }
    // Adaptive continuation needs a dedicated authenticated endpoint; do not
    // invoke on_task_completed() and its unfenced direct scheduling path.
    if (purpose === 'adaptive_planning' && !canAttemptApproval) {
      setError('Verified senior-operator identity is required to resume adaptive planning.');
      return;
    }
    if (!['flow_generation', 'flow_refinement', 'adaptive_planning'].includes(purpose ?? '')) {
      setError('Unknown planner purpose; no inference was started.');
      return;
    }
    if (!Number.isInteger(approval.authorization_version) || !Number.isInteger(approval.flow_revision)) {
      setError('Signed or Flow version is missing; refresh approval details.');
      return;
    }
    if (!window.confirm(
      `Resume approved internal planner ${approval.task_id}?\n` +
      `Authorization version ${approval.authorization_version}, Flow revision ${approval.flow_revision}.\n` +
      'This explicitly requests a paid model inference. It does NOT dispatch a scanning or exploitation agent. Adaptive results are PROPOSALS ONLY. The server rechecks signed authorization and can reject stale approval.',
    )) return;
    void run(`planner-resume-${approval.id}`, async () => {
      if (purpose === 'adaptive_planning') {
        const result = await flowApi.continueApprovedAdaptivePlanner(
          approval.id, approval.authorization_version!, approval.flow_revision!,
        );
        if (result.status !== 'proposal_ready' || result.execution_started !== false ||
          result.review_required !== true || result.planner_task_id !== approval.task_id) {
          throw new Error('Adaptive continuation receipt incomplete or unexpected. No execution can be assumed.');
        }
        setAdaptiveProposals((previous) => ({ ...previous, [approval.id]: result }));
        await refreshApprovals(engagementId);
        await refreshFlow(flowId);
        await refreshEngagement(engagementId);
        return `Adaptive planner ${approval.id} settled. Proposal: ${result.proposal.action}. HUMAN REVIEW REQUIRED: no agent scheduled and no target scanned.`;
      }
      const result = purpose === 'flow_generation'
        ? await flowApi.generateProposals(flowId, objective!.id)
        : await flowApi.refineProposals(flowId, source!.id);
      await refreshApprovals(engagementId);
      await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      return proposalNotice(`Resume approved planner ${approval.id}`, result);
    });
  };

  const confirmAdaptiveFollowup = (proposal: AdaptivePlannerProposal) => {
    const target = proposal.proposal.parameters.target;
    if (busy || mutationInFlight.current || !canAttemptApproval || !authorizedScope || isClosed ||
      proposal.flow_id !== flowId || !flowDetailsCurrent ||
      proposal.flow_revision !== selectedFlow?.revision ||
      proposal.proposal.action !== 'request_sub_recon' || !target ||
      !Number.isInteger(proposal.authorization_version) || (proposal.authorization_version ?? 0) <= 0) {
      setError('This adaptive follow-up requires a verified senior operator, current signed version and Flow revision, and an in-scope recon proposal. Refresh and review.');
      return;
    }
    if (!window.confirm(
      `AUTHORIZE a pending reconnaissance plan for target ${target}?\n` +
      `Approval ${proposal.approval_id}, signed authorization v${proposal.authorization_version}, Flow revision ${proposal.flow_revision}.\n` +
      'This is a separate explicit human execution confirmation. It ONLY creates a planned objective and a pending approval-required subtask; it does NOT call an agent, queue an execution, or touch a target. Later execution requires separate authenticated subtask dispatch and approval.',
    )) return;
    void run(`adaptive-confirm-${proposal.approval_id}`, async () => {
      const admission = await flowApi.prepareConfirmedAdaptiveFollowup(
        proposal.approval_id, proposal.authorization_version!, proposal.flow_revision, target,
      );
      if (admission.status !== 'pending_dispatch_review' || admission.execution_started !== false ||
        admission.dispatch_required !== true || admission.approval_required !== true || admission.target !== target ||
        admission.flow_id !== flowId || admission.flow_revision !== proposal.flow_revision + 1) {
        throw new Error('Adaptive follow-up receipt was unexpected. Execution cannot be assumed; inspect durable Flow state.');
      }
      setConfirmedAdaptiveFollowups((prior) => ({ ...prior, [proposal.approval_id]: admission }));
      await refreshApprovals(engagementId);
      await refreshFlow(flowId);
      await refreshEngagement(engagementId);
      return `Server persisted human-confirmed adaptive plan: objective ${admission.objective_task_id}, pending subtask ${admission.subtask_id}. EXECUTION NOT STARTED. A separate subtask dispatch and approval are required.`;
    });
  };

  const priorSubtasks = (detail?.subtasks ?? []).filter((step) => step.task_id === parentId)
    .sort((a, b) => a.order - b.order);

  return (
    <div className="flex flex-col gap-6 text-on-surface" data-testid="flow-operations">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display-lg text-primary-fixed text-[24px] uppercase flex gap-3 items-center">
            <GitBranch size={24} /> Flow Operations
          </h1>
          <p className="text-on-surface-variant text-[12px] mt-2">
            Persistent objectives, human-initiated dispatch and real engagement diagnostics.
          </p>
        </div>
        <button className={buttonStyle} type="button" onClick={() => void refresh()} disabled={Boolean(busy)}>
          <RefreshCw size={14} /> {busy === 'refresh' ? 'REFRESHING...' : 'REFRESH FROM API'}
        </button>
      </div>
      {error && <div role="alert" className="border border-error bg-error/10 p-3 text-error text-[12px]">{error}</div>}
      {notice && <div role="status" className="border border-primary-fixed/40 bg-primary-fixed/5 p-3 text-primary-fixed text-[12px]">{notice}</div>}

      <Card title="Authorized engagement">
        <div className="flex flex-wrap items-end gap-4">
          <label className="flex-1 min-w-[230px] text-[11px] text-on-surface-variant">
            ENGAGEMENT
            <select aria-label="Engagement" value={engagementId} onChange={(e) => setEngagementId(e.target.value)} className={inputStyle}>
                    <option value="">Select an engagement</option>
              {engagements.map((eng) => (
                <option key={eng.session_id} value={eng.session_id}>{eng.session_id} · {eng.phase}</option>
              ))}
            </select>
          </label>
          {selectedEngagement && (
            <div className="text-[11px] text-on-surface-variant">
              <div>Phase: <strong className={statusColor(selectedEngagement.phase)}>{selectedEngagement.phase}</strong></div>
              <div>Scope: {[...(selectedEngagement.scope.domains ?? []), ...(selectedEngagement.scope.ips ?? [])].join(', ') || 'Not specified'}</div>
              <div>Authorization: {authorizedScope ? 'Reference and explicit scope present' : 'Reference or scope missing — dispatch unavailable'}</div>
            </div>
          )}
          {loading && <span className="text-on-surface-variant text-[11px]">Loading…</span>}
        </div>
        {!loading && engagements.length === 0 && !error && (
          <p className="text-on-surface-variant text-[12px] mt-3">No accessible engagements returned by the API.</p>
        )}
        {selectedEngagement && (
          <div className="mt-4 border-t border-outline-variant pt-4 space-y-3">
            <p className="text-on-surface-variant text-[11px]">
              Flow pause/resume/cancel controls affect the plan, not active execution. 
              Per-task execution cancellation is not available. Senior-operator emergency halt affects the entire engagement.
            </p>
            {canAttemptHalt ? (
              <div className="flex flex-wrap items-end gap-3">
                <label className="flex-1 min-w-[230px] text-[11px] text-on-surface-variant">EMERGENCY HALT REASON (REQUIRED)
                  <input className={inputStyle} aria-label="Emergency halt reason" maxLength={500}
                    value={emergencyReason} onChange={(event) => setEmergencyReason(event.target.value)}
                    placeholder="Explain the immediate safety or scope concern" />
                </label>
                <button type="button" onClick={emergencyHalt}
                  className="inline-flex items-center gap-2 border border-error text-error px-3 py-2 text-[11px] font-label-caps hover:bg-error/10 disabled:opacity-40"
                  disabled={Boolean(busy) || engagementClosed || emergencyReason.trim().length < 10 || emergencyReason.trim().length > 500}>
                  <ShieldAlert size={14} /> {busy === 'emergency-halt' ? 'HALTING...' : 'SENIOR: EMERGENCY HALT ENGAGEMENT'}
                </button>
              </div>
            ) : (
              <p className="text-on-surface-variant text-[11px]">Only senior_operator can perform emergency halt.</p>
            )}
          </div>
        )}
      </Card>

      {engagementId && (
        <>
          {canAttemptApproval && <Card title="Provider routes — declared capabilities only">
            <div className="space-y-2 text-xs">
              <p>Read-only operator catalog. Live provider availability and native cost ceilings are NOT verified. Signed budget admission remains required before any model use.</p>
              <button type="button" className={buttonStyle} disabled={providerCapabilitiesBusy}
                onClick={() => void refreshProviderCapabilities()}>Refresh declared provider routes</button>
              {providerCapabilitiesError && <p role="alert" className="text-error">{providerCapabilitiesError}</p>}
              {providerCapabilities?.engagement_id === engagementId && <div>
                {providerCapabilities.routes.length === 0 ? <p>No locally declared provider routes.</p>
                  : providerCapabilities.routes.map((route, index) => <p key={`${index}-${route.provider}-${route.model}`}>
                    {route.provider} / {route.model} — {route.deployment} — declared operations: {route.operations.join(', ') || 'none'} (unverified)
                  </p>)}
                <p>Provider currently available: NOT VERIFIED. Native price ceiling: NOT VERIFIED. Signed budget admission: REQUIRED.</p>
              </div>}
            </div>
          </Card>}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Create flow">
              <form onSubmit={createFlow} className="flex gap-2 items-end">
                <label className="flex-1 text-[11px] text-on-surface-variant">FLOW OBJECTIVE
                  <input className={inputStyle} value={newFlowObjective} maxLength={2048}
                    onChange={(e) => setNewFlowObjective(e.target.value)} required
                    placeholder="Describe the approved security objective" />
                </label>
                <button className={buttonStyle} type="submit" disabled={Boolean(busy) || !newFlowObjective.trim() || engagementClosed}>
                  <Plus size={14} /> CREATE
                </button>
              </form>
            </Card>
            <Card title="Existing flows">
              {flowError && <p role="alert" className="text-error text-[11px] mb-2">{flowError}</p>}
              {flows.length === 0 ? (
                <p className="text-on-surface-variant text-[12px]">No persisted flows returned.</p>
              ) : (
                <label className="text-[11px] text-on-surface-variant">SELECT FLOW
                  <select aria-label="Flow" className={inputStyle} value={flowId} onChange={(e) => setFlowId(e.target.value)}>
                    {flows.map((flow) => (
                      <option key={flow.id} value={flow.id}>{flow.objective.slice(0, 85)} · {flow.status}</option>
                    ))}
                  </select>
                </label>
              )}
            </Card>
          </div>

          {selectedFlow && (
            <>
              <FlowModelAnalyticsPanel
                key={`model-analytics-${selectedFlow.id}`}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
              />
              <FlowArtifactsPanel
                key={selectedFlow.id}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
              />
              <McpToolCatalogPanel
                key={`mcp-declarations-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                objectives={objectives.filter(item => item.status === 'planned')
                  .map(item => ({ id: item.id, title: item.payload?.title || item.id }))}
                onProposed={() => void refreshFlow(selectedFlow.id)}
              />
              <FlowMcpActionsPanel
                key={`signed-mcp-actions-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref ?? undefined}
              />
              <FlowMcpActionPreflightPanel
                key={`mcp-action-preflight-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <FlowMcpProviderReadinessPanel
                key={`mcp-provider-readiness-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <NativeMcpGrantLedgerPanel
                key={`native-grant-ledger-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <ProviderPolicyReviewPanel
                key={`provider-intent-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <ProviderCredentialProfilesPanel
                key={`provider-profile-references-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <FlowResourceAliasesPanel
                key={`virtual-resources-${selectedFlow.id}-${selectedFlow.revision}`}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
              />
              <FlowResourceFoldersPanel
                key={`persisted-resource-folders-${selectedFlow.id}-${selectedFlow.revision}`}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <OperatorKnowledgePanel
                key={`operator-knowledge-${selectedFlow.id}`}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
              />
              <ReviewedLibraryFlowImportPanel
                key={`reviewed-global-library-${selectedFlow.id}-${selectedFlow.revision}`}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
                authorizationId={selectedEngagement?.scope.authorization_ref ?? undefined}
              />
              <FlowArtifactReviewPanel
                key={`human-review-${selectedFlow.id}`}
                flowId={selectedFlow.id}
                engagementId={selectedFlow.engagement_id}
                revision={selectedFlow.revision}
                authorizationId={selectedEngagement?.scope.authorization_ref}
              />
              <SignedWorkflowReplayPanel
                key={`signed-replay-${selectedFlow.id}`}
                engagement={selectedEngagement ?? null}
                flow={selectedFlow}
                disabled={Boolean(busy) || !flowDetailsCurrent || !authorizedScope || isClosed}
                onProposed={() => void refreshFlow(selectedFlow.id)}
              />
              <CandidateFindingReviewPanel
                key={`candidate-source-${selectedFlow.id}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
              />
              <CandidateEvidenceArtifactPanel
                key={`candidate-evidence-${selectedFlow.id}-${selectedFlow.revision}`}
                engagementId={selectedFlow.engagement_id}
                flowId={selectedFlow.id}
                revision={selectedFlow.revision}
                flowStatus={selectedFlow.status}
              />
              <Card title="Flow plan and operator controls">
                <div className="flex flex-wrap gap-4 items-center justify-between mb-4">
                  <div className="min-w-0">
                    <h2 className="text-primary-fixed font-code-sm break-words">{selectedFlow.objective}</h2>
                    <p className="text-on-surface-variant text-[11px]">
                      {selectedFlow.id} · Revision {selectedFlow.revision} · <span className={statusColor(selectedFlow.status)}>{selectedFlow.status}</span>
                    </p>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    {canAttemptHalt && (
                      <button className="inline-flex items-center gap-2 border border-error text-error px-3 py-2 text-[11px] font-label-caps hover:bg-error/10 disabled:opacity-40"
                        type="button" onClick={halt} disabled={Boolean(busy) || engagementClosed}>
                        <ShieldAlert size={14} /> SENIOR: HALT FLOW + ENGAGEMENT
                      </button>
                    )}
                    <small className="text-on-surface-variant text-[10px]">
                      {roleHint === 'operator'
                        ? 'Halt requires senior_operator privileges.'
                        : 'Halt is validated server-side as senior_operator only.'}
                    </small>
                  </div>
                </div>
                <div className="border-t border-outline-variant pt-4 mt-4 mb-4 space-y-3">
                  <p className="text-on-surface-variant text-[11px]">
                    Plan-only controls. Pausing prevents new dispatches; resuming requires active authorized scope. 
                    Cancelling marks unsubmitted steps cancelled. These controls cannot stop running tools or workflows.
                  </p>
                  {flowHasSubmittedWork && (
                    <p role="status" className="text-secondary text-[11px]">
                      This flow includes submitted or unresolved work. The API will reject plan pause/cancel while execution is in flight (HTTP 409).
                      Use senior emergency halt if active execution must stop.
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2">
                    <button type="button" className={buttonStyle}
                      onClick={() => changeFlowPlanning('pause')}
                      disabled={Boolean(busy) || !flowDetailsCurrent || !canAttemptFlowControl || engagementClosed ||
                        !['pending', 'running'].includes(selectedFlow.status) || flowHasSubmittedWork}
                      title="Pause new flow planning only; in-flight tasks cannot be paused">
                      <PauseCircle size={14} /> {busy === 'flow-pause' ? 'PAUSING...' : 'PAUSE PLAN'}
                    </button>
                    <button type="button" className={buttonStyle}
                      onClick={() => changeFlowPlanning('resume')}
                      disabled={Boolean(busy) || !flowDetailsCurrent || !canAttemptFlowControl || engagementClosed ||
                        selectedFlow.status !== 'paused' || !authorizedScope || flowHasSubmittedWork}
                      title="Resume only a paused flow in an active authorized engagement">
                      <RotateCcw size={14} /> {busy === 'flow-resume' ? 'RESUMING...' : 'RESUME PLAN'}
                    </button>
                    {canAttemptCancel && (
                      <button type="button" className={`${buttonStyle} border-error text-error`}
                        onClick={() => changeFlowPlanning('cancel')}
                        disabled={Boolean(busy) || !flowDetailsCurrent || engagementClosed || flowHasSubmittedWork ||
                          !['pending', 'running', 'paused'].includes(selectedFlow.status)}
                        title="Senior operator: irreversibly cancel pending plan steps, never active execution">
                        <Ban size={14} /> {busy === 'flow-cancel' ? 'CANCELLING...' : 'SENIOR: CANCEL PLAN'}
                      </button>
                    )}
                  </div>
                  {!canAttemptFlowControl && (
                    <p className="text-on-surface-variant text-[10px]">Flow planning controls require operator or senior_operator privileges.</p>
                  )}
                  {roleHint === 'operator' && (
                    <p className="text-on-surface-variant text-[10px]">Cancel requires senior_operator privileges. Pause and resume are available to operators.</p>
                  )}
                </div>
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
                  <form onSubmit={createObjective} className="space-y-2">
                    <label className="text-[11px] text-on-surface-variant">NEW TASK OBJECTIVE
                      <input className={inputStyle} value={newObjectiveTitle} onChange={(e) => setNewObjectiveTitle(e.target.value)}
                        maxLength={256} required placeholder="e.g. Validate scoped asset inventory" />
                    </label>
                    <button className={buttonStyle} disabled={Boolean(busy) || !newObjectiveTitle.trim() || isClosed}>
                      <Plus size={14} /> ADD OBJECTIVE
                    </button>
                  </form>
                  <div className="space-y-2">
                    <p className="font-label-caps text-on-surface-variant text-[11px]">PLANNED TASK OBJECTIVES ({objectives.length})</p>
                    <p className="text-on-surface-variant text-[11px]">
                      AI generation proposes up to 15 steps per flow for review. Proposals do not execute automatically.
                      Active steps still require operator dispatch and approval.
                    </p>
                    {objectives.length === 0 && <p className="text-on-surface-variant text-[12px]">Create an objective before adding subtasks.</p>}
                    <p className="text-on-surface-variant font-code-sm text-[10px]">
                      FLOW CAPACITY: {flowStepCount}/15 STEPS
                    </p>
                    {objectives.map((objective) => {
                      const existingSteps = detail?.subtasks.filter((step) => step.task_id === objective.id).length ?? 0;
                      const generationBusy = busy === `generate-${objective.id}`;
                      return (
                        <div key={objective.id} className="bg-surface-container-high border border-outline-variant p-3 text-[11px]">
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <div className="min-w-0">
                              <span className={statusColor(objective.status)}>{objective.status}</span> · {objective.payload?.title || objective.id}
                              <span className="block text-on-surface-variant font-code-sm break-all">{objective.id}</span>
                              <span className="block text-on-surface-variant">{existingSteps} proposed or existing step{existingSteps === 1 ? '' : 's'}</span>
                            </div>
                            <button type="button" className={buttonStyle}
                              aria-label={`Generate subtask proposals for ${objective.payload?.title || objective.id}`}
                              onClick={() => generateProposals(objective)}
                              disabled={Boolean(busy) || !authorizedScope || isClosed || !detail || existingSteps > 0 || flowStepCount >= 15}>
                              <Sparkles size={14} /> {generationBusy ? 'GENERATING...' : existingSteps > 0 ? 'ALREADY PLANNED' : 'GENERATE PROPOSALS'}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </Card>

              <Card title="Add bounded subtask">
                <form onSubmit={createSubtask} className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <label className="text-[11px] text-on-surface-variant">PARENT OBJECTIVE
                      <select className={inputStyle} aria-label="Parent objective" value={parentId}
                        onChange={(e) => { setParentId(e.target.value); setDependencies([]); }} required>
                        <option value="">Choose objective</option>
                        {objectives.map((objective) => (
                          <option key={objective.id} value={objective.id}>{objective.payload?.title || objective.id}</option>
                        ))}
                      </select>
                    </label>
                    <label className="text-[11px] text-on-surface-variant">TASK TYPE
                      <input className={inputStyle} value={subtaskType} maxLength={128} onChange={(e) => setSubtaskType(e.target.value)} required />
                    </label>
                    <label className="text-[11px] text-on-surface-variant">AGENT
                      <select className={inputStyle} value={subtaskAgent} onChange={(e) => setSubtaskAgent(e.target.value)}>
                        <option value="recon">Recon</option>
                        <option value="vuln_analysis">Vulnerability analysis</option>
                        <option value="reporting">Reporting</option>
                        <option value="human_oversight">Human oversight</option>
                        <option value="context_manager">Context manager</option>
                        <option value="payload_mutation">Payload mutation</option>
                        <option value="exploit_validation">Exploit validation</option>
                        <option value="attack_chain">Attack chain</option>
                        <option value="workflow">Workflow</option>
                        <option value="stateful_logic">Stateful logic</option>
                        <option value="visual_context">Visual context</option>
                        <option value="sast_analysis">Static analysis</option>
                        <option value="cloud_specialist">Cloud specialist</option>
                        <option value="concurrency">Concurrency</option>
                        <option value="nextjs_specialist">Next.js specialist</option>
                        <option value="react_specialist">React specialist</option>
                      </select>
                    </label>
                  </div>
                  <label className="block text-[11px] text-on-surface-variant">TITLE
                    <input className={inputStyle} value={subtaskTitle} maxLength={256} onChange={(e) => setSubtaskTitle(e.target.value)} required />
                  </label>
                  <label className="block text-[11px] text-on-surface-variant">DESCRIPTION
                    <textarea className={inputStyle} value={subtaskDescription} maxLength={4096} rows={2}
                      onChange={(e) => setSubtaskDescription(e.target.value)} />
                  </label>
                  {priorSubtasks.length > 0 && (
                    <fieldset className="border border-outline-variant p-3 text-[11px]">
                      <legend className="text-on-surface-variant">DEPEND ON EARLIER SUBTASKS (OPTIONAL)</legend>
                      <div className="flex flex-wrap gap-4">
                        {priorSubtasks.map((step) => (
                          <label key={step.id} className="flex gap-2 items-center">
                            <input type="checkbox" checked={dependencies.includes(step.id)}
                              onChange={(e) => setDependencies((current) => e.target.checked
                                ? [...current, step.id] : current.filter((id) => id !== step.id))} />
                            {step.title} ({step.status})
                          </label>
                        ))}
                      </div>
                    </fieldset>
                  )}
                  <label className="flex gap-2 text-[11px] items-center">
                    <input type="checkbox" checked={requiresApproval} onChange={(e) => setRequiresApproval(e.target.checked)} />
                    Require explicit approval (backend also enforces consequential-action gates)
                  </label>
                  <button className={buttonStyle} disabled={Boolean(busy) || !parentId || !subtaskTitle.trim() || isClosed}>
                    <Plus size={14} /> ADD PENDING SUBTASK
                  </button>
                </form>
              </Card>

              <Card title="Subtask status, revision and dispatch">
                {!authorizedScope && <p className="text-[11px] text-error mb-3">
                  <AlertTriangle size={14} className="inline mr-2" /> Engagement authorization reference or explicit targets are missing; execution controls are disabled.
                </p>}
                {(detail?.subtasks.length ?? 0) === 0 && (
                  <p className="text-[12px] text-on-surface-variant">No subtasks returned by the selected flow.</p>
                )}
                <div className="space-y-3">
                  {[...(detail?.subtasks ?? [])].sort((a, b) => a.order - b.order).map((step) => {
                    const isEditing = editing === step.id;
                    const dependencySteps = step.dependencies.map((id) =>
                      detail?.subtasks.find((prior) => prior.id === id && prior.task_id === step.task_id));
                    const blockers = dependencySteps.filter((dependency) => !dependency || dependency.status !== 'completed');
                    const canDispatch = step.status === 'pending' && blockers.length === 0;
                    const waitingApproval = flowApprovals.find((approval) => approval.task_id === step.execution_task_id);
                    return (
                      <div key={step.id} className="border border-outline-variant bg-surface-container-high/60 p-4">
                        <div className="flex justify-between gap-3 items-start">
                          <div className="min-w-0">
                            <p className="font-code-sm text-[13px]">{step.title}</p>
                            <p className="font-code-sm text-on-surface-variant text-[10px] break-all">{step.id} · {step.agent_type} · {step.task_type}</p>
                            <p className={`font-label-caps text-[10px] ${statusColor(step.status)}`}>{step.status}</p>
                            <p className="text-on-surface-variant text-[11px] mt-1">{step.description || 'No description'}</p>
                            {step.dependencies.length > 0 && (
                              <div className="mt-2 text-[10px] text-on-surface-variant">
                                <p>Dependencies ({step.dependencies.length - blockers.length}/{step.dependencies.length} completed):</p>
                                <ul className="mt-1 space-y-1">
                                  {step.dependencies.map((id, index) => {
                                    const dependency = dependencySteps[index];
                                    return (
                                      <li key={id} className="flex flex-wrap items-center gap-1">
                                        {dependency?.status === 'completed' ?
                                          <CheckCircle2 size={12} className="text-primary-fixed" /> : <Clock3 size={12} className="text-secondary" />}
                                        <span>{dependency?.title || id}</span>
                                        <span className={statusColor(dependency?.status || 'missing')}>
                                          ({dependency?.status || 'missing — refresh or inspect flow'})
                                        </span>
                                      </li>
                                    );
                                  })}
                                </ul>
                              </div>
                            )}
                            {step.execution_task_id && <p className="text-[10px] text-secondary">Execution: {step.execution_task_id}</p>}
                            {step.approval_required && (
                              <p className="text-[10px] text-secondary">
                                {waitingApproval ? `Senior-operator approval pending: ${waitingApproval.id}` :
                                  'Requires separate senior-operator approval after dispatch if the task is gated.'}
                              </p>
                            )}
                            {step.status === 'pending' && blockers.length > 0 && (
                              <p className="text-error text-[10px] mt-1" role="status">
                                Cannot dispatch: {blockers.length} prerequisite{blockers.length === 1 ? '' : 's'} not completed.
                              </p>
                            )}
                            {step.status === 'completed' && (
                              <p className="text-on-surface-variant text-[10px]">
                                Generator/Refiner passes: {step.refinement_count ?? 0}/3
                              </p>
                            )}
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            {step.status === 'pending' && !isEditing && (
                              <button type="button" className={buttonStyle}
                                onClick={() => { setEditing(step.id); setEditTitle(step.title); setEditDescription(step.description); }}>
                                REVISE
                              </button>
                            )}
                            {step.status === 'completed' && (
                              <button type="button" className={buttonStyle}
                                aria-label={`Refine proposals after ${step.title}`}
                                onClick={() => refineProposals(step)}
                                disabled={Boolean(busy) || !authorizedScope || isClosed || (step.refinement_count ?? 0) >= 3}
                                title={(step.refinement_count ?? 0) >= 3 ? 'Maximum of three refinements reached' : 'Propose additional pending steps from this completed subtask'}>
                                <Sparkles size={14} /> {busy === `refine-${step.id}` ? 'REFINING...' : (step.refinement_count ?? 0) >= 3 ? 'REFINEMENT LIMIT (3/3)' : `REFINE PROPOSALS (${step.refinement_count ?? 0}/3)`}
                              </button>
                            )}
                          </div>
                        </div>
                        {isEditing && (
                          <div className="space-y-2 mt-3">
                            <input aria-label="Revised title" className={inputStyle} value={editTitle} maxLength={256} onChange={(e) => setEditTitle(e.target.value)} />
                            <textarea aria-label="Revised description" className={inputStyle} value={editDescription} maxLength={4096}
                              onChange={(e) => setEditDescription(e.target.value)} />
                            <div className="flex gap-2">
                              <button type="button" className={buttonStyle} onClick={() => revise(step)} disabled={Boolean(busy) || !editTitle.trim()}>
                                <Save size={14} /> SAVE REVISION
                              </button>
                              <button type="button" className={buttonStyle} onClick={() => setEditing('')} disabled={Boolean(busy)}>CANCEL</button>
                            </div>
                          </div>
                        )}
                        {step.status === 'pending' && (
                          <div className="mt-3 pt-3 border-t border-outline-variant flex flex-wrap items-end gap-3">
                            <label className="text-[10px] text-on-surface-variant flex-1 min-w-[200px]">AUTHORIZED TARGET (FOR RECON/ANALYSIS)
                              <input aria-label={`Dispatch target for ${step.title}`} className={inputStyle}
                                value={targets[step.id] ?? ''} onChange={(e) => setTargets((current) => ({ ...current, [step.id]: e.target.value }))}
                                placeholder={selectedEngagement?.scope.domains?.[0] || 'Scoped hostname or URL'} />
                            </label>
                            <label className="text-[10px] text-on-surface-variant">PRIORITY (1–10)
                              <input aria-label={`Dispatch priority for ${step.title}`} className={inputStyle} type="number" min={1} max={10}
                                value={priorities[step.id] ?? 5} onChange={(e) => setPriorities((current) =>
                                  ({ ...current, [step.id]: Number(e.target.value) }))} />
                            </label>
                            <button className={buttonStyle} type="button" onClick={() => dispatch(step)}
                              disabled={Boolean(busy) || !authorizedScope || isClosed || !canDispatch}>
                              <Play size={14} /> DISPATCH SUBTASK
                            </button>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </Card>

              <Card title="Pending approvals for this flow">
                <p className="text-on-surface-variant text-[11px] mb-3">
                  Requests come from the authenticated approval API and are matched to persisted execution task IDs. 
                  Only senior operators can approve or reject; authorization is checked on the server.
                </p>
                {approvalsError && (
                  <p role="alert" className="text-error text-[11px] mb-3">Approval requests unavailable: {approvalsError}</p>
                )}
                {readyApprovalsError && (
                  <p role="alert" className="text-error text-[11px] mb-3">Approved planner continuation list unavailable: {readyApprovalsError}. Generic pending approvals remain separate.</p>
                )}
                {!approvalsError && flowApprovals.length === 0 && (
                  <p className="text-on-surface-variant text-[11px]">No pending approval requests linked to this flow.</p>
                )}
                {!approvalsError && unmappedApprovalCount > 0 && (
                  <p className="text-on-surface-variant text-[10px] mb-3">
                    {unmappedApprovalCount} additional pending engagement request{unmappedApprovalCount === 1 ? '' : 's'} 
                    not linked to this flow. This panel does not authorize unrelated tasks.
                  </p>
                )}
                {canAttemptApproval && flowApprovals.length > 0 && (
                  <p className="mb-3 text-[11px] text-on-surface-variant">
                    Verified senior operator: <span className="font-code-sm">{verifiedApprover?.sub}</span>
                  </p>
                )}
                <div className="space-y-3">
                  {flowApprovals.map((approval) => (
                    <div key={approval.id} className="border border-outline-variant p-3 text-[11px]">
                      <div className="flex flex-wrap justify-between gap-3">
                        <div className="min-w-0">
                          <p className="font-code-sm break-all">{approval.id} · {approval.action_type}</p>
                          <p className="text-on-surface-variant break-all">Task: {approval.task_id}</p>
                          <p className="text-on-surface-variant break-all">Target: {approval.target || 'Not specified'}</p>
                          <p className="text-secondary">Risk: {approval.risk_assessment} · Status: pending</p>
                          <p className="text-on-surface-variant">Requested: {displayTime(approval.requested_at)}</p>
                          {approval.action_type === 'planner_inference' && (
                            <p className="text-on-surface-variant">
                              INTERNAL PLANNER — authorization v{approval.authorization_version ?? 'unverified'},
                              Flow revision {approval.flow_revision ?? 'unknown'}.
                              Approval alone does not start a model call.
                              {approval.flow_revision_current === false && ' The Flow revision/status has changed: review is blocked.'}
                            </p>
                          )}
                        </div>
                        <span className="text-secondary font-label-caps">WAITING FOR DECISION</span>
                      </div>
                      {canAttemptApproval && (
                        <div className="mt-3 border-t border-outline-variant pt-3 space-y-2">
                          <label className="block text-on-surface-variant">DECISION NOTES (REQUIRED FOR REJECTION)
                            <textarea className={inputStyle} rows={2} maxLength={1000}
                              aria-label={`Approval notes for ${approval.id}`}
                              value={approvalNotes[approval.id] ?? ''}
                              onChange={(event) => setApprovalNotes((current) =>
                                ({ ...current, [approval.id]: event.target.value }))} />
                          </label>
                          <div className="flex flex-wrap gap-2">
                            <button type="button" className={buttonStyle} onClick={() => decideApproval(approval, 'approved')}
                              disabled={Boolean(busy) || isClosed || (approval.action_type === 'planner_inference' &&
                                (!Number.isInteger(approval.authorization_version) || !Number.isInteger(approval.flow_revision)
                                  || approval.flow_revision_current !== true))}>
                              <CheckCircle2 size={14} /> {busy === `approval-${approval.id}` ? 'PROCESSING...' : 'APPROVE'}
                            </button>
                            <button type="button" className={buttonStyle} onClick={() => decideApproval(approval, 'rejected')}
                              disabled={Boolean(busy) || isClosed || !approvalNotes[approval.id]?.trim() ||
                                (approval.action_type === 'planner_inference' &&
                                  (!Number.isInteger(approval.authorization_version) || !Number.isInteger(approval.flow_revision)
                                    || approval.flow_revision_current !== true))}>
                              <XCircle size={14} /> REJECT
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                {readyFlowApprovals.length > 0 && (
                  <div className="mt-4 space-y-3 border-t border-outline-variant pt-3">
                    <p className="text-[11px] text-secondary">
                      Approved internal planning requests are still parked. A separate, explicit continuation is required
                      and will recheck authorization before any model tokens are spent.
                    </p>
                    {readyFlowApprovals.map((approval) => (
                      <div key={approval.id} className="border border-outline-variant p-3 text-[11px]">
                        <p className="font-code-sm break-all">{approval.id} · HUMAN APPROVED / NOT EXECUTED</p>
                        <p className="text-on-surface-variant">Purpose: {approval.planner_purpose} · signed v{approval.authorization_version}, Flow revision {approval.flow_revision}</p>
                        <p className="text-on-surface-variant break-all">Planner task: {approval.task_id}</p>
                        {approval.flow_revision_current === false && (
                          <p role="alert" className="text-error">Flow changed or was paused; authorization must be reviewed again. This request cannot resume.</p>
                        )}
                        {approval.planner_purpose === 'adaptive_planning' && (
                          <p className="text-on-surface-variant">Adaptive continuation needs a dedicated authenticated endpoint. The signed proposal-only route below meets this requirement; no agent is scheduled.</p>
                        )}
                          <button type="button" className={`${buttonStyle} mt-2`}
                            onClick={() => resumeApprovedPlanner(approval)}
                            disabled={Boolean(busy) || isClosed || !authorizedScope || approval.flow_revision_current !== true ||
                              (approval.planner_purpose === 'adaptive_planning' && !canAttemptApproval)}
                            title="Recheck signed authorization, claim this approved planner once, and return a proposal for review">
                            <Sparkles size={14} /> {busy === `planner-resume-${approval.id}` ? 'RESUMING...' : approval.planner_purpose === 'adaptive_planning' ? 'PROPOSE ADAPTIVE NEXT STEP (SENIOR)' : 'RESUME APPROVED PLANNER'}
                          </button>
                      </div>
                    ))}
                  </div>
                )}
                {adaptiveProposalsError && (
                  <p role="alert" className="text-error text-[11px] mt-2">Persisted adaptive proposals unavailable: {adaptiveProposalsError}. No model retry has been attempted.</p>
                )}
                {Object.entries(adaptiveProposals).filter(([, result]) => result.flow_id === flowId).map(([approvalId, result]) => (
                  <div key={approvalId} className="mt-3 border border-outline-variant p-3 space-y-2 text-[11px]" role="status">
                    <p className="font-code-sm">ADAPTIVE PROPOSAL ONLY · HUMAN REVIEW REQUIRED</p>
                    <p className="text-on-surface-variant break-all">Approval: {approvalId} · Planner: {result.planner_task_id}</p>
                    <p>Action: {result.proposal.action} · Flow revision: {result.flow_revision}</p>
                    {result.proposal.parameters.target && <p className="break-all">Suggested scoped target: {result.proposal.parameters.target}</p>}
                    {result.proposal.parameters.statement && <p>Suggested hypothesis: {result.proposal.parameters.statement}</p>}
                    <p>No agent, scan or follow-up task has been scheduled. Review and create a separately approved Flow step if appropriate.</p>
                    {result.proposal.action === 'request_sub_recon' && (
                      <button type="button" className={buttonStyle}
                        disabled={Boolean(busy) || !canAttemptApproval || !authorizedScope || isClosed ||
                          result.flow_revision !== selectedFlow?.revision ||
                          !Number.isInteger(result.authorization_version) || confirmedAdaptiveFollowups[approvalId] != null}
                        onClick={() => confirmAdaptiveFollowup(result)}>
                        <CheckCircle2 size={14} /> {busy === `adaptive-confirm-${approvalId}` ? 'PERSISTING...' : 'SENIOR: CONFIRM & PREPARE FOLLOW-UP PLAN'}
                      </button>
                    )}
                    {confirmedAdaptiveFollowups[approvalId] && (
                      <p className="text-secondary break-all">PENDING DISPATCH REVIEW — objective {confirmedAdaptiveFollowups[approvalId].objective_task_id}, subtask {confirmedAdaptiveFollowups[approvalId].subtask_id}. Execution not started.</p>
                    )}
                  </div>
                ))}
                <button type="button" className={`${buttonStyle} mt-3`}
                  onClick={() => void refreshApprovals()} disabled={Boolean(busy)}>
                  <RefreshCw size={13} /> REFRESH PENDING APPROVALS
                </button>
              </Card>

              <Card title="Persisted execution actions">
                {actions === null ? (
                  <p className="text-on-surface-variant text-[11px]">Action history unavailable or loading.</p>
                ) : actions.length === 0 ? (
                  <p className="text-on-surface-variant text-[11px]">No correlated action records were returned for this flow.</p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {actions.map((action) => (
                      <div key={action.id} className="border border-outline-variant p-3 text-[11px] font-code-sm">
                        <div className="flex flex-wrap justify-between gap-2">
                          <span>{action.tool_name}</span>
                          <span className={statusColor(action.outcome)}>{action.outcome}</span>
                        </div>
                        <p className="text-on-surface-variant mt-1">
                          {displayTime(action.created_at)} · {action.duration_ms == null ? 'Duration unavailable' : `${action.duration_ms} ms`}
                          {action.task_id ? ` · ${action.task_id}` : ''}
                        </p>
                        {(action.safe_metadata?.model || action.safe_metadata?.input_tokens != null || action.safe_metadata?.cost_usd != null) && (
                          <p className="text-on-surface-variant">
                            {action.safe_metadata.model ? `Model ${action.safe_metadata.model} · ` : ''}
                            {action.safe_metadata.input_tokens != null ? `Input ${action.safe_metadata.input_tokens} · ` : ''}
                            {action.safe_metadata.output_tokens != null ? `Output ${action.safe_metadata.output_tokens} · ` : ''}
                            {action.safe_metadata.cost_usd != null ? `Reported billed USD ${action.safe_metadata.cost_usd}` : 'Cost unavailable'}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </>
          )}

          <SupervisionPanel
            engagementId={engagementId}
            tasks={diagnostics?.tasks.items ?? []}
            canControl={canAttemptFlowControl && !engagementClosed}
          />
          <SignedReportOperatorPanel key={`signed-human-report-${engagementId}`} engagementId={engagementId} />
          <Card title="Engagement diagnostics — live tasks and durable audit">
            {diagnosticsError && <p role="alert" className="text-error text-[11px] mb-3">Diagnostics unavailable: {diagnosticsError}</p>}
            {!diagnostics ? (
              <p className="text-on-surface-variant text-[12px]">No diagnostics returned by the API.</p>
            ) : (
              <div className="space-y-4">
                <p className="text-on-surface-variant text-[11px]">
                  <Activity size={14} className="inline mr-2" />
                  Captured {displayTime(diagnostics.captured_at)} · {diagnostics.phase} · Task source: {diagnostics.tasks.source}
                </p>
                <div className="flex flex-wrap gap-3">
                  <div className="border border-outline-variant p-3 text-[12px]">
                    <span className="text-primary-fixed font-code-sm text-[20px]">{diagnostics.tasks.total}</span>
                    <p className="text-on-surface-variant text-[10px]">LIVE TASKS IN MEMORY</p>
                  </div>
                  <div className="border border-outline-variant p-3 text-[12px]">
                    <span className="text-secondary font-code-sm text-[20px]">{diagnostics.tasks.retried}</span>
                    <p className="text-on-surface-variant text-[10px]">RETRIED TASKS</p>
                  </div>
                  <div className="border border-outline-variant p-3 text-[12px]">
                    <span className="text-error font-code-sm text-[20px]">{diagnostics.tasks.overdue_running}</span>
                    <p className="text-on-surface-variant text-[10px]">RUNNING BEYOND TIMEOUT</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-3 text-[11px] font-code-sm">
                  {Object.entries(diagnostics.tasks.status_counts).map(([status, count]) => (
                    <span className="border border-outline-variant px-3 py-1" key={status}>{status}: {count}</span>
                  ))}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[11px]">
                    <thead className="border-b border-outline text-on-surface-variant">
                      <tr><th className="p-2">TASK</th><th className="p-2">STATUS</th><th className="p-2">RETRIES</th><th className="p-2">RUNTIME</th></tr>
                    </thead>
                    <tbody>
                      {diagnostics.tasks.items.map((task) => (
                        <tr key={task.task_id} className="border-b border-outline-variant">
                          <td className="p-2 font-code-sm">{task.task_id}<span className="block text-on-surface-variant">{task.task_type}</span></td>
                          <td className={`p-2 ${task.overdue ? 'text-error' : statusColor(task.status)}`}>{task.status}{task.overdue ? ' · overdue' : ''}</td>
                          <td className="p-2">{task.retry_count}/{task.max_retries}</td>
                          <td className="p-2">{task.running_seconds == null ? '—' : `${task.running_seconds} s`}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {diagnostics.tasks.truncated && <p className="text-on-surface-variant text-[10px] mt-2">Additional task rows omitted by API limit.</p>}
                </div>
                <div className="border-t border-outline-variant pt-4">
                  <h3 className="font-label-caps text-on-surface-variant text-[11px] mb-2 flex items-center gap-2">
                    <ClipboardList size={14} /> RECENT AUDIT EVENTS ({diagnostics.audit.events_returned})
                  </h3>
                  {!diagnostics.audit.available && <p className="text-error text-[11px]">Audit database unavailable. Live task values are separate.</p>}
                  {diagnostics.audit.available && diagnostics.audit.events.length === 0 && (
                    <p className="text-on-surface-variant text-[11px]">No persisted audit events returned.</p>
                  )}
                  <div className="max-h-64 overflow-y-auto space-y-2">
                    {diagnostics.audit.events.map((event) => (
                      <div key={event.event_id} className="bg-surface-container-high p-2 text-[11px] flex flex-wrap justify-between gap-2">
                        <span className="font-code-sm">{event.event_type} · {event.actor_type}/{event.actor_id}
                          {event.task_id && <span className="block text-on-surface-variant">{event.task_id}</span>}
                        </span>
                        <span className="text-on-surface-variant">{displayTime(event.timestamp)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
