import { useEffect, useRef, useState, type FormEvent } from 'react';

import { currentOperator, subscribeOperator } from '../../services/api';
import type { Engagement, FlowRecord } from '../../services/flows';
import {
  loadSignedReplayComparison,
  loadWorkflowReplaySources,
  submitWorkflowReplay,
  validateReplayInput,
  verifyReplayProposal,
  type WorkflowReplayInput,
  type SignedReplayComparison,
  type WorkflowReplaySourceCatalog,
} from '../../services/signedReplay';
import { Card } from '../shared/Card';
import { TargetAuthorityReviewPanel } from './TargetAuthorityReviewPanel';

type Fields = Pick<WorkflowReplayInput,
  'workflowId' | 'sourceTaskId' | 'sourceUserLabel' | 'targetUserLabel'>;

interface SignedWorkflowReplayPanelProps {
  engagement: Engagement | null;
  flow: FlowRecord | null;
  disabled?: boolean;
  onProposed?: () => void;
}

const fieldStyle =
  'w-full min-w-0 border border-outline-variant bg-background px-3 py-2 text-[12px] text-on-surface font-code-sm';
const buttonStyle =
  'inline-flex items-center gap-2 border border-outline px-3 py-2 text-[11px] font-label-caps text-on-surface hover:bg-surface-container-high disabled:opacity-40 disabled:cursor-not-allowed';

/** Senior-only proposal control. All four editable values are operator
 * supplied, verified against the original PostgreSQL map_workflow source.
 * No user labels, workflow identifiers or authorization versions are inferred.
 */
export function SignedWorkflowReplayPanel({
  engagement, flow, disabled = false, onProposed,
}: SignedWorkflowReplayPanelProps) {
  const [role, setRole] = useState(() => currentOperator()?.role ?? '');
  const [fields, setFields] = useState<Fields>({
    workflowId: '', sourceTaskId: '', sourceUserLabel: '', targetUserLabel: '',
  });
  const [catalog, setCatalog] = useState<WorkflowReplaySourceCatalog | null>(null);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState('');
  const [verified, setVerified] = useState<WorkflowReplayInput | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [receiptTaskId, setReceiptTaskId] = useState('');
  const [outcomeUnknown, setOutcomeUnknown] = useState(false);
  const [reviewTaskId, setReviewTaskId] = useState('');
  const [comparisonStepId, setComparisonStepId] = useState('');
  const [comparison, setComparison] = useState<SignedReplayComparison | null>(null);
  const [reviewBusy, setReviewBusy] = useState(false);
  const guard = useRef(false);
  const submitted = useRef(false);

  useEffect(() => subscribeOperator((identity) => {
    setRole(identity?.role ?? '');
    setVerified(null);
    setConfirmed(false);
  }), []);

  useEffect(() => {
    // Parent Flow/engagement may change while a user is reviewing.
    setVerified(null);
    setConfirmed(false);
    setReceiptTaskId('');
    setError('');
    setOutcomeUnknown(false);
    setReviewTaskId('');
    setComparisonStepId('');
    setComparison(null);
    submitted.current = false;
  }, [engagement?.session_id, flow?.id, flow?.revision, flow?.status]);

  useEffect(() => {
    let active = true;
    setCatalog(null);
    setCatalogError('');
    setFields({ workflowId: '', sourceTaskId: '', sourceUserLabel: '', targetUserLabel: '' });
    setVerified(null);
    setConfirmed(false);
    if (!engagement || !flow || role !== 'senior_operator'
        || currentOperator()?.role !== 'senior_operator'
        || flow.engagement_id !== engagement.session_id
        || !['pending', 'running'].includes(flow.status)) return;
    setCatalogLoading(true);
    void loadWorkflowReplaySources(engagement.session_id, flow.id).then(result => {
      if (!active) return;
      if (result.flow_revision !== flow.revision) {
        throw new Error('Flow revision changed. Refresh the selected Flow before proposing.');
      }
      setCatalog(result);
    }).catch(cause => {
      if (active) setCatalogError(
        cause instanceof Error ? cause.message : 'Signed workflow sources could not be verified.',
      );
    }).finally(() => {
      if (active) setCatalogLoading(false);
    });
    return () => { active = false; };
  }, [role, engagement?.session_id, flow?.id, flow?.revision, flow?.status]);

  const senior = role === 'senior_operator' && currentOperator()?.role === 'senior_operator';
  const active = Boolean(engagement && flow
    && engagement.session_id === flow.engagement_id
    && !['halted', 'completed'].includes(engagement.phase)
    && ['pending', 'running'].includes(flow.status)
    && Number.isSafeInteger(flow.revision) && flow.revision >= 0);
  const localFields = {
    engagementId: engagement?.session_id ?? '',
    flowId: flow?.id ?? '',
    expectedFlowRevision: flow?.revision ?? -1,
    expectedAuthorizationVersion: verified?.expectedAuthorizationVersion ?? 0,
    ...fields,
  };
  const validFields = Boolean(catalog
    && catalog.flow_id === flow?.id
    && catalog.flow_revision === flow?.revision
    && catalog.sources.some(source => source.source_task_id === fields.sourceTaskId
      && source.workflow_id === fields.workflowId
      && source.source_user_label === fields.sourceUserLabel)
    && catalog.identities.includes(fields.sourceUserLabel)
    && catalog.identities.includes(fields.targetUserLabel))
    && !validateReplayInput({
    ...localFields, expectedAuthorizationVersion: 1,
    });
  const matchingProof = Boolean(
    verified && validFields
    && verified.engagementId === engagement?.session_id
    && verified.flowId === flow?.id
    && verified.expectedFlowRevision === flow?.revision
    && verified.workflowId === fields.workflowId
    && verified.sourceTaskId === fields.sourceTaskId
    && verified.sourceUserLabel === fields.sourceUserLabel
    && verified.targetUserLabel === fields.targetUserLabel,
  );

  function selectSource(sourceTaskId: string) {
    const source = catalog?.sources.find(item => item.source_task_id === sourceTaskId);
    setFields({
      sourceTaskId: source?.source_task_id ?? '',
      workflowId: source?.workflow_id ?? '',
      sourceUserLabel: source?.source_user_label ?? '',
      targetUserLabel: '',
    });
    setVerified(null);
    setConfirmed(false);
    setError('');
  }

  function selectTarget(targetUserLabel: string) {
    setFields(previous => ({ ...previous, targetUserLabel }));
    setVerified(null);
    setConfirmed(false);
    setError('');
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (guard.current || disabled || !senior || !active || !validFields
      || !engagement || !flow || submitted.current) return;
    guard.current = true;
    setBusy(true);
    setVerified(null);
    setConfirmed(false);
    setError('');
    try {
      const evidence = await verifyReplayProposal(engagement, flow, fields);
      if (currentOperator()?.role !== 'senior_operator') throw new Error('Senior operator session changed.');
      setVerified(evidence);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Workflow replay evidence could not be verified.');
    } finally {
      guard.current = false;
      setBusy(false);
    }
  }

  async function propose() {
    if (guard.current || submitted.current || disabled || !senior
      || !active || !matchingProof || !confirmed || !verified || !engagement) return;
    guard.current = true;
    submitted.current = true; // One submission: a lost response may have admitted a TaskORM.
    setBusy(true);
    setError('');
    setOutcomeUnknown(false);
    try {
      const receipt = await submitWorkflowReplay(engagement, verified);
      setReceiptTaskId(receipt.task_id);
      setReviewTaskId(receipt.task_id);
      onProposed?.();
    } catch (cause) {
      setOutcomeUnknown(true);
      setError(
        (cause instanceof Error ? cause.message : 'The proposal outcome could not be confirmed.')
        + ' The request may have committed. Inspect the authoritative task and approval inbox before attempting another proposal.',
      );
    } finally {
      setBusy(false);
      guard.current = false;
    }
  }

  async function reviewComparison() {
    if (guard.current || reviewBusy || disabled || !senior || !active
      || !engagement || !flow || !fields.workflowId) return;
    setReviewBusy(true);
    setComparison(null);
    setError('');
    try {
      const observed = await loadSignedReplayComparison(
        engagement.session_id, fields.workflowId, flow.id,
        reviewTaskId, comparisonStepId,
      );
      if (currentOperator()?.role !== 'senior_operator') {
        throw new Error('Senior operator session changed.');
      }
      setComparison(observed);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Signed comparison evidence unavailable.');
    } finally {
      setReviewBusy(false);
    }
  }

  return (
    <Card title="Signed workflow differential replay — proposal only">
      <div className="space-y-3 text-[11px] text-on-surface-variant" data-testid="signed-workflow-replay">
        <p>
          Senior operator review stages a separate, signed replay Task for human execution approval.
          No browser navigation, finding validation or autonomous replay is triggered here.
          Remote effects remain UNKNOWN until independently reconciled. Verified findings: none.
        </p>
        {!senior && (
          <p role="status">A currently verified senior_operator identity is required for replay proposals.</p>
        )}
        {!active && <p role="status">Select an active, confirmed Flow and authorized engagement to continue.</p>}
        <p className="font-code-sm break-all">
          Flow: {flow?.id || 'unavailable'} · Current revision: {Number.isSafeInteger(flow?.revision) ? flow?.revision : 'unverified'}
          {' '}· Engagement: {engagement?.session_id || 'unavailable'}
        </p>
        {catalogError && <p role="alert" className="text-error">{catalogError}</p>}
        {catalogLoading && <p role="status">Loading signed workflow sources from PostgreSQL…</p>}
        {catalog && catalog.sources.length === 0 && (
          <p role="status">No eligible completed signed map_workflow source was found in this Flow.</p>
        )}
        <form onSubmit={(event) => void verify(event)} className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="min-w-0 text-[11px] text-on-surface-variant">
            VERIFIED COMPLETED MAP_WORKFLOW SOURCE
            <select className={fieldStyle} aria-label="Verified workflow source"
              value={fields.sourceTaskId} onChange={event => selectSource(event.target.value)}
              disabled={busy || submitted.current || disabled || !senior || !catalog} required>
              <option value="">Choose original signed source</option>
              {catalog?.sources.map(source => (
                <option value={source.source_task_id} key={source.source_task_id}>
                  {source.source_task_id} · {source.workflow_id} · {source.source_user_label}
                </option>
              ))}
            </select>
          </label>
          <label className="min-w-0 text-[11px] text-on-surface-variant">
            DISTINCT VERIFIED TARGET IDENTITY
            <select className={fieldStyle} aria-label="Verified target identity"
              value={fields.targetUserLabel} onChange={event => selectTarget(event.target.value)}
              disabled={busy || submitted.current || disabled || !senior || !fields.sourceTaskId} required>
              <option value="">Choose an imported authenticated identity</option>
              {catalog?.identities.filter(label => label !== fields.sourceUserLabel).map(label => (
                <option value={label} key={label}>{label}</option>
              ))}
            </select>
          </label>
          {fields.sourceTaskId && (
            <p className="md:col-span-2 font-code-sm break-all">
              Selected original workflow {fields.workflowId}; source identity {fields.sourceUserLabel}.
              {' '}Catalog authorization v{catalog?.authorization_version ?? 'unverified'}.
            </p>
          )}
          <div className="md:col-span-2 flex flex-wrap items-center gap-3">
            <button type="submit" className={buttonStyle} disabled={
              busy || catalogLoading || disabled || !senior || !active || !validFields || submitted.current
            }>
              {busy ? 'VERIFYING / SUBMITTING...' : 'VERIFY SIGNED WORKFLOW SOURCE'}
            </button>
            {matchingProof && verified && (
              <span role="status" className="text-primary-fixed">
                Verified source · authorization v{verified.expectedAuthorizationVersion} · Flow revision {verified.expectedFlowRevision}
              </span>
            )}
          </div>
        </form>
        {matchingProof && !submitted.current && (
          <label className="flex items-start gap-2 text-on-surface">
            <input type="checkbox" checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)} disabled={busy || disabled} />
            I confirm these two identity labels, signed source Task, workflow and Flow revision.
            This only requests separate human execution approval.
          </label>
        )}
        <button type="button" className={buttonStyle} onClick={() => void propose()}
          disabled={busy || disabled || !senior || !active || !matchingProof || !confirmed || submitted.current}>
          SENIOR: PROPOSE DIFFERENTIAL REPLAY
        </button>
        {receiptTaskId && (
          <p role="status" className="text-primary-fixed">
            Awaiting SEPARATE human execution approval for Task {receiptTaskId}.
            Execution started: no. Remote effect: UNKNOWN. Verified findings: none.
          </p>
        )}
        <section aria-label="Signed differential evidence comparison" className="space-y-2 border-t border-outline-variant pt-3">
          <p className="font-label-caps text-on-surface">Read-only signed comparison · no finding promotion</p>
          <p>
            After BOTH source and target GET tasks receive separate human execution approval and
            signed terminal receipts, inspect their exact workflow Step. This never performs HTTP
            replay. Matching provider responses are NOT independent ownership proof.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <label>
              APPROVED REPLAY PARENT TASK ID
              <input className={fieldStyle} value={reviewTaskId}
                onChange={event => { setReviewTaskId(event.target.value); setComparison(null); }}
                placeholder="task-…" aria-label="Original signed replay parent task"
                disabled={reviewBusy || disabled || !senior} />
            </label>
            <label>
              ORIGINAL WORKFLOW STEP ID
              <input className={fieldStyle} value={comparisonStepId}
                onChange={event => { setComparisonStepId(event.target.value); setComparison(null); }}
                placeholder="step-…" aria-label="Approved workflow step"
                disabled={reviewBusy || disabled || !senior} />
            </label>
          </div>
          <button type="button" className={buttonStyle} onClick={() => void reviewComparison()}
            disabled={reviewBusy || disabled || !senior || !active
              || !/^task-[A-Za-z0-9._-]{1,78}$/.test(reviewTaskId)
              || !/^step-[A-Za-z0-9._-]{1,80}$/.test(comparisonStepId)
              || !fields.workflowId}>
            {reviewBusy ? 'READING SIGNED PG EVIDENCE…' : 'READ APPROVED SOURCE / TARGET COMPARISON'}
          </button>
          {comparison && (
            <p role="status" data-testid="signed-replay-comparison">
              Comparison: {comparison.status.replace(/_/g, ' ')} ·
              Source observed: {String(comparison.source_observed)} ·
              Target observed: {String(comparison.target_observed)} ·
              Reason: {comparison.reason.replace(/_/g, ' ')}.
              Provider testimony only. Independently verified vulnerability: NO.
              Verified findings: 0. External target effect: UNKNOWN.
            </p>
          )}
        </section>
        <TargetAuthorityReviewPanel engagement={engagement} flow={flow} disabled={disabled} />
        {outcomeUnknown && (
          <p role="status" className="text-secondary">
            Proposal/remote effect UNKNOWN. Automatic retry disabled. Check durable TaskORM and approval state.
          </p>
        )}
        {error && <p role="alert" className="text-error">{error}</p>}
      </div>
    </Card>
  );
}
