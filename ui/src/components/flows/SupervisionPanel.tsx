import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AlertTriangle, Clock3, RefreshCw, ShieldAlert } from 'lucide-react';
import { Card } from '../shared/Card';
import { DurableSupervisionSubscribersPanel } from './DurableSupervisionSubscribersPanel';
import { supervisionApi, streamSupervisionEvents, assertRevokeAuthorizationInput, type AuthorizationStatus, type AuthorizationRevocation, type ExecutionAttempt, type ExecutionControl, type PersistedSupervisionTask, type SupervisionEvent, type SupervisionMessage, type TerminalCallback, type ModelUsageSummary, type OpenAIProjectCostsObservation, type MCPDispatchReceipt, type TemporalObservation, type UnreconciledModelCall } from '../../services/supervision';
import type { TaskDiagnostic } from '../../services/flows';
import { FlowApiError, operatorRoleHint } from '../../services/flows';

const controlStyle = 'border border-outline px-3 py-2 text-[11px] hover:bg-surface-container-high disabled:opacity-40';

function time(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

type Props = {
  engagementId: string;
  tasks: TaskDiagnostic[];
  canControl: boolean;
};

/**
 * Read-only by default. Mutations are delivered to authenticated APIs and
 * display only persisted outcomes, not locally inferred worker state.
 */
export function SupervisionPanel({ engagementId, tasks, canControl }: Props) {
  const [taskId, setTaskId] = useState('');
  const [events, setEvents] = useState<SupervisionEvent[]>([]);
  const [attempts, setAttempts] = useState<ExecutionAttempt[]>([]);
  const [mcpDispatches, setMcpDispatches] = useState<MCPDispatchReceipt[]>([]);
  const [temporalObservation, setTemporalObservation] = useState<TemporalObservation | null>(null);
  const [terminalCallbacks, setTerminalCallbacks] = useState<TerminalCallback[]>([]);
  const [control, setControl] = useState<ExecutionControl | null>(null);
  const [messages, setMessages] = useState<SupervisionMessage[]>([]);
  const [modelUsage, setModelUsage] = useState<ModelUsageSummary | null>(null);
  const [providerCosts, setProviderCosts] = useState<OpenAIProjectCostsObservation | null>(null);
  const [providerCostsError, setProviderCostsError] = useState('');
  const [providerCostsLoading, setProviderCostsLoading] = useState(false);
  const providerCostsEpoch = useRef(0);
  const [unreconciledModelCalls, setUnreconciledModelCalls] = useState<UnreconciledModelCall[]>([]);
  const [authorization, setAuthorization] = useState<AuthorizationStatus | null>(null);
  const [authorizationError, setAuthorizationError] = useState('');
  const [revokeReason, setRevokeReason] = useState('');
  const [revokeResult, setRevokeResult] = useState<AuthorizationRevocation | null>(null);
  const [persistedTasks, setPersistedTasks] = useState<PersistedSupervisionTask[] | null>(null);
  const [reason, setReason] = useState('');
  const [operatorInput, setOperatorInput] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [liveState, setLiveState] = useState<'connecting' | 'live' | 'reconnecting'>('connecting');
  const latestSequence = useRef(0);
  const temporalObservationRevision = useRef(0);
  const chainId = taskId ? 'supervision-' + taskId : '';
  const visibleTasks = persistedTasks ?? tasks;
  const currentTask = visibleTasks.find((task) => task.task_id === taskId);
  // An untrusted JWT role is only a display hint. Backend always enforces
  // authenticated senior_operator role and authoritative PostgreSQL ownership.
  const seniorRoleHint = operatorRoleHint() === 'senior_operator';

  const refresh = useCallback(async () => {
    if (!engagementId) return;
    const selected = taskId;
    const requests = await Promise.allSettled([
      supervisionApi.events(engagementId, selected || undefined),
      selected ? supervisionApi.attempts(engagementId, selected) : Promise.resolve({ attempts: [] }),
      selected ? supervisionApi.control(engagementId, selected) : Promise.resolve({ control: null }),
      selected ? supervisionApi.messages(engagementId, 'supervision-' + selected) : Promise.resolve({ messages: [] }),
      supervisionApi.tasks(engagementId),
      selected ? supervisionApi.terminalCallbacks(engagementId, selected) : Promise.resolve({ callbacks: [] }),
      supervisionApi.modelUsage(engagementId),
      supervisionApi.authorizationStatus(engagementId),
      selected ? supervisionApi.mcpDispatches(engagementId, selected) : Promise.resolve({ dispatches: [] }),
      supervisionApi.unresolvedModelCalls(engagementId),
    ]);
    const failures: string[] = [];
    const [eventResult, attemptResult, controlResult, messageResult, taskResult, callbackResult, usageResult, authorizationResult, mcpResult, unresolvedCallsResult] = requests;
    if (eventResult.status === 'fulfilled') {
      setEvents(eventResult.value.events);
      latestSequence.current = Math.max(
        latestSequence.current,
        ...eventResult.value.events.map((entry) => entry.sequence),
        0,
      );
    }
    else { setEvents([]); failures.push('events'); }
    if (attemptResult.status === 'fulfilled') setAttempts(attemptResult.value.attempts);
    else { setAttempts([]); failures.push('attempts'); }
    if (controlResult.status === 'fulfilled') setControl(controlResult.value.control);
    else { setControl(null); failures.push('control'); }
    if (messageResult.status === 'fulfilled') setMessages(messageResult.value.messages);
    else { setMessages([]); failures.push('messages'); }
    if (taskResult.status === 'fulfilled') setPersistedTasks(taskResult.value.tasks);
    else { setPersistedTasks(null); failures.push('persisted tasks'); }
    if (callbackResult.status === 'fulfilled') setTerminalCallbacks(callbackResult.value.callbacks);
    else { setTerminalCallbacks([]); failures.push('terminal callbacks'); }
    if (usageResult.status === 'fulfilled') setModelUsage(usageResult.value.usage);
    else { setModelUsage(null); failures.push('provider usage ledger'); }
    if (authorizationResult.status === 'fulfilled') {
      setAuthorization(authorizationResult.value);
      setAuthorizationError('');
    } else {
      // An unavailable database must never be presented as a valid signed
      // policy or as an authoritative 'unverified' legacy status.
      setAuthorization(null);
      setAuthorizationError('Signed authorization state unavailable. No active authority can be confirmed.');
    }
    if (mcpResult.status === 'fulfilled') setMcpDispatches(mcpResult.value.dispatches);
    else { setMcpDispatches([]); failures.push('remote MCP dispatch receipts'); }
    if (unresolvedCallsResult.status === 'fulfilled'
      && unresolvedCallsResult.value.safe_to_retry === false
      && unresolvedCallsResult.value.invoice_reconciled === false) {
      setUnreconciledModelCalls(unresolvedCallsResult.value.calls);
    } else {
      setUnreconciledModelCalls([]);
      failures.push('unreconciled provider calls');
    }
    setError(failures.length
      ? 'Could not verify ' + failures.join(', ') + ' from the authenticated supervision API.'
      : '');
  }, [engagementId, taskId]);

  useEffect(() => {
    // A previous engagement's project-cost evidence must not survive
    // navigation or an asynchronous previous-request completion.
    providerCostsEpoch.current += 1;
    setProviderCosts(null);
    setProviderCostsError('');
    setProviderCostsLoading(false);
  }, [engagementId]);

  useEffect(() => {
    // The cursor belongs to one engagement + task pair. Do not reuse a
    // sequence observed in an unrelated task when changing selection.
    latestSequence.current = 0;
    temporalObservationRevision.current += 1;
    setTemporalObservation(null);
  }, [engagementId, taskId]);

  useEffect(() => {
    setTaskId((current) => visibleTasks.some((item) => item.task_id === current)
      ? current : visibleTasks[0]?.task_id ?? '');
  }, [tasks, persistedTasks]);

  useEffect(() => {
    setEvents([]);
    setAttempts([]);
    setMcpDispatches([]);
    setTerminalCallbacks([]);
    setControl(null);
    setMessages([]);
    setNotice('');
    void refresh();
    const timer = window.setInterval(() => { if (!busy) void refresh(); }, 15000);
    return () => window.clearInterval(timer);
  }, [refresh, busy]);

  useEffect(() => {
    if (!engagementId || !taskId) return;
    const controller = new AbortController();
    let retries = 0;
    async function consumeStream(): Promise<void> {
      while (!controller.signal.aborted) {
        try {
          setLiveState(retries ? 'reconnecting' : 'connecting');
          await streamSupervisionEvents(
            engagementId, taskId, latestSequence.current, controller.signal,
            (event) => {
              latestSequence.current = Math.max(latestSequence.current, event.sequence);
              setEvents((prev) => [...prev.filter((item) => item.id !== event.id), event].slice(-100));
              setLiveState('live');
              // Refresh authoritative control and delivery receipts on each
              // durable notification; this is not a client-side status guess.
              void refresh();
            },
          );
        } catch (cause) {
          if (controller.signal.aborted) return;
          if (cause instanceof FlowApiError && [401, 403].includes(cause.status)) {
            setError('Live supervision authorization expired or was denied; reconnect requires valid access.');
            return;
          }
        }
        if (controller.signal.aborted) return;
        retries += 1;
        setLiveState('reconnecting');
        // Bounded backoff + cancellation: an operator who navigates away
        // must not leave an unauthorized stream polling in the background.
        await new Promise<void>((resolve) => {
          const timer = window.setTimeout(resolve, Math.min(1000 * retries, 5000));
          controller.signal.addEventListener('abort', () => {
            window.clearTimeout(timer);
            resolve();
          }, { once: true });
        });
      }
    }
    void consumeStream();
    return () => controller.abort();
  }, [engagementId, taskId, refresh]);

  async function observeOpenAICosts() {
    if (!engagementId || !seniorRoleHint || providerCostsLoading) return;
    const epoch = ++providerCostsEpoch.current;
    setProviderCosts(null);
    setProviderCostsError('');
    setProviderCostsLoading(true);
    const day = 86400;
    const end = Math.floor(Date.now() / 1000 / day) * day;
    try {
      const observed = await supervisionApi.observeOpenAIProjectCosts(
        engagementId, end - 7 * day, end,
      );
      if (epoch !== providerCostsEpoch.current) return;
      const verifiedCostShape = observed.provider_cost_data_present
        ? (typeof observed.provider_cost_usd === 'string'
          && /^\d+(?:\.\d{1,12})?(?:[Ee][+-]?\d{1,2})?$/.test(observed.provider_cost_usd)
          && Number.isFinite(Number(observed.provider_cost_usd))
          && Number(observed.provider_cost_usd) >= 0)
        : observed.provider_cost_usd === null;
      if (observed.source !== 'openai_organization_costs_api' ||
          observed.source_authenticated !== true ||
          observed.currency !== 'USD' ||
          !verifiedCostShape ||
          !/^[a-f0-9]{64}$/.test(observed.project_sha256) ||
          typeof observed.observation_recorded !== 'boolean' ||
          observed.project_access_binding !== 'server_configured_engagement' ||
          observed.provider_project_exclusivity_verified !== false ||
          typeof observed.provider_cost_data_present !== 'boolean' ||
          observed.provider_cost_data_present !== (observed.provider_cost_usd !== null) ||
          observed.individual_call_cost_verified !== false ||
          observed.provider_project_comparable_to_engagement !== false ||
          observed.ledger_mutated !== false ||
          observed.safe_to_retry !== false) {
        throw new Error('Provider source assertions are not independently confirmed by the API.');
      }
      setProviderCosts(observed);
    } catch {
      if (epoch === providerCostsEpoch.current) {
        setProviderCostsError('Provider project costs unavailable or not enabled. Do not substitute operator attestations or assumed zero spend.');
      }
    } finally {
      if (epoch === providerCostsEpoch.current) setProviderCostsLoading(false);
    }
  }

  async function sendControl(action: 'cancel' | 'pause' | 'resume') {
    if (busy || !canControl || !taskId || reason.trim().length < 10) return;
    if (!window.confirm(
      action.toUpperCase() + ' execution of ' + taskId + '?\n'
      + 'This submits a durable operator request. Remote termination may remain UNKNOWN.'
    )) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const outcome = await supervisionApi.requestControl(
        engagementId, taskId, action, reason.trim(), crypto.randomUUID(),
      );
      await refresh();
      setNotice('Control ' + outcome.control.request_id + ' persisted: ' + outcome.control.status
        + '. Execution stopped: ' + (outcome.execution_stopped ? 'confirmed' : 'NOT CONFIRMED') + '.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Control request failed');
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function revokeSignedAuthorization() {
    if (busy || !seniorRoleHint ||
        !authorization || authorization.status === 'revoked' || !authorization.version) return;
    let cleanReason: string;
    try {
      cleanReason = assertRevokeAuthorizationInput(authorization.version, revokeReason);
    } catch {
      setError('Revocation requires the current signed version and a meaningful 10–500-character reason.');
      return;
    }
    if (!window.confirm(
      'REVOKE signed ROE for engagement ' + engagementId + ' at version ' + authorization.version + '?\n'
      + 'This revokes PostgreSQL authorization and requests a local halt. '
      + 'Existing remote execution may remain UNKNOWN; revocation is NOT proof of termination.',
    )) return;
    setBusy(true);
    setError('');
    setNotice('');
    setRevokeResult(null);
    try {
      const result = await supervisionApi.revokeAuthorization(
        engagementId, authorization.version, cleanReason,
      );
      if (result.status !== 'revoked' || result.authorization_version !== authorization.version ||
          result.remote_execution_outcome !== 'unknown') {
        throw new Error('Revocation outcome was not confirmed; refresh authoritative state.');
      }
      setRevokeResult(result);
      setAuthorization((previous) => previous && {
        ...previous, status: 'revoked', remote_execution_outcome: 'unknown',
      });
      setRevokeReason('');
      setNotice('Signed authorization version ' + result.authorization_version
        + ' revoked in PostgreSQL. Local halt request: '
        + (result.halt_request_accepted ? 'accepted' : 'not confirmed')
        + '. Remote execution outcome: UNKNOWN — termination has NOT been verified.');
      // Read the latest version again; another senior could rotate it.
      await refresh();
    } catch (err) {
      setError(err instanceof FlowApiError && err.status === 409
        ? 'Authorization version is stale or changed. Refresh the signed status before retrying.'
        : 'Revocation status cannot be confirmed. Refresh authoritative PostgreSQL state.');
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault();
    const content = operatorInput.trim();
    if (!content || !taskId || busy) return;
    setBusy(true);
    setError('');
    try {
      const result = await supervisionApi.submitMessage(
        engagementId, chainId, taskId, content, crypto.randomUUID(),
      );
      setOperatorInput('');
      await refresh();
      setNotice('Operator input persisted (' + result.delivery_status
        + '). An agent response is not implied until independently recorded.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not persist operator input');
    } finally {
      setBusy(false);
    }
  }

  async function requestRemoteReconciliation(receipt: MCPDispatchReceipt) {
    if (busy || !taskId || receipt.task_id !== taskId) return;
    setBusy(true);
    setError('');
    try {
      const result = await supervisionApi.reconcileMcpDispatch(
        engagementId, taskId, receipt.server_id, receipt.request_id,
      );
      if (result.request_id !== receipt.request_id) {
        throw new Error('Provider receipt identity could not be verified');
      }
      await refresh();
      setNotice('Remote status query: ' + result.status + '. PostgreSQL: '
        + result.persisted_status + '. A status query does not rerun the original tool.');
    } catch {
      setError('Remote provider status cannot be confirmed. No original tool was replayed.');
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function observePendingRemoteRequests() {
    if (busy || !taskId || !canControl) return;
    const selectedTask = taskId;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await supervisionApi.observePendingMcpDispatches(
        engagementId, selectedTask,
      );
      if (result.safe_to_retry !== false ||
          result.external_effect_status !== 'unknown' ||
          !Array.isArray(result.observed)) {
        throw new Error('Provider observation contract is unverified.');
      }
      if (selectedTask !== taskId) return;
      await refresh();
      const confirmed = result.observed.filter((item) =>
        item.status === item.persisted_status &&
        ['confirmed_stopped', 'confirmed_finished'].includes(item.status),
      ).length;
      setNotice('Read-only remote status sweep checked ' + result.observed.length
        + ' persisted requests (' + confirmed + ' provider-signed terminal assertions recorded). '
        + result.remaining_unobserved + ' not observed. No original tool was repeated; '
        + 'provider statements are not proof of physical target effects.');
    } catch {
      setError('Remote observation was not fully verified. Existing UNKNOWN actions are not safe to retry.');
    } finally {
      setBusy(false);
    }
  }

  async function stopPersistedRemoteRequest(receipt: MCPDispatchReceipt) {
    if (
      busy || !seniorRoleHint || taskId !== receipt.task_id
      || !authorization || authorization.status !== 'active'
      || authorization.version !== receipt.authorization_version
      || reason.trim().length < 10 || reason.trim().length > 500
    ) return;
    if (!window.confirm(
      'Request ONE durable stop for original remote request ' + receipt.request_id
      + ' on ' + receipt.server_id + '?\n'
      + 'PostgreSQL will reserve this cancellation attempt before contacting the provider. '
      + 'Timeouts and ambiguous effects will remain UNKNOWN; this action will not be automatically retried. '
      + 'A signed provider status does not independently prove physical termination.'
    )) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const outcome = await supervisionApi.cancelPersistedMcpDispatch(
        engagementId, taskId, receipt, reason.trim(),
      );
      await refresh();
      const attested = outcome.status === 'confirmed_stopped'
        && outcome.provider_reported_stop === true
        && outcome.persisted_status === 'confirmed_stopped';
      setNotice(
        'Durable remote cancellation: ' + (
          attested ? 'provider signed STOP assertion persisted' : 'remote outcome UNKNOWN'
        ) + '. Original tool was not replayed. No independent physical stop '
        + 'or safe-to-retry guarantee is established.',
      );
    } catch {
      setError(
        'Remote stop acceptance/receipt could not be confirmed. '
        + 'Do not repeat this consequential request; reconcile the original remote status.',
      );
    } finally {
      setBusy(false);
    }
  }

  async function observeTemporalWorkflow() {
    if (busy || !taskId || !canControl) return;
    const selected = taskId;
    const revision = ++temporalObservationRevision.current;
    setBusy(true);
    setError('');
    try {
      const observed = await supervisionApi.observeTemporal(engagementId, selected);
      if (temporalObservationRevision.current !== revision) return;
      if (observed.task_id !== selected || observed.safe_to_retry !== false
        || observed.external_effect_status !== 'unknown'
        || observed.durable_status_changed !== false) {
        throw new Error('Temporal observation contract was not verified');
      }
      setTemporalObservation(observed);
      setNotice('Temporal observation recorded for display only: '
        + observed.observation + ' (' + observed.provider_status
        + '). External effect remains UNKNOWN; no task was replayed.');
    } catch {
      if (temporalObservationRevision.current !== revision) return;
      setTemporalObservation(null);
      setError('Temporal observation could not be verified. No execution was retried or marked stopped.');
    } finally {
      setBusy(false);
    }
  }

  async function reconcileVerifiedTemporalExistence() {
    if (busy || !taskId || !seniorRoleHint || authorization?.status !== 'active'
      || !authorization.version) return;
    const selected = taskId;
    const revision = ++temporalObservationRevision.current;
    setBusy(true);
    setError('');
    try {
      const result = await supervisionApi.reconcileTemporalExistence(
        engagementId, selected, authorization.version,
      );
      if (revision !== temporalObservationRevision.current || result.task_id !== selected
        || result.safe_to_retry !== false || result.external_effect_status !== 'unknown') {
        throw new Error('Provider reconciliation response is not trustworthy');
      }
      await refresh();
      setNotice(result.reconciled_workflow_existence
        ? 'An independently observed Temporal workflow RUN ID is now stored as a scheduling receipt. External execution/effects remain UNKNOWN. No task was restarted.'
        : 'Workflow existence not confirmed. The unresolved state remains; no task was restarted.');
    } catch {
      if (revision !== temporalObservationRevision.current) return;
      setError('Could not verify and persist workflow existence. Retry is NOT authorized and execution remains unresolved.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Durable agent supervision and execution receipts">
      <p className="text-on-surface-variant text-[11px] mb-4">
        PostgreSQL-backed attempts, event histories and operator requests. A control marked unknown does not mean the remote tool stopped.
        <span className="block mt-1">
          Task inventory: {persistedTasks !== null ? 'durable PostgreSQL records (all replicas)' : 'fallback to local diagnostics'}
        </span>
        <span className="block mt-1" role="status">
          Event feed: {liveState === 'live' ? 'connected (authenticated)' :
            liveState === 'reconnecting' ? 'reconnecting; periodic refresh remains active' :
            'connecting to authorized stream'}
        </span>
      </p>
      <section className="border border-outline-variant p-3 mb-4 text-[11px]" aria-label="Signed authorization status">
        <h3 className="font-label-caps text-[11px] mb-2">SIGNED ROE AUTHORIZATION — AUTHORITATIVE POSTGRESQL</h3>
        {authorizationError && <p role="alert" className="text-error">{authorizationError}</p>}
        {!authorization && !authorizationError && <p role="status">Checking signed authorization ledger…</p>}
        {authorization && <>
          <p role="status">Status: <strong>{authorization.status.toUpperCase()}</strong>
            {' '}· version {authorization.version ?? 'not available'}
            {' '}· expires {authorization.expires_at ? time(authorization.expires_at) : 'not available'}
          </p>
          {authorization.status === 'unverified' && <p className="text-error mt-1">
            No verified signed authorization is recorded. A legacy session is not authorized for new execution.
          </p>}
          {authorization.status === 'revoked' && <p className="text-error mt-1">
            Signed ROE is revoked. Remote execution may still be running; termination remains UNKNOWN.
          </p>}
          {authorization.status === 'expired' && <p className="text-error mt-1">
            Signed ROE has expired. No current authorization is established.
          </p>}
        </>}
        {revokeResult && <p role="status" className="mt-2 text-error">
          Revocation acknowledged for version {revokeResult.authorization_version} (PostgreSQL).
          {' '}Local halt request: {revokeResult.halt_request_accepted ? 'accepted' : 'not confirmed'}.
          {' '}Remote execution outcome UNKNOWN; do not assume stopped.
        </p>}
        {seniorRoleHint && <div className="border-t border-outline-variant pt-3 mt-3">
          <label className="block text-on-surface-variant">
            SENIOR OPERATOR SIGNED ROE REVOCATION REASON (10–500 CHARACTERS)
            <textarea value={revokeReason} onChange={(event) => setRevokeReason(event.target.value)}
              rows={2} maxLength={500}
              className="w-full mt-1 border border-outline p-2 bg-background text-on-surface" />
          </label>
          <button type="button"
            className={controlStyle + ' text-error border-error mt-2'}
            disabled={busy || !authorization || authorization.status === 'revoked' ||
              !authorization.version || revokeReason.trim().length < 10}
            onClick={() => void revokeSignedAuthorization()}>
            <ShieldAlert size={13} className="inline mr-1" /> REVOKE SIGNED ROE (CAS VERSION)
          </button>
          <p className="text-on-surface-variant text-[10px] mt-1">
            Revocation is an irreversible authorization decision for this version.
            Remote operations may remain UNKNOWN until separately reconciled.
          </p>
        </div>}
        {!seniorRoleHint && <p className="text-on-surface-variant text-[10px] mt-2">
          ROE revocation requires senior_operator access. The backend enforces the role independently.
        </p>}
      </section>
      {modelUsage && <section className="border border-outline-variant p-3 mb-4 text-[11px]" aria-label="Provider usage receipts">
        <strong>MODEL USAGE — PERSISTED PROVIDER RECEIPTS</strong>
        <p className="mt-1">{modelUsage.calls} admitted calls · {modelUsage.settled_calls} settled · {modelUsage.unknown_calls} uncertain</p>
        <p>Reported input tokens: {modelUsage.provider_reported_input_tokens ?? 'unavailable'} · reported output tokens: {modelUsage.provider_reported_output_tokens ?? 'unavailable'}</p>
        <p>Provider-reported billed USD: {modelUsage.provider_reported_cost_usd ?? 'unavailable'}
          {' '}· {modelUsage.cost_complete ? 'all receipts priced' : `${modelUsage.unpriced_calls} unpriced receipts; total is incomplete`}
        </p>
        <p className="text-on-surface-variant mt-1">A cost total excludes missing provider receipts; it is not an invoice reconciliation or projected price estimate.</p>
        {seniorRoleHint && <div className="mt-2 pt-2 border-t border-outline-variant">
          <button type="button" className={controlStyle}
            disabled={providerCostsLoading} onClick={() => void observeOpenAICosts()}>
            {providerCostsLoading ? 'Checking independent provider aggregate…' :
              'OBSERVE OPENAI PROJECT COSTS — LAST 7 COMPLETED UTC DAYS'}
          </button>
          <p className="text-on-surface-variant mt-1">
            Requires separately configured organization admin credentials and a fixed provider project.
            Read-only aggregate; never a per-call invoice, hard provider spending limit, or confirmed execution outcome.
          </p>
          {providerCostsError && <p role="alert" className="text-error">{providerCostsError}</p>}
          {providerCosts && <div role="status" className="mt-2">
            <p>OpenAI Costs API project aggregate, USD {
              providerCosts.provider_cost_data_present
                ? providerCosts.provider_cost_usd
                : 'UNKNOWN (no provider cost lines returned)'
            }
              {' '}({providerCosts.buckets} UTC day buckets, {providerCosts.cost_lines} cost lines).</p>
            <p>Independent provider observation audit:
              {' '}{providerCosts.observation_recorded === true ? 'recorded with PostgreSQL outbox' :
                providerCosts.observation_recorded === false ? 'previously recorded (idempotent)' :
                'unverified by this API version'}.
            </p>
            <p>Project SHA256 prefix: {providerCosts.project_sha256.slice(0, 12)}
              {' '}· source: authenticated configured API, not a per-call signed invoice.</p>
            <p className="text-on-surface-variant">
              This provider project/time-range cannot be directly compared to the engagement lifetime ledger.
              Individual call charge verification: NO. External spending ceiling verification: NO.
              Ledger unchanged; unknown calls remain unknown.
            </p>
            <p className="text-error">
              Project exclusivity verification: NO. Server-configured engagement access grants a
              read of the project aggregate but does not prove the OpenAI project contains only
              this engagement's activity. Cross-engagement cost attribution is NOT verified.
            </p>
          </div>}
        </div>}
        {unreconciledModelCalls.length > 0 && <div className="mt-2 border-t border-outline-variant pt-2">
          <strong className="text-error">UNRESOLVED PROVIDER CALLS — NO AUTOMATIC RETRY</strong>
          <div className="max-h-32 overflow-y-auto">
            {unreconciledModelCalls.map((call) => <p key={call.call_id} className="font-code-sm">
              {call.call_id} · {call.status} · {call.operation} · billed cost UNKNOWN
            </p>)}
          </div>
          <p>Invoice reconciliation remains unverified. A reserved or unknown paid request may have reached the provider.</p>
        </div>}
      </section>}
      <div className="flex flex-wrap gap-3 items-end mb-3">
        <label className="text-[11px] flex-1 min-w-[200px] text-on-surface-variant">
          EXECUTION TASK
          <select className="w-full border border-outline p-2 bg-background text-on-surface"
            value={taskId} onChange={(event) => setTaskId(event.target.value)}>
            <option value="">Select task</option>
            {visibleTasks.map((task) => <option key={task.task_id} value={task.task_id}>
              {task.task_id} · {task.status}
            </option>)}
          </select>
        </label>
        <button type="button" className={controlStyle} disabled={busy} onClick={() => void refresh()}>
          <RefreshCw size={13} className="inline mr-1" /> REFRESH VERIFIED STATE
        </button>
      </div>
      {error && <p role="alert" className="text-error text-[11px] mb-3">{error}</p>}
      {notice && <p role="status" className="text-secondary text-[11px] mb-3">{notice}</p>}
      <DurableSupervisionSubscribersPanel engagementId={engagementId} taskId={taskId || undefined} canControl={canControl} />
      {currentTask && <p className="text-[11px] mb-3">Current task status: <strong>{currentTask.status}</strong>
        {' '}· retry {currentTask.retry_count}/{currentTask.max_retries}</p>}
      {taskId && currentTask && ['dispatching', 'dispatch_unknown'].includes(currentTask.status) &&
        <section className="border border-outline-variant p-3 mb-4 text-[11px]" aria-label="Temporal workflow observation">
          <h3 className="font-label-caps mb-2">TEMPORAL DISPATCH — PROVIDER-ONLY OBSERVATION</h3>
          <p className="text-error mb-2">
            Dispatch outcome is unresolved. Workflow presence/absence is not proof of remote execution,
            exploit effect, cancellation, or safe retry.
          </p>
          <button type="button" className={controlStyle} disabled={busy || !canControl}
            onClick={() => void observeTemporalWorkflow()}>
            CHECK EXISTING WORKFLOW (NO REPLAY)
          </button>
          {seniorRoleHint && authorization?.status === 'active' && authorization.version && currentTask.status === 'dispatch_unknown' &&
            <button type="button" className={controlStyle + ' ml-2'}
              disabled={busy || !canControl}
              onClick={() => void reconcileVerifiedTemporalExistence()}>
              VERIFY WORKFLOW EXISTS — FENCE IN POSTGRESQL
            </button>}
          {temporalObservation && <p role="status" className="mt-2">
            Observed: <strong>{temporalObservation.observation}</strong> · provider state:
            {' '}<strong>{temporalObservation.provider_status}</strong> · verified:
            {' '}{temporalObservation.verified ? 'yes' : 'no'}.
            {' '}External outcome UNKNOWN. Durable task status unchanged. Automatic retry prohibited.
          </p>}
        </section>}
      {taskId && <section className="border border-outline-variant p-3 mb-4">
        <h3 className="font-label-caps text-[11px] mb-2">DURABLE TERMINAL CALLBACKS</h3>
        <div className="space-y-2 text-[11px]" role="status">
          {terminalCallbacks.length === 0 && <p className="text-on-surface-variant">No terminal callback intent recorded.</p>}
          {terminalCallbacks.map((item) => (
            <div className="bg-surface-container-high p-2" key={item.id}>
              <strong>{item.outcome} · {item.status.toUpperCase()}</strong>
              <span className="text-on-surface-variant"> · claim attempts {item.attempts}</span>
              <p className="font-code-sm break-all">{item.attempt_id}</p>
              {item.effect_steps && <div className="mt-2 space-y-1">
                <p className="text-on-surface-variant">Persisted downstream effect receipts:</p>
                {item.effect_steps.order.map((step) => <p key={step} className="font-code-sm">
                  {step.replace(/_/g, ' ')} · <strong>{item.effect_steps?.states[step] ?? 'unknown'}</strong>
                </p>)}
                <p className="text-on-surface-variant">A returned step records a local callback return; it does not independently prove an external provider action completed.</p>
              </div>}
              {item.status === 'unknown' && <p className="text-error">
                Outcome of downstream callback is not verified. Automatic replay is blocked pending reconciliation.
              </p>}
              {item.status === 'pending' && <p className="text-on-surface-variant">Terminal status committed; callback queued durably.</p>}
              {item.status === 'leased' && <p className="text-on-surface-variant">A worker has claimed callback processing, not yet acknowledged completion.</p>}
            </div>
          ))}
        </div>
      </section>}
      {taskId && <section className="border border-outline-variant p-3 mb-4 text-[11px]" aria-label="Remote MCP dispatch receipts">
        <h3 className="font-label-caps text-[11px] mb-2">REMOTE MCP REQUESTS — GLOBAL POSTGRESQL FENCE</h3>
        {mcpDispatches.some((receipt) => !['confirmed_stopped', 'confirmed_finished'].includes(receipt.status)) &&
          <button type="button" className={controlStyle + ' mb-2'} disabled={busy || !canControl}
            onClick={() => void observePendingRemoteRequests()}>
            OBSERVE UP TO 6 UNKNOWN REMOTE REQUESTS (NO REPLAY)
          </button>}
        {mcpDispatches.length === 0 && <p className="text-on-surface-variant">No durable MCP dispatch claim recorded for this task.</p>}
        <div className="space-y-2 max-h-52 overflow-y-auto">
          {mcpDispatches.map((receipt) => <div key={receipt.server_id + ':' + receipt.request_id} className="bg-surface-container-high p-2">
            <strong>{receipt.server_id} · {receipt.tool_name}</strong>
            <p className="font-code-sm break-all">{receipt.request_id} · signed ROE v{receipt.authorization_version}</p>
            <p>Status: <strong>{receipt.status.toUpperCase()}</strong></p>
            {!['confirmed_stopped', 'confirmed_finished'].includes(receipt.status) &&
              <button type="button" className={controlStyle + ' mt-1'}
                disabled={busy || !canControl}
                onClick={() => void requestRemoteReconciliation(receipt)}>
                CHECK PROVIDER STATUS (NO REPLAY)
              </button>}
            {!['confirmed_stopped', 'confirmed_finished', 'cancel_requested'].includes(receipt.status)
              && seniorRoleHint && authorization?.status === 'active'
              && authorization.version === receipt.authorization_version &&
              <button type="button" className={controlStyle + ' mt-1 ml-2 text-error'}
                disabled={busy || reason.trim().length < 10 || reason.trim().length > 500}
                onClick={() => void stopPersistedRemoteRequest(receipt)}>
                REQUEST ONE POST-RESTART REMOTE STOP (UNKNOWN UNTIL SIGNED RECEIPT)
              </button>}
            {!['confirmed_stopped', 'confirmed_finished'].includes(receipt.status) && <p className="text-error">
              Remote completion/termination is NOT verified. Database dispatch admission is not provider execution proof.
            </p>}
          </div>)}
        </div>
      </section>}
      {control && <div className="border border-outline-variant p-3 text-[11px] mb-4">
        <strong>Most recent control:</strong> {control.action} · <span className={
          control.status === 'confirmed_stopped' ? 'text-primary-fixed' : 'text-secondary'
        }>{control.status.toUpperCase()}</span>
        <p className="text-on-surface-variant mt-1">{control.request_id} · {time(control.updated_at)}</p>
        {control.status !== 'confirmed_stopped' && <p className="text-error mt-1">
          <AlertTriangle size={13} className="inline mr-1" /> Remote execution termination is not verified.
        </p>}
      </div>}
      {taskId && <div className="border-t border-outline-variant pt-4 mb-5">
        <label className="block text-[11px] text-on-surface-variant">
          OPERATOR REASON (10–500 CHARACTERS)
          <textarea className="w-full border border-outline bg-background text-on-surface p-2 mt-1"
            rows={2} maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} />
        </label>
        <div className="flex flex-wrap gap-2 mt-2">
          <button type="button" className={controlStyle} disabled={busy || !canControl || reason.trim().length < 10}
            onClick={() => void sendControl('pause')}>REQUEST PAUSE</button>
          <button type="button" className={controlStyle} disabled={busy || !canControl || reason.trim().length < 10}
            onClick={() => void sendControl('resume')}>REQUEST RESUME</button>
          <button type="button" className={controlStyle + ' text-error border-error'}
            disabled={busy || !canControl || reason.trim().length < 10}
            onClick={() => void sendControl('cancel')}>
            <ShieldAlert size={13} className="inline mr-1" /> REQUEST EXECUTION CANCELLATION
          </button>
        </div>
        <p className="text-on-surface-variant text-[10px] mt-2">
          Pause/resume can affect cooperative reasoning checkpoints when the owning worker acknowledges them;
          they do not suspend already dispatched remote tools. Cancellation can remain unresolved;
          emergency engagement halt remains a separate senior-operator control.
        </p>
      </div>}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 mb-5">
        <section className="border border-outline-variant p-3">
          <h3 className="font-label-caps text-[11px] mb-2">EXECUTION ATTEMPTS ({attempts.length})</h3>
          <div className="space-y-2 max-h-56 overflow-y-auto text-[11px]">
            {attempts.length === 0 && <p className="text-on-surface-variant">No durable attempts returned.</p>}
            {attempts.map((attempt) => <div key={attempt.id} className="bg-surface-container-high p-2">
              <strong>{attempt.status}</strong> · attempt {attempt.attempt} · rev {attempt.revision}
              <p className="text-on-surface-variant">{time(attempt.updated_at)}</p>
              {attempt.external_id && <p className="font-code-sm break-all">External ID: {attempt.external_id}</p>}
            </div>)}
          </div>
        </section>
        <section className="border border-outline-variant p-3">
          <h3 className="font-label-caps text-[11px] mb-2">DURABLE EVENTS ({events.length})</h3>
          <div className="space-y-2 max-h-56 overflow-y-auto text-[11px]">
            {events.length === 0 && <p className="text-on-surface-variant">No events returned.</p>}
            {events.map((entry) => <div key={entry.id} className="bg-surface-container-high p-2">
              <strong>{entry.kind}</strong> · {entry.actor_id}
              <p className="text-on-surface-variant"><Clock3 size={11} className="inline mr-1" />{time(entry.created_at)}</p>
            </div>)}
          </div>
        </section>
      </div>
      {taskId && <section className="border-t border-outline-variant pt-4">
        <h3 className="font-label-caps text-[11px] mb-2">PERSISTENT AGENT / OPERATOR MESSAGE CHAIN</h3>
        <div className="max-h-48 overflow-y-auto space-y-2 text-[11px]">
          {messages.length === 0 && <p className="text-on-surface-variant">No durable messages returned.</p>}
          {messages.map((entry) => <div key={entry.id} className="bg-surface-container-high p-2">
            <strong>{entry.role} · {entry.actor_id}</strong>
            {entry.role === 'operator' && (
              <span className="ml-2 text-on-surface-variant">
                Delivery: {entry.delivery_state === 'consumed' ? 'consumed by agent reasoning' :
                  entry.delivery_state === 'leased' ? 'leased, awaiting model acknowledgement' :
                  entry.delivery_state === 'rejected' ? 'rejected' : 'pending'}
              </span>
            )}
            <p className="mt-1 whitespace-pre-wrap break-words">{entry.content}</p>
            <p className="text-on-surface-variant">{time(entry.created_at)}</p>
          </div>)}
        </div>
        <form onSubmit={(event) => void sendMessage(event)} className="flex flex-col gap-2 mt-3">
          <label className="text-[11px] text-on-surface-variant">OPERATOR INPUT (PERSISTED, DELIVERY NOT GUARANTEED)
            <textarea rows={2} maxLength={2000} className="w-full border border-outline p-2 bg-background text-on-surface"
              value={operatorInput} onChange={(event) => setOperatorInput(event.target.value)} />
          </label>
          <button className={controlStyle} type="submit" disabled={busy || !canControl || !operatorInput.trim()}>
            SAVE OPERATOR MESSAGE
          </button>
        </form>
      </section>}
    </Card>
  );
}
