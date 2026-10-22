import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import {
  checkFlowMcpActionPreflight, currentMcpPreflightScope,
  listPreparedMcpPreflightActions, type McpActionPreflight,
} from '../../services/flowMcpActionPreflight';
import type { FlowMcpAction, McpActionScope } from '../../services/flowMcpActions';

export interface FlowMcpActionPreflightPanelProps {
  flowId: string;
  engagementId: string;
  revision: number;
  flowStatus: string;
  authorizationId?: string | null;
}

/**
 * Inspect a previously approved, PREPARED Action's current eligibility.
 * This panel has no mutation/approval/dispatch workflow.
 */
export function FlowMcpActionPreflightPanel({
  flowId, engagementId, revision, flowStatus, authorizationId,
}: FlowMcpActionPreflightPanelProps) {
  const [actor, setActor] = useState(() => currentOperator());
  const [scope, setScope] = useState<McpActionScope | null>(null);
  const [prepared, setPrepared] = useState<FlowMcpAction[]>([]);
  const [chosen, setChosen] = useState('');
  const [manifestSha, setManifestSha] = useState('');
  const [result, setResult] = useState<McpActionPreflight | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const inFlight = useRef(false);
  const active = flowStatus === 'pending' || flowStatus === 'running';
  const permitted = active && !!authorizationId
    && (actor?.role === 'operator' || actor?.role === 'senior_operator');

  const invalidate = useCallback(() => {
    setScope(null);
    setPrepared([]);
    setChosen('');
    setResult(null);
  }, []);

  const readCurrentScope = useCallback(async (): Promise<McpActionScope> => {
    if (!permitted || !authorizationId) {
      throw new Error('Signed operator or active Flow unavailable.');
    }
    return currentMcpPreflightScope(flowId, engagementId, revision, authorizationId);
  }, [authorizationId, engagementId, flowId, permitted, revision]);

  const refresh = useCallback(async () => {
    if (inFlight.current || !permitted) return;
    const run = ++generation.current;
    inFlight.current = true;
    setBusy(true);
    invalidate();
    setMessage('');
    try {
      const signed = await readCurrentScope();
      const list = await listPreparedMcpPreflightActions(signed);
      const readback = await readCurrentScope();
      if (signed.authorizationVersion !== readback.authorizationVersion
        || signed.authorizationSha256 !== readback.authorizationSha256
        || signed.authorizationId !== readback.authorizationId) {
        throw new Error('Current signed Flow ROE changed.');
      }
      if (run !== generation.current) return;
      setScope(signed);
      setPrepared(list);
      setMessage(list.length
        ? 'Loaded prepared Actions from the signed ledger. Select one to inspect its current eligibility.'
        : 'No PREPARED Action exists in this signed Flow. Preflight cannot grant an approval.');
    } catch {
      if (run === generation.current) {
        invalidate();
        setMessage('Signed prepared Action catalog unavailable or stale. Eligibility is unconfirmed.');
      }
    } finally {
      if (run === generation.current) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  }, [invalidate, permitted, readCurrentScope]);

  useEffect(() => {
    if (permitted) void refresh();
    else {
      ++generation.current;
      inFlight.current = false;
      setBusy(false);
      invalidate();
    }
    return () => {
      ++generation.current;
      inFlight.current = false;
    };
  }, [invalidate, permitted, refresh]);

  useEffect(() => subscribeOperator(next => {
    ++generation.current;
    inFlight.current = false;
    setBusy(false);
    setActor(next);
    invalidate();
    setManifestSha('');
    setMessage('Operator identity changed. Re-read the signed Action catalog before preflight.');
  }), [invalidate]);

  async function inspect(): Promise<void> {
    if (inFlight.current || busy || !permitted || !scope || !chosen) return;
    const action = prepared.find(item => item.action_id === chosen);
    if (!action || action.status !== 'prepared') return;
    const sha = manifestSha.trim();
    if (sha && !/^[0-9a-f]{64}$/.test(sha)) {
      setResult(null);
      setMessage('Optional approved resource manifest must be a 64-character lowercase SHA-256.');
      return;
    }
    const run = ++generation.current;
    inFlight.current = true;
    setBusy(true);
    setResult(null);
    setMessage('');
    try {
      const current = await readCurrentScope();
      if (current.flowId !== scope.flowId || current.engagementId !== scope.engagementId
        || current.flowRevision !== scope.flowRevision
        || current.authorizationId !== scope.authorizationId
        || current.authorizationVersion !== scope.authorizationVersion
        || current.authorizationSha256 !== scope.authorizationSha256) {
        throw new Error('Signed Flow authority changed.');
      }
      const inspection = await checkFlowMcpActionPreflight(
        scope, action.action_id, sha || undefined,
      );
      const after = await readCurrentScope();
      if (after.authorizationVersion !== scope.authorizationVersion
        || after.authorizationSha256 !== scope.authorizationSha256
        || after.authorizationId !== scope.authorizationId) {
        throw new Error('Signed ROE was changed after preflight.');
      }
      if (run !== generation.current) return;
      setResult(inspection);
      setMessage(inspection.allowed
        ? 'Eligible at the time of this read-only check. A later dispatch must independently pass all authorization and lease checks.'
        : 'Preflight denied by current authoritative checks. No execution eligibility established.');
    } catch {
      if (run === generation.current) {
        setResult(null);
        setScope(null);
        setPrepared([]);
        setChosen('');
        setMessage('Eligibility UNKNOWN: signed authorization, Action or preflight response unavailable. Read the ledger again; no automatic retry.');
      }
    } finally {
      if (run === generation.current) {
        inFlight.current = false;
        setBusy(false);
      }
    }
  }

  return <Card title="Signed MCP Action preflight — read-only eligibility">
    <div className="space-y-3 text-xs">
      <p>Checks the current signed Task, Subtask, existing prepared Action, declared READ_ONLY
        MCP tool and independent human approval. This check issues no approval, contacts no
        provider, creates no reservation and dispatches no action.</p>
      <p>Flow {flowId} · revision {revision} · {flowStatus}</p>
      <button type="button"
        className="border border-outline rounded px-3 py-2 disabled:opacity-40"
        disabled={!permitted || busy || inFlight.current}
        onClick={() => void refresh()}>
        {busy ? 'CHECKING CURRENT SIGNED CATALOG…' : 'READ PREPARED ACTIONS (NO EXECUTION)'}
      </button>
      {!permitted && <p role="status">Current verified operator, Flow and signed authorization are required.</p>}
      {scope && <div className="space-y-3 border border-outline rounded p-3">
        <label className="block space-y-1">
          <span>Existing independently approved prepared Action</span>
          <select aria-label="Prepared signed MCP Action"
            className="w-full border border-outline p-2 bg-surface-container"
            value={chosen} disabled={busy}
            onChange={event => { setChosen(event.target.value); setResult(null); setMessage(''); }}>
            <option value="">Choose an existing PREPARED Action</option>
            {prepared.map(action => <option key={action.action_id} value={action.action_id}>
              {action.action_id} · {action.server_id}/{action.tool_name} · {action.task_id}
            </option>)}
          </select>
        </label>
        <label className="block space-y-1">
          <span>Optional signed resource manifest SHA-256 (required for resource-bound Actions)</span>
          <input aria-label="Expected signed resource manifest SHA-256"
            className="w-full border border-outline p-2"
            maxLength={64} spellCheck={false}
            value={manifestSha} disabled={busy} placeholder="64 lowercase hexadecimal characters"
            onChange={event => {
              setManifestSha(event.target.value);
              setResult(null);
              setMessage('');
            }} />
        </label>
        {chosen && prepared.filter(action => action.action_id === chosen).map(action =>
          <div key={action.action_id} className="border border-outline/50 rounded p-2 space-y-1">
            <p>Task {action.task_id} · Subtask {action.subtask_id}</p>
            <p>Tool {action.server_id}/{action.tool_name} · status PREPARED</p>
            <p>Arguments SHA-256: {action.parameters_sha256}</p>
            <p>Target effects independently verified: NO · future dispatch guaranteed: NO</p>
          </div>
        )}
        <button type="button"
          className="border border-outline rounded px-3 py-2 disabled:opacity-40"
          disabled={busy || !permitted || !chosen || inFlight.current}
          onClick={() => void inspect()}>CHECK ELIGIBILITY (READ ONLY)</button>
      </div>}
      {message && <p role="status" className="text-on-surface-variant">{message}</p>}
      {result && <div role="status" className="border border-outline rounded p-3 space-y-2">
        <p><strong>{result.allowed ? 'CURRENTLY ELIGIBLE FOR INDEPENDENT DISPATCH REVIEW' : 'NOT ELIGIBLE'}</strong></p>
        <p>{result.code}: {result.reason}</p>
        {result.allowed && <>
          <p>Action {result.action_id} · {result.action_status}</p>
          <p>Signed declaration SHA-256: {result.declaration_sha256}</p>
          <p>{result.resource_bound
            ? `Approved resource SHA-256: ${result.resource_artifact_sha256}`
            : 'No Task resource binding declared'}</p>
        </>}
        <p>Read-only: YES · provider contacted: NO · approval issued: NO</p>
        <p>Dispatch performed: NO · reservation performed: NO · future dispatch guaranteed: NO</p>
        <p>Eligibility can change immediately after this check. Separate authorization and explicit
          dispatch remain mandatory. No target-effect verification is inferred.</p>
      </div>}
    </div>
  </Card>;
}
