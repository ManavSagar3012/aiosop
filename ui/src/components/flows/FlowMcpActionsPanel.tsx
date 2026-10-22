import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import { readSignedToolCatalog, type SignedToolCatalog } from '../../services/mcpToolCatalog';
import {
  listFlowMcpActions, prepareFlowMcpAction, dispatchFlowMcpAction,
  reconcileSignedMcpAction,
  type FlowMcpAction, type McpActionScope,
} from '../../services/flowMcpActions';

interface Props {
  flowId: string;
  engagementId: string;
  revision: number;
  flowStatus: string;
  authorizationId?: string | null;
}

// This panel has signed *declarations*, not an independently qualified native
// execution channel for these integrations. Keep them visible as diagnostics,
// but do not offer their manifests as operational choices.
const UNQUALIFIED_NATIVE_SERVERS = new Set([
  'source-map-mcp', 'cloud-mcp', 'turbo-intruder-mcp',
]);

const ACTION_STATUS_LABELS: Record<FlowMcpAction['status'], string> = {
  prepared: 'PREPARED intent in Action ledger; no MCP dispatch recorded',
  reserved: 'RESERVED in Action ledger; external outcome UNKNOWN',
  unknown: 'UNKNOWN original Action outcome; original dispatch must NOT be retried',
  finished: 'FINISHED in Action ledger; provider/tool status only',
  cancelled: 'CANCELLED in Action ledger; remote termination not independently proven',
};

/** Catalog declarations are candidates only; never runtime health proof. */
export function declaredActionChoices(catalog: SignedToolCatalog | null) {
  return catalog?.servers.flatMap(server =>
    !UNQUALIFIED_NATIVE_SERVERS.has(server.server_id)
    && server.manifest_initialized && server.circuit_state === 'closed'
      ? server.tools.filter(tool => tool.side_effect_class === 'READ_ONLY'
        && tool.declared_scope_check)
        .map(tool => ({server_id: server.server_id, tool_name: tool.name}))
      : []
  ) ?? [];
}

export function allowsSignedActionDispatch(action: FlowMcpAction): boolean {
  return action.status === 'prepared' && !UNQUALIFIED_NATIVE_SERVERS.has(action.server_id);
}

/** Ledger state and provider testimony never promote to verified target effects. */
export function McpActionAuthorityLabels({action}: {action: FlowMcpAction}) {
  return <div className="space-y-1" aria-label={`Authority for ${action.action_id}`}>
    <p>Durable Action status: {ACTION_STATUS_LABELS[action.status]}</p>
    <p>Original execution request: {action.request_id ?? 'not recorded in readback'}.
      {' '}Execution started: {action.execution_started ? 'recorded by Action ledger' : 'not recorded by Action ledger'}.
      {' '}External execution outcome: {action.status==='finished' ? 'provider/tool reported finished; target outcome UNKNOWN' : 'UNKNOWN or not executed'}.</p>
    {action.receipt_sha256 && <p>Provider status receipt digest stored: {action.receipt_sha256.slice(0,16)}…
      {' '}Receipt authenticity is limited to the provider status assertion.</p>}
    <p>Independent target-owner effect evidence: NOT PRESENT in this Action readback.
      {' '}Target effect verified: {action.target_effect_verified ? 'YES' : 'NO'}.
      {' '}Safe automatic replay: {action.safe_to_automatically_retry ? 'YES' : 'NO'}.</p>
    {action.status==='unknown' && <p role="alert">Original 0027 Action outcome UNKNOWN.
      {' '}Do not resend the dispatch or infer success from a lost HTTP acknowledgement.
      {' '}Only read the ledger or submit independently signed provider STATUS for the same request.</p>}
  </div>;
}

/** Prepared actions are NOT the inert human-review proposals and never authorize themselves. */
export function FlowMcpActionsPanel({flowId, engagementId, revision, flowStatus, authorizationId}: Props) {
  const [actor, setActor] = useState(() => currentOperator());
  const [scope, setScope] = useState<McpActionScope|null>(null);
  const [actions, setActions] = useState<FlowMcpAction[]>([]);
  const [tools, setTools] = useState<SignedToolCatalog|null>(null);
  const [taskId, setTaskId] = useState('');
  const [subtaskId, setSubtaskId] = useState('');
  const [chosen, setChosen] = useState('');
  const [target, setTarget] = useState('');
  const [providerReceipt, setProviderReceipt] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const epoch = useRef(0);
  const active = ['pending','running'].includes(flowStatus);
  const permitted = active && ['operator','senior_operator'].includes(actor?.role ?? '');
  const declaredTools = declaredActionChoices(tools);
  const currentTool = declaredTools.find(item => `${item.server_id}/${item.tool_name}` === chosen);

  const currentScope = useCallback(async (previous?:McpActionScope):Promise<McpActionScope> => {
    if (!authorizationId || !permitted) throw new Error('Current Flow owner unavailable.');
    const status = await supervisionApi.authorizationStatus(engagementId);
    if (status.status!=='active' || !Number.isSafeInteger(status.version)
      || (status.version ?? 0)<1 || !/^[0-9a-f]{64}$/.test(status.policy_sha256 ?? ''))
      throw new Error('Current signed ROE unavailable.');
    const value = {
      flowId, engagementId, flowRevision:revision, authorizationVersion:status.version!,
      authorizationId,authorizationSha256:status.policy_sha256!,
    };
    if (previous && (previous.flowId!==value.flowId || previous.engagementId!==value.engagementId
      || previous.flowRevision!==value.flowRevision || previous.authorizationVersion!==value.authorizationVersion
      || previous.authorizationId!==value.authorizationId
      || previous.authorizationSha256!==value.authorizationSha256))
      throw new Error('Signed authority changed.');
    return value;
  },[authorizationId,permitted,engagementId,flowId,revision]);

  const refresh = useCallback(async () => {
    const run = ++epoch.current;
    setBusy(true);setScope(null);setTools(null);setActions([]);setMessage('');
    try {
      const signed = await currentScope();
      const declarations = await readSignedToolCatalog(
        engagementId,flowId,revision,signed.authorizationVersion);
      const latest = await listFlowMcpActions(signed);
      await currentScope(signed);
      if (run!==epoch.current) return;
      setScope(signed);setTools(declarations);setActions(latest);
      setMessage('Read current signed Task-bound MCP actions. No execution initiated by refresh.');
    } catch {
      if (run===epoch.current) {
        setScope(null);setActions([]);setTools(null);
        setMessage('Signed MCP actions unavailable/revoked. No provider status or target effect can be assumed.');
      }
    } finally {if (run===epoch.current) setBusy(false);}
  },[engagementId,flowId,revision,currentScope]);

  useEffect(() => {
    if (permitted) void refresh();
    return () => {++epoch.current;};
  },[permitted,refresh]);
  useEffect(()=>subscribeOperator(next => {
    ++epoch.current;setActor(next);setScope(null);setTools(null);setActions([]);
    setConfirmed(false);setMessage('Operator identity changed; read signed action state again.');
  }),[]);

  async function prepare() {
    if (!scope || !currentTool || !confirmed || !permitted || busy) return;
    if (!window.confirm(
      `Prepare a separate signed MCP action for ${currentTool.server_id}/${currentTool.tool_name}?\n`
      + 'The server MUST already possess the matching current Task/Subtask/Action, signed ROE, active lease and independently approved human Task payload. '
      + 'This only writes a PREPARED intent; it does NOT dispatch an MCP call. No retries after UNKNOWN.'
    )) return;
    const run=++epoch.current;setBusy(true);setMessage('');
    try {
      await currentScope(scope);
      const params:Record<string,string|number|boolean> = target.trim() ? {target:target.trim()} : {};
      const created=await prepareFlowMcpAction(scope,{
        taskId,subtaskId,serverId:currentTool.server_id,toolName:currentTool.tool_name,
        parameters:params,confirmed:true,
      });
      await currentScope(scope);
      const next=await listFlowMcpActions(scope);
      if (!next.some(item=>item.action_id===created.action_id
        && item.status==='prepared' && item.parameters_sha256===created.parameters_sha256))
        throw new Error('Prepared action missing in current signed readback.');
      if (run===epoch.current) {
        setActions(next);setConfirmed(false);
        setMessage(`Prepared ${created.action_id}; no MCP call started. Separate explicit dispatch and current trusted approval are still mandatory.`);
      }
    } catch {
      if (run===epoch.current) {
        setScope(null);setActions([]);setConfirmed(false);
        setMessage('Prepare rejected or outcome UNKNOWN. Manually read signed action ledger; never repeat an uncertain POST.');
      }
    } finally {if (run===epoch.current)setBusy(false);}
  }

  async function dispatch(action:FlowMcpAction) {
    if (!scope || !permitted || busy || !allowsSignedActionDispatch(action)
      || !confirmed || action.flow_id!==flowId || action.engagement_id!==engagementId) return;
    if (!window.confirm(
      `ONE-TIME remote dispatch of signed approved Action ${action.action_id}?\n`
      + 'This may contact only a currently authorized target. The backend must independently recheck persisted human approval, signed Task/Action, ROE, lease, budget and remote tool. '
      + 'An uncertain provider result becomes UNKNOWN and MUST NOT be automatically replayed.'
    )) return;
    const run=++epoch.current;setBusy(true);setMessage('');
    try {
      await currentScope(scope);
      const completed=await dispatchFlowMcpAction(scope,action.action_id,true);
      await currentScope(scope);
      const next=await listFlowMcpActions(scope);
      if (!next.some(item=>item.action_id===completed.action_id
        && item.status===completed.status && item.parameters_sha256===completed.parameters_sha256))
        throw new Error('Durable dispatch readback changed.');
      if(run===epoch.current) {
        setActions(next);setConfirmed(false);
        setMessage(`Action ${completed.action_id}: ${completed.status}. Tool/provider result is NOT independently verified target effect.`);
      }
    } catch {
      if(run===epoch.current) {
        setScope(null);setActions([]);setConfirmed(false);
        setMessage('Remote dispatch outcome UNKNOWN or rejected. Manually inspect signed ledger; DO NOT retry consequential execution.');
      }
    } finally {if(run===epoch.current)setBusy(false);}
  }

  async function reconcile(action:FlowMcpAction) {
    if(!scope || !permitted || busy || !confirmed || action.status!=='unknown'
      || providerReceipt.length<50 || providerReceipt.length>4096) return;
    if(!window.confirm(
      `Record independently provider-signed STATUS for UNKNOWN Action ${action.action_id}?\n`
      + 'This does NOT rerun the MCP tool and NEVER establishes target-effect or vulnerability verification. '
      + 'The server must independently verify its configured Ed25519 provider key and the exact original execution identity.'
    ))return;
    const run=++epoch.current;setBusy(true);setMessage('');
    try {
      await currentScope(scope);
      const settled=await reconcileSignedMcpAction(scope,action,providerReceipt,true);
      await currentScope(scope);
      const all=await listFlowMcpActions(scope);
      if(!all.some(row=>row.action_id===settled.action_id && row.status===settled.status
        && row.target_effect_verified===false))throw new Error('Signed status not in ledger');
      if(run===epoch.current){setActions(all);setProviderReceipt('');setConfirmed(false);
        setMessage(`Provider-asserted STATUS ${settled.status} recorded; independent TARGET effect remains unverified.`);}
    } catch {
      if(run===epoch.current){setScope(null);setActions([]);setProviderReceipt('');setConfirmed(false);
        setMessage('Signed provider receipt rejected or reconciliation UNKNOWN. Read durable status; never retry or execute automatically.');}
    } finally {if(run===epoch.current)setBusy(false);}
  }

  return <Card title="Flow MCP approved actions — separately authorized execution">
    <div className="space-y-2 text-xs">
      <p>This workflow is separate from the NON-DISPATCHABLE human-review marker.
        Selecting a tool or clicking a confirmation does NOT grant execution authority.
        Server must verify an independently approved current Task/Subtask/Action,
        signed rules of engagement, lease and budget before any remote call.</p>
      <p>Signed Action GET returns durable PostgreSQL state, not an independently authenticated
        target-owner response. An HTTP success, tool result, provider-signed STATUS or
        SourceMap 0036 schema does not verify a target effect. Original 0027 UNKNOWN
        execution must be read back and never automatically retried.</p>
      <p>Flow {flowId} · revision {revision} · {flowStatus}</p>
      <button type="button" disabled={!permitted || busy} className="border border-outline px-3 py-2 disabled:opacity-40"
        onClick={()=>void refresh()}>{busy?'CHECKING SIGNED ACTIONS…':'READ SIGNED ACTION LEDGER (NO EXECUTION)'}</button>
      {message&&<p role="status">{message}</p>}
      {scope&&<div className="border border-outline p-3 space-y-2">
        <p>Tool catalog: declarations only; runtime health and dispatch authority UNVERIFIED.
          Cloud/Turbo readiness is not established. Native SourceMap 0036 staging/schema
          is not an operational capability in this panel. These three integrations
          are excluded from the Action preparation selector pending independent qualification.</p>
        <p>Prepare a separately Task-approved <strong>READ_ONLY</strong> MCP action. An existing approved
          signed Task payload must already pin its action identity, arguments SHA, Flow authority and human approval.</p>
        <label className="block">Existing approved Task ID
          <input aria-label="Approved MCP Task ID" className="w-full border border-outline p-2"
            value={taskId} maxLength={96} onChange={e=>{setTaskId(e.target.value);setConfirmed(false);}}/></label>
        <label className="block">Existing signed Subtask ID
          <input aria-label="Signed MCP Subtask ID" className="w-full border border-outline p-2"
            value={subtaskId} maxLength={96} onChange={e=>{setSubtaskId(e.target.value);setConfirmed(false);}}/></label>
        <label className="block">Initialized read-only tool declaration
          <select aria-label="Read-only registered MCP tool" value={chosen}
            className="w-full border border-outline p-2" onChange={e=>{setChosen(e.target.value);setConfirmed(false);}}>
            <option value="">Select currently declared tool</option>
            {declaredTools.map(tool=><option key={`${tool.server_id}/${tool.tool_name}`}
              value={`${tool.server_id}/${tool.tool_name}`}>
              {tool.server_id}/{tool.tool_name} — declaration only, runtime unverified
            </option>)}</select></label>
        <label className="block">Explicit authorized HTTPS target (only if signed Task pins one)
          <input aria-label="Authorized MCP target" className="w-full border border-outline p-2"
            value={target} maxLength={400} placeholder="https://scope.example.test/path"
            onChange={e=>{setTarget(e.target.value);setConfirmed(false);}}/></label>
        <label className="flex gap-2 items-start">
          <input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)} disabled={!permitted||busy}/>
          I acknowledge that preparing does NOT execute, remote dispatch may have an UNKNOWN outcome,
          and only a real separate signed approval can authorize action execution.
        </label>
        <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
          disabled={!permitted||busy||!confirmed||!currentTool||!taskId||!subtaskId}
          onClick={()=>void prepare()}>PREPARE SIGNED TASK ACTION (NO EXECUTION)</button>
      </div>}
      {scope&&<div className="space-y-2">
        <strong>Durable Action readback</strong>
        {actions.length===0&&<p>No signed approved MCP actions recorded for this Flow.</p>}
        {actions.map(action=><div key={action.action_id} className="border border-outline p-2 space-y-1">
          <p>{action.action_id} · {action.server_id}/{action.tool_name} · {action.status}</p>
          <p>Task {action.task_id} · signed Subtask {action.subtask_id} · argument SHA {action.parameters_sha256.slice(0,16)}…</p>
          <McpActionAuthorityLabels action={action}/>
          {UNQUALIFIED_NATIVE_SERVERS.has(action.server_id)&&<p>
            SourceMap/Cloud/Turbo Action readback is historical ledger metadata only here.
            Operational readiness is not established; dispatch is unavailable from this console.</p>}
          {allowsSignedActionDispatch(action)
            &&<button type="button" disabled={!permitted||busy||!confirmed}
            className="border border-outline px-3 py-2 disabled:opacity-40"
            onClick={()=>void dispatch(action)}>EXPLICIT ONE-TIME APPROVED MCP DISPATCH</button>}
          {action.status==='unknown'&&<div className="space-y-2">
            <p>UNKNOWN outcome is quarantined; never auto-retry. Only an original, current, provider-signed terminal-status receipt may be submitted for verification.</p>
            <label className="block">Provider-signed original status receipt JSON (not a target-effect proof)
              <textarea aria-label={`Signed MCP receipt for ${action.action_id}`} className="w-full border border-outline p-2"
                value={providerReceipt} maxLength={4096} rows={3}
                onChange={e=>{setProviderReceipt(e.target.value);setConfirmed(false);}} />
            </label>
            <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
              disabled={!permitted||busy||!confirmed||providerReceipt.length<50}
              onClick={()=>void reconcile(action)}>VERIFY SIGNED PROVIDER STATUS (NO MCP REPLAY)</button>
          </div>}
        </div>)}
      </div>}
    </div>
  </Card>;
}
