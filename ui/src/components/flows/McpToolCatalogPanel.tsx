import { useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import { readSignedToolCatalog, type SignedToolCatalog } from '../../services/mcpToolCatalog';
import { proposeDeclaredToolReview, priorToolProposalAttempt } from '../../services/flowToolProposals';

interface Props {
  engagementId: string;
  flowId: string;
  revision: number;
  flowStatus: string;
  objectives?: { id: string; title: string }[];
  onProposed?: () => void;
}

/** Read-only discovery can create a signed, inert *human review proposal*, NEVER run MCP. */
export function McpToolCatalogPanel({ engagementId, flowId, revision, flowStatus, objectives = [], onProposed }: Props) {
  const [actor, setActor] = useState(() => currentOperator());
  const [catalog, setCatalog] = useState<SignedToolCatalog | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [selectedTool, setSelectedTool] = useState('');
  const [parentTaskId, setParentTaskId] = useState('');
  const [reviewed, setReviewed] = useState(false);
  const [knownVersion, setKnownVersion] = useState<number | null>(null);
  const epoch = useRef(0);
  const active = flowStatus === 'running' || flowStatus === 'pending';
  const eligible = active && (actor?.role === 'operator' || actor?.role === 'senior_operator')
    && currentOperator()?.sub === actor.sub;

  useEffect(() => {
    ++epoch.current; setCatalog(null); setMessage(''); setBusy(false);
    setSelectedTool(''); setParentTaskId(''); setReviewed(false); setKnownVersion(null);
    return () => { ++epoch.current; };
  }, [engagementId, flowId, revision, flowStatus]);
  useEffect(() => subscribeOperator(next => {
    ++epoch.current; setCatalog(null); setMessage(''); setBusy(false);
    setSelectedTool(''); setParentTaskId(''); setReviewed(false); setKnownVersion(null); setActor(next);
  }), []);

  async function inspect() {
    if (!eligible || busy || !actor?.sub) return;
    const requestId = ++epoch.current;
    const principal = actor.sub;
    setCatalog(null); setMessage(''); setBusy(true);
    try {
      const before = await supervisionApi.authorizationStatus(engagementId);
      if (before.status !== 'active' || typeof before.version !== 'number' || before.version < 1)
        throw new Error('Current signed ROE unavailable.');
      const read = await readSignedToolCatalog(engagementId, flowId, revision, before.version);
      const after = await supervisionApi.authorizationStatus(engagementId);
      if (after.status !== 'active' || after.version !== before.version)
        throw new Error('Current signed ROE changed.');
      if (requestId !== epoch.current || currentOperator()?.sub !== principal) return;
      setCatalog(read);
      setKnownVersion(before.version);
    } catch {
      if (requestId === epoch.current) {
        setCatalog(null);
        setMessage('Signed tool declarations unavailable, changed or revoked. No tool execution was approved.');
      }
    } finally {
      if (requestId === epoch.current) setBusy(false);
    }
  }

  async function propose() {
    const [serverId, toolName] = selectedTool.split('/', 2);
    const capability = catalog?.servers.find(server => server.server_id === serverId)
      ?.tools.find(tool => tool.name === toolName);
    const attemptKey = JSON.stringify([actor?.sub, flowId, revision, parentTaskId, serverId, toolName]);
    if (!eligible || busy || !reviewed || !capability || knownVersion === null
      || !parentTaskId || !objectives.some(item => item.id === parentTaskId)
      || priorToolProposalAttempt(attemptKey)) return;
    if (!window.confirm(
      `Create one PENDING human review subtask for ${serverId}/${toolName} under ${parentTaskId}?\n`
      + 'No MCP call, browser navigation, scanning, provider spend or target verification will occur. '
      + 'Unknown POST acknowledgments must be resolved by manually refreshing Flow; do NOT retry.'
    )) return;
    const requestId = ++epoch.current;
    const principal = actor?.sub;
    setBusy(true); setMessage('');
    try {
      const before = await supervisionApi.authorizationStatus(engagementId);
      if (before.status !== 'active' || before.version !== knownVersion)
        throw new Error('ROE changed');
      const result = await proposeDeclaredToolReview({
        flowId, engagementId, objectiveTaskId: parentTaskId,
        serverId, toolName, expectedFlowRevision: revision,
        expectedAuthorizationVersion: before.version, explicitHumanConfirmation: true,
      });
      const after = await supervisionApi.authorizationStatus(engagementId);
      if (after.status !== 'active' || after.version !== before.version)
        throw new Error('Signed authorization changed after write');
      if (requestId !== epoch.current || currentOperator()?.sub !== principal) return;
      setCatalog(null); setSelectedTool(''); setReviewed(false);
      setMessage(`Persisted pending human-only subtask ${result.subtask_id}. No execution occurred. Refresh Flow plan.`);
      onProposed?.();
    } catch {
      if (requestId === epoch.current) {
        setCatalog(null); setReviewed(false);
        setMessage('Tool proposal rejected or outcome UNKNOWN. Manually READ current Flow; never automatically retry POST.');
      }
    } finally {
      if (requestId === epoch.current) setBusy(false);
    }
  }

  return <Card title="Signed Flow MCP tool catalog — declarations only">
    <div className="space-y-2 text-xs" aria-label="Signed Flow tool declarations">
      <p>Browse the initialized, locally registered MCP tool *declarations* for the current signed Flow.
        This does NOT probe providers, run tools, verify runtime reachability or grant execution.
        Every actual task still requires signed scope, Task/Subtask authorization and human approval where required.</p>
      <p>Flow {flowId} · revision {revision} · {flowStatus}</p>
      <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
        onClick={() => void inspect()} disabled={!eligible || busy}>
        {busy ? 'CHECKING CURRENT SIGNED DECLARATIONS…' : 'READ DECLARED TOOLS (GET ONLY)'}
      </button>
      {message && <p role="alert">{message}</p>}
      {catalog && <div role="status" className="space-y-2">
        <p>Catalog: declarations_only_unverified · signed authorization version {catalog.authorization_version}
          · execution authorized: NO · live tool health verified: NO.</p>
        {catalog.servers.length === 0 && <p>No registered MCP services were declared.</p>}
        {catalog.servers.map(server => <div key={server.server_id} className="border border-outline p-2 space-y-1">
          <p><strong>{server.server_id}</strong> · {server.manifest_initialized ? 'manifest initialized' : 'not initialized'}
            · circuit {server.circuit_state}</p>
          {server.tools.map(tool => <label key={tool.name} className="flex items-start gap-2 font-mono break-all">
            <input type="radio" name={`mcp-tool-${flowId}`}
              checked={selectedTool === `${server.server_id}/${tool.name}`}
              onChange={() => { setSelectedTool(`${server.server_id}/${tool.name}`); setReviewed(false); }}
              disabled={busy || !eligible || !server.manifest_initialized || server.circuit_state !== 'closed'
                || !tool.declared_scope_check}/>
            <span>{tool.name} · {tool.side_effect_class} · declared approval: {tool.declared_requires_approval ? 'yes' : 'no'}
              · authorized for execution: NO</span>
          </label>)}
        </div>)}
        <div className="border-t border-outline pt-2 space-y-2">
          <p>Optional follow-up: turn a declared capability into an inert persisted Flow *review proposal*.
            It has no tool arguments, no provider execution and cannot be dispatched directly from this panel.</p>
          <label className="block">Parent planned Task objective
            <select aria-label="Parent objective for MCP tool review"
              value={parentTaskId} onChange={event => { setParentTaskId(event.target.value); setReviewed(false); }}
              disabled={!eligible || busy} className="block w-full border border-outline p-2 bg-background text-on-surface">
              <option value="">Select a current planned objective</option>
              {objectives.map(objective => <option key={objective.id} value={objective.id}>
                {objective.title.slice(0, 90)}
              </option>)}
            </select>
          </label>
          <label className="flex items-start gap-2">
            <input type="checkbox" checked={reviewed} onChange={event => setReviewed(event.target.checked)}
              disabled={!eligible || !selectedTool || !parentTaskId || busy}/>
            <span>I confirm this creates a pending HUMAN REVIEW subtask only; a further signed Task/Action and approval are required for any consequential execution.</span>
          </label>
          <button type="button" className="border border-outline px-3 py-2 disabled:opacity-40"
            onClick={() => void propose()} disabled={!eligible || busy || !reviewed || !selectedTool
              || !parentTaskId || !knownVersion
              || priorToolProposalAttempt(JSON.stringify([actor?.sub, flowId, revision, parentTaskId,
                ...selectedTool.split('/', 2)]))}>
            RECORD PENDING TOOL REVIEW (NO EXECUTION)
          </button>
        </div>
      </div>}
    </div>
  </Card>;
}
