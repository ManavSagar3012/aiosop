import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import {
  readFlowResourceAliases, previewFlowAlias, previewSignedTaskResource,
  type FlowAliases,
} from '../../services/flowResourceAliases';

interface Props { flowId: string; engagementId: string; revision: number; flowStatus: string }

/** Fully inert virtual folders; Task preview is signed admission ONLY, not a mount or tool call. */
export function FlowResourceAliasesPanel({ flowId, engagementId, revision, flowStatus }: Props) {
  const [actor, setActor] = useState(() => currentOperator());
  const [catalog, setCatalog] = useState<FlowAliases | null>(null);
  const [authorizationSha, setAuthorizationSha] = useState('');
  const [selectedArtifactId, setSelectedArtifactId] = useState('');
  const [taskId, setTaskId] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0);
  const eligible = ['pending','running'].includes(flowStatus)
    && ['operator','senior_operator'].includes(actor?.role ?? '');

  const refresh = useCallback(async () => {
    const stamp = ++epoch.current;
    setCatalog(null); setSelectedArtifactId(''); setAuthorizationSha('');
    setConfirmed(false); setMessage(''); setBusy(true);
    try {
      const signed = await supervisionApi.authorizationStatus(engagementId);
      if (signed.status !== 'active' || !signed.version || !signed.policy_sha256)
        throw new Error('Signed current authorization unavailable');
      const result = await readFlowResourceAliases(flowId, revision, signed.version);
      const readback = await supervisionApi.authorizationStatus(engagementId);
      if (readback.status !== 'active' || readback.version !== signed.version
        || readback.policy_sha256 !== signed.policy_sha256)
        throw new Error('Signed Flow authority changed');
      if (stamp !== epoch.current) return;
      setCatalog(result); setAuthorizationSha(signed.policy_sha256);
    } catch {
      if (stamp === epoch.current) {
        setCatalog(null); setAuthorizationSha('');
        setMessage('Signed resource virtual folders unavailable or revoked; no file or target action was performed.');
      }
    } finally { if (stamp === epoch.current) setBusy(false); }
  }, [engagementId, flowId, revision]);

  useEffect(() => {
    if (eligible) void refresh();
    return () => { ++epoch.current; };
  }, [eligible, refresh]);
  useEffect(() => subscribeOperator(next => {
    ++epoch.current; setActor(next); setCatalog(null); setAuthorizationSha('');
    setSelectedArtifactId(''); setConfirmed(false);
    setMessage('Operator changed. Current signed Flow resource snapshot cleared.');
  }), []);

  async function previewArtifact(artifactId: string) {
    if (!catalog || busy) return;
    const stamp = ++epoch.current;
    setBusy(true); setMessage('');
    try {
      const current = await supervisionApi.authorizationStatus(engagementId);
      if (current.status !== 'active' || current.version !== catalog.authorization_version
        || current.policy_sha256 !== authorizationSha) throw new Error('Signer changed');
      const item = await previewFlowAlias(flowId, revision, catalog.authorization_version,
        catalog.source_manifest_sha256, artifactId);
      const after = await supervisionApi.authorizationStatus(engagementId);
      if (after.status !== 'active' || after.version !== current.version
        || after.policy_sha256 !== current.policy_sha256) throw new Error('Signer changed during preview');
      if (stamp === epoch.current) {
        setSelectedArtifactId(item.artifact_id);
        setConfirmed(false);
        setMessage(`Verified metadata-only preview for ${item.original_name} (SHA-256 ${item.sha256}). No artifact bytes were exposed.`);
      }
    } catch {
      if (stamp === epoch.current) {
        setSelectedArtifactId(''); setCatalog(null);
        setMessage('Resource preview changed or UNKNOWN. Read current signed Flow again.');
      }
    } finally { if (stamp === epoch.current) setBusy(false); }
  }

  async function taskPreflight() {
    const item = catalog?.items.find(entry => entry.artifact_id === selectedArtifactId);
    if (!catalog || !item || !confirmed || !/^task-[A-Za-z0-9._:-]{1,85}$/.test(taskId) || busy)
      return;
    if (!window.confirm(`Check exact signed Task ${taskId} eligibility to READ inert artifact ${item.original_name}?
This sends no file to a worker and starts no tool or target execution.
If HTTP response is UNKNOWN, do not automatically retry; manually inspect signed Task state.`))
      return;
    const stamp = ++epoch.current;
    setBusy(true); setMessage('');
    try {
      const signed = await supervisionApi.authorizationStatus(engagementId);
      if (signed.status !== 'active' || signed.version !== catalog.authorization_version
        || signed.policy_sha256 !== authorizationSha) throw new Error('Signer changed');
      const result = await previewSignedTaskResource({
        flowId, engagementId, revision, version: catalog.authorization_version,
        taskId, artifactId: item.artifact_id, artifactSha: item.sha256,
        authorizationSha, manifestSha: catalog.source_manifest_sha256, confirmed: true,
      });
      const after = await supervisionApi.authorizationStatus(engagementId);
      if (after.status !== 'active' || after.version !== signed.version
        || after.policy_sha256 !== signed.policy_sha256)
        throw new Error('Signer changed after preview');
      if (stamp === epoch.current) {
        setConfirmed(false);
        setMessage(`Current Task eligibility PREVIEW passed. Approved-command SHA ${result.approved_command_sha256}; no worker transfer or execution.`);
      }
    } catch {
      if (stamp === epoch.current) {
        setConfirmed(false); setCatalog(null);
        setMessage('Approved Task preflight denied or outcome UNKNOWN. No execution or file transfer is claimed.');
      }
    } finally { if (stamp === epoch.current) setBusy(false); }
  }

  return <Card title="Signed Flow virtual resources — read-only">
    <div className="space-y-2 text-xs">
      <p>Immutable PostgreSQL Flow artifacts are organized into deterministic text/source VIRTUAL folders.
        Aliases are NOT persisted file moves, copied folders, container mounts or worker synchronization.
        Every artifact byte remains untrusted as instructions or a verified finding.</p>
      <button type="button" disabled={!eligible || busy} onClick={() => void refresh()}>READ SIGNED VIRTUAL FOLDERS</button>
      {message && <p role="alert">{message}</p>}
      {catalog && <div role="status" className="space-y-2">
        <p>Manifest SHA-256: <code>{catalog.source_manifest_sha256}</code> · {catalog.count} inert artifacts.
          Aliases persisted: NO · worker sync: NO.</p>
        {catalog.folders.map(folder => <p key={folder.path}>{folder.path}: {folder.count} entries</p>)}
        {catalog.items.map(item => <div key={item.artifact_id} className="border border-outline p-2 space-y-1">
          <p className="break-all">{item.alias_path}</p>
          <p>SHA-256: {item.sha256}, {item.size_bytes} bytes, type {item.classification}.</p>
          <button type="button" disabled={busy} onClick={() => void previewArtifact(item.artifact_id)}>
            PREVIEW METADATA ONLY
          </button>
        </div>)}
        <div className="border-t border-outline pt-2 space-y-2">
          <p>Optional current human-approved Task preflight (checks current signed Task,
            lease, command and source SHA only; never transfers resource bytes).</p>
          <p>Selected immutable artifact: {selectedArtifactId || 'none'}</p>
          <label>Existing signed Task ID<input className="block border p-2 w-full" value={taskId}
            maxLength={90} onChange={event => { setTaskId(event.target.value); setConfirmed(false); }}
            placeholder="task-…" /></label>
          <label className="flex items-start gap-2"><input type="checkbox"
            checked={confirmed} onChange={event => setConfirmed(event.target.checked)}
            disabled={!selectedArtifactId || !taskId || busy}/>
            I acknowledge a successful preflight is NOT tool execution, container sync, vulnerability verification or human report release.
          </label>
          <button type="button" disabled={!selectedArtifactId || !confirmed || !eligible || busy}
            onClick={() => void taskPreflight()}>CHECK CURRENT SIGNED TASK ELIGIBILITY (NO EXECUTION)</button>
        </div>
      </div>}
    </div>
  </Card>;
}
