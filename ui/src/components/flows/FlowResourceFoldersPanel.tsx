import { useCallback, useEffect, useRef, useState } from 'react';
import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { supervisionApi } from '../../services/supervision';
import { flowArtifactsApi, type FlowResourceManifest } from '../../services/flowArtifacts';
import {
  flowResourceFoldersApi, type FlowResourceFolderCatalog, type ResourceFolderScope,
  type FolderMutation,
} from '../../services/flowResourceFolders';

interface Props {
  flowId: string;
  engagementId: string;
  revision: number;
  flowStatus: string;
  authorizationId?: string | null;
}

function exactInertManifest(
  catalog: FlowResourceFolderCatalog,
  manifest: FlowResourceManifest,
): void {
  const indexed = new Map(manifest.items.map(item => [item.artifact_id, item]));
  const metadata = [...catalog.unassigned, ...catalog.folders.flatMap(folder => folder.items)];
  if (metadata.length !== manifest.count || indexed.size !== metadata.length
    || metadata.some(item => {
      const original = indexed.get(item.artifact_id);
      return !original || original.sha256 !== item.artifact_sha256
        || original.name !== item.original_name
        || original.classification !== item.classification
        || original.size_bytes !== item.size_bytes;
    }))
    throw new Error('Folder entries are not exact signed source manifest metadata.');
}

/** Persisted, signed, metadata-only VIRTUAL folders; no file movement or execution. */
export function FlowResourceFoldersPanel({
  flowId, engagementId, revision, flowStatus, authorizationId,
}: Props) {
  const [actor, setActor] = useState(() => currentOperator());
  const [scope, setScope] = useState<ResourceFolderScope | null>(null);
  const [catalog, setCatalog] = useState<FlowResourceFolderCatalog | null>(null);
  const [manifest, setManifest] = useState<FlowResourceManifest | null>(null);
  const [name, setName] = useState('');
  const [selectedFolder, setSelectedFolder] = useState('');
  const [selectedArtifact, setSelectedArtifact] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const generation = useRef(0);
  const pending = useRef(false);
  const permitted = ['pending', 'running'].includes(flowStatus)
    && ['operator', 'senior_operator'].includes(actor?.role ?? '');

  const clear = () => {
    setScope(null); setCatalog(null); setManifest(null);
    setSelectedFolder(''); setSelectedArtifact(''); setConfirmed(false);
  };
  const validateSignature = useCallback(async (expected?: ResourceFolderScope): Promise<ResourceFolderScope> => {
    if (!authorizationId || !permitted) throw new Error('Signed owner and active Flow required.');
    const current = await supervisionApi.authorizationStatus(engagementId);
    if (current.status !== 'active'
      || !Number.isSafeInteger(current.version) || (current.version ?? 0) < 1
      || !/^[0-9a-f]{64}$/.test(current.policy_sha256 ?? ''))
      throw new Error('Current signed ROE is unavailable.');
    await flowArtifactsApi.currentResourceFlow(flowId, engagementId, revision);
    const value: ResourceFolderScope = {
      flowId, engagementId, flowRevision:revision,
      authorizationVersion:current.version!,
      authorizationId, authorizationSha256:current.policy_sha256!,
      manifestSha256:expected?.manifestSha256 ?? '',
    };
    if (expected && (expected.flowId !== flowId || expected.engagementId !== engagementId
      || expected.flowRevision !== revision
      || expected.authorizationId !== authorizationId
      || expected.authorizationVersion !== current.version
      || expected.authorizationSha256 !== current.policy_sha256))
      throw new Error('Current signed Flow/authorization changed.');
    return value;
  }, [authorizationId, engagementId, flowId, permitted, revision]);

  const refresh = useCallback(async () => {
    const epoch = ++generation.current;
    setBusy(true); clear(); setMessage('');
    try {
      const signed = await validateSignature();
      const latestManifest = await flowArtifactsApi.resourceManifest(
        flowId, revision, signed.authorizationVersion,
      );
      if (latestManifest.flow_id !== flowId
        || latestManifest.flow_revision !== revision
        || latestManifest.authorization_version !== signed.authorizationVersion
        || !/^[0-9a-f]{64}$/.test(latestManifest.manifest_sha256))
        throw new Error('Current immutable source manifest unavailable.');
      const fenced = { ...signed, manifestSha256:latestManifest.manifest_sha256 };
      const metadata = await flowResourceFoldersApi.read(fenced);
      exactInertManifest(metadata,latestManifest);
      await validateSignature(fenced);
      const later = await flowArtifactsApi.resourceManifest(
        flowId, revision, signed.authorizationVersion,
      );
      if (later.manifest_sha256 !== fenced.manifestSha256)
        throw new Error('Source manifest changed during folder readback.');
      if (generation.current !== epoch) return;
      setScope(fenced); setCatalog(metadata); setManifest(latestManifest);
      setMessage('Current signed PostgreSQL folder metadata read. No files moved, synced or executed.');
    } catch {
      if (generation.current === epoch) {
        clear();
        setMessage('Signed Flow folder catalog unavailable or stale. No resource execution or file operation occurred.');
      }
    } finally {
      if (generation.current === epoch) setBusy(false);
    }
  }, [flowId, revision, validateSignature]);

  useEffect(() => {
    if (permitted) void refresh();
    else clear();
    return () => { ++generation.current; };
  }, [permitted, refresh]);
  useEffect(() => subscribeOperator(next => {
    ++generation.current; setActor(next); clear();
    setMessage('Operator identity changed; review the current signed Flow again.');
  }), []);

  async function perform(action: FolderMutation): Promise<void> {
    if (!scope || !catalog || !manifest || !permitted || !confirmed
      || busy || pending.current) return;
    const details = action.operation === 'create' || action.operation === 'rename'
      ? action.name : action.operation === 'assign' || action.operation === 'unassign'
        ? `${action.artifact_id} (SHA-256 ${action.artifact_sha256})`
        : action.folder_id;
    if (!window.confirm(
      `Confirm virtual metadata ${action.operation} at EXACT catalog revision ${catalog.catalog_revision}?\n`
      + `${details}\nNo byte transfer, copy, sync, file creation, worker mount, executable action, or finding approval occurs.\n`
      + 'A lost POST response remains UNKNOWN; never automatically resend it.',
    )) return;
    pending.current = true;
    const epoch = ++generation.current;
    setBusy(true); setMessage('');
    try {
      const before = await validateSignature(scope);
      const source = await flowArtifactsApi.resourceManifest(
        flowId, revision, scope.authorizationVersion,
      );
      if (before.authorizationSha256 !== scope.authorizationSha256
        || source.manifest_sha256 !== scope.manifestSha256)
        throw new Error('Manifest or ROE changed before mutation.');
      // Local manifest is only an identity fence: DB/review approval remains
      // authoritative for assignments; never claim local SHA proves approval.
      if (action.operation === 'assign' || action.operation === 'unassign') {
        if (!source.items.some(item => item.artifact_id === action.artifact_id
          && item.sha256 === action.artifact_sha256))
          throw new Error('Artifact no longer present in signed manifest.');
      }
      const updated = await flowResourceFoldersApi.mutate(scope,catalog,action,true);
      exactInertManifest(updated,source);
      await validateSignature(scope);
      const after = await flowArtifactsApi.resourceManifest(
        flowId, revision, scope.authorizationVersion,
      );
      if (after.manifest_sha256 !== scope.manifestSha256)
        throw new Error('Manifest changed after folder request.');
      if (generation.current !== epoch) return;
      setCatalog(updated); setConfirmed(false); setName('');
      setMessage(`Signed GET readback confirmed catalog revision ${updated.catalog_revision}. `
        + 'Persisted VIRTUAL metadata only; independent senior artifact approval is still required for assignments.');
    } catch {
      if (generation.current === epoch) {
        clear();
        setMessage('Folder POST denied or outcome UNKNOWN. Manually READ current signed Flow catalog. Do NOT repeat the POST; no file sync or execution is claimed.');
      }
    } finally {
      pending.current = false;
      if (generation.current === epoch) setBusy(false);
    }
  }

  const folder = catalog?.folders.find(row => row.folder_id === selectedFolder);
  const selected = manifest?.items.find(item => item.artifact_id === selectedArtifact);
  const currentAssignment = catalog?.folders.find(folder => folder.items.some(
    item => item.artifact_id === selectedArtifact,
  ));
  const assignmentCount = catalog?.folders.reduce((count,folder) => count + folder.items.length,0) ?? 0;
  return <Card title="Signed Flow resource folders — persisted VIRTUAL metadata only">
    <div className="space-y-3 text-xs" aria-label="Signed Flow virtual resource folder management">
      <p>Organize immutable artifacts by PostgreSQL folder LABELS and SHA-bound associations, not host paths.
        This never moves bytes, creates host files, synchronizes container resources, enables agent instructions or executes a tool.
        Assignments require an independently approved senior Flow artifact review on the server.</p>
      <p>Flow <code>{flowId}</code> · revision {revision} · operator {actor?.role ?? 'unverified'}.</p>
      <button type="button" disabled={!permitted || busy} onClick={() => void refresh()}>
        READ CURRENT SIGNED FOLDER CATALOG (GET)
      </button>
      {message && <p role="alert">{message}</p>}
      {catalog && scope && manifest && <div className="space-y-2">
        <p role="status">Catalog CAS revision <strong>{catalog.catalog_revision}</strong>;
          {catalog.folders.length} virtual folders, {assignmentCount} metadata assignments.</p>
        <p className="break-all">Current source manifest SHA-256: <code>{scope.manifestSha256}</code>.</p>
        <p>Host files created: NO · container sync: NO · execution: NO · artifact bytes remain untrusted.</p>
        <ul className="space-y-1">{catalog.folders.map(entry => <li key={entry.folder_id} className="border p-2">
          <strong>{entry.name}</strong> — <code>{entry.folder_id}</code> — {entry.items.length} associations
        </li>)}</ul>
        <label className="block">Virtual folder name (lowercase, digits, hyphen or underscore only; begins with a letter)
          <input className="w-full border p-2" maxLength={48} value={name}
            onChange={event => {setName(event.target.value);setConfirmed(false);}}
            placeholder="team_notes" />
        </label>
        <label className="block">Existing virtual folder
          <select className="block border p-2 w-full" value={selectedFolder}
            onChange={event => {setSelectedFolder(event.target.value);setConfirmed(false);}}>
            <option value="">Choose a folder</option>
            {catalog.folders.map(entry => <option key={entry.folder_id} value={entry.folder_id}>
              {entry.name} ({entry.folder_id})
            </option>)}
          </select>
        </label>
        <label className="block">Immutable manifest artifact (metadata only)
          <select className="block border p-2 w-full" value={selectedArtifact}
            onChange={event => {setSelectedArtifact(event.target.value);setConfirmed(false);}}>
            <option value="">Choose an artifact</option>
            {manifest.items.map(item => <option key={item.artifact_id} value={item.artifact_id}>
              {item.name} — {item.sha256.slice(0,12)}…
            </option>)}
          </select>
        </label>
        {selected && <p className="break-all">Selected artifact SHA-256: {selected.sha256}.
          Current assignment: {currentAssignment?.folder_id ?? 'unassigned'}.</p>}
        <label className="flex items-start gap-2"><input type="checkbox" checked={confirmed}
          disabled={busy} onChange={event => setConfirmed(event.target.checked)} />
          I explicitly confirm a VIRTUAL metadata change only. Lost POST responses remain UNKNOWN;
          I will inspect the signed GET catalog instead of replaying.
        </label>
        <div className="flex flex-wrap gap-2">
          <button type="button" disabled={!confirmed || busy || !permitted || !name}
            onClick={() => void perform({operation:'create',name})}>CREATE VIRTUAL FOLDER</button>
          <button type="button" disabled={!confirmed || busy || !permitted || !folder || !name}
            onClick={() => folder && void perform({operation:'rename',folder_id:folder.folder_id,name})}>
            RENAME VIRTUAL FOLDER</button>
          <button type="button" disabled={!confirmed || busy || !permitted || !folder}
            onClick={() => folder && void perform({operation:'delete',folder_id:folder.folder_id})}>
            DELETE EMPTY VIRTUAL FOLDER</button>
          <button type="button" disabled={!confirmed || busy || !permitted || !folder || !selected || !!currentAssignment}
            onClick={() => folder && selected && void perform({
              operation:'assign',folder_id:folder.folder_id,
              artifact_id:selected.artifact_id,artifact_sha256:selected.sha256,
            })}>ASSIGN ARTIFACT (SENIOR REVIEW REQUIRED)</button>
          <button type="button" disabled={!confirmed || busy || !permitted || !folder || !selected
            || currentAssignment?.folder_id !== folder.folder_id}
            onClick={() => folder && selected && void perform({
              operation:'unassign',
              artifact_id:selected.artifact_id,artifact_sha256:selected.sha256,
            })}>UNASSIGN ARTIFACT</button>
        </div>
      </div>}
    </div>
  </Card>;
}
