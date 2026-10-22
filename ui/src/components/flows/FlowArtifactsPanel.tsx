import { useCallback, useEffect, useRef, useState } from 'react';

import { Card } from '../shared/Card';
import { currentOperator, subscribeOperator } from '../../services/api';
import { flowArtifactsApi, type FlowArtifact, type FlowResourceManifest } from '../../services/flowArtifacts';
import { supervisionApi } from '../../services/supervision';

interface Props {
  flowId: string;
  engagementId: string;
  revision: number;
}

/** Operator-visible vault; never interprets uploaded bytes or executes a file. */
export function FlowArtifactsPanel({ flowId, engagementId, revision }: Props) {
  const [version, setVersion] = useState<number | null>(null);
  const [files, setFiles] = useState<FlowArtifact[]>([]);
  const [resourceManifest, setResourceManifest] = useState<FlowResourceManifest | null>(null);
  const [resourceReviewed, setResourceReviewed] = useState(false);
  const [confirmedManifestSha, setConfirmedManifestSha] = useState('');
  const [candidate, setCandidate] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const fileInput = useRef<HTMLInputElement | null>(null);
  const generation = useRef(0);
  const resourceInFlight = useRef(false);

  const clearResourceReview = () => {
    setResourceManifest(null);
    setResourceReviewed(false);
    setConfirmedManifestSha('');
  };

  // Signed identity changes invalidate all previously reviewed bytes/snapshots.
  // A new operator must explicitly refresh inventory and verify a new manifest.
  useEffect(() => subscribeOperator(() => {
    ++generation.current;
    setVersion(null);
    setFiles([]);
    clearResourceReview();
    setNotice('');
    setError('Operator identity changed. Refresh signed Flow before resource review.');
  }), []);

  function expectedOperator(): string {
    const identity = currentOperator();
    if (!identity?.sub || !['operator', 'senior_operator'].includes(identity.role)) {
      throw new Error('Verified owner/operator identity is required for this Flow.');
    }
    return identity.sub;
  }

  function checkOperator(sub: string): void {
    if (currentOperator()?.sub !== sub || !['operator', 'senior_operator'].includes(currentOperator()?.role ?? '')) {
      throw new Error('Operator identity changed while verifying resources.');
    }
  }

  async function checkSnapshot(versionNumber: number, reviewer: string): Promise<void> {
    checkOperator(reviewer);
    const policy = await supervisionApi.authorizationStatus(engagementId);
    if (policy.status !== 'active' || policy.version !== versionNumber) {
      throw new Error('Signed authorization version changed; resource snapshot is stale.');
    }
    await flowArtifactsApi.currentResourceFlow(flowId, engagementId, revision);
    checkOperator(reviewer);
  }

  const reload = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true);
    setError('');
    setVersion(null);
    setFiles([]);
    clearResourceReview();
    try {
      const reviewer = expectedOperator();
      const policy = await supervisionApi.authorizationStatus(engagementId);
      if (policy.status !== 'active' || !Number.isSafeInteger(policy.version) || !policy.version) {
        throw new Error('This Flow has no currently active signed authorization.');
      }
      await flowArtifactsApi.currentResourceFlow(flowId, engagementId, revision);
      const inventory = await flowArtifactsApi.list(flowId, revision, policy.version);
      await flowArtifactsApi.currentResourceFlow(flowId, engagementId, revision);
      checkOperator(reviewer);
      if (generation.current !== current) return;
      setVersion(policy.version);
      setFiles(inventory);
    } catch (cause) {
      if (generation.current === current) {
        setError(cause instanceof Error ? cause.message : 'Could not verify Flow artifact inventory.');
      }
    } finally {
      if (generation.current === current) setLoading(false);
    }
  }, [flowId, engagementId, revision]);

  useEffect(() => {
    void reload();
    return () => { ++generation.current; };
  }, [reload]);

  async function upload() {
    if (!candidate || !version || working || !currentOperator()) return;
    setWorking(true);
    setError('');
    setNotice('');
    try {
      const policy = await supervisionApi.authorizationStatus(engagementId);
      if (policy.status !== 'active' || policy.version !== version) {
        throw new Error('Signed authorization changed. Refresh before uploading.');
      }
      const artifact = await flowArtifactsApi.upload(flowId, revision, version, candidate);
      setNotice('Stored immutable artifact ' + artifact.name + ' with SHA-256 receipt.');
      setCandidate(null);
      if (fileInput.current) fileInput.current.value = '';
      await reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Artifact upload was not confirmed.');
    } finally {
      setWorking(false);
    }
  }

  async function download(artifact: FlowArtifact) {
    if (!version || working) return;
    setWorking(true);
    setError('');
    try {
      const policy = await supervisionApi.authorizationStatus(engagementId);
      if (policy.status !== 'active' || policy.version !== version) {
        throw new Error('Signed authorization changed. Refresh before downloading.');
      }
      const bytes = await flowArtifactsApi.download(flowId, revision, version, artifact);
      const url = URL.createObjectURL(bytes);
      try {
        const link = document.createElement('a');
        link.href = url;
        link.download = artifact.name;
        link.rel = 'noopener noreferrer';
        link.click();
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Artifact download was not confirmed.');
    } finally {
      setWorking(false);
    }
  }

  async function inspectResources() {
    if (!version || working || loading || resourceInFlight.current || !currentOperator()) return;
    const current = generation.current;
    const reviewer = expectedOperator();
    resourceInFlight.current = true;
    setWorking(true);
    setError('');
    setNotice('');
    clearResourceReview();
    try {
      await checkSnapshot(version, reviewer);
      const verified = await flowArtifactsApi.resourceManifest(flowId, revision, version);
      await checkSnapshot(version, reviewer);
      if (generation.current !== current) return;
      setResourceManifest(verified);
      setNotice('Immutable manifest SHA-256 verified and independently read back under current Flow/ROE. Review exact file paths, sizes and digests before export.');
    } catch {
      if (generation.current === current) {
        clearResourceReview();
        setError('Signed Flow manifest verification UNKNOWN or stale. Review again; no resource bytes were exported.');
      }
    } finally {
      resourceInFlight.current = false;
      if (generation.current === current) setWorking(false);
    }
  }

  async function downloadResourceBundle() {
    if (!version || !resourceManifest || !resourceReviewed
      || confirmedManifestSha !== resourceManifest.manifest_sha256
      || working || loading || resourceInFlight.current || !currentOperator()) return;
    if (!window.confirm('Export this exact SHA-256-verified inert Flow resource snapshot as a ZIP?\n'
      + 'Manifest SHA-256: ' + resourceManifest.manifest_sha256 + '\n'
      + 'Files: ' + resourceManifest.count + ', bytes: ' + resourceManifest.total_size_bytes + '\n'
      + 'This is an UNTRUSTED DATA DOWNLOAD, never execution or synchronization to a container.')) return;
    const current = generation.current;
    const reviewer = expectedOperator();
    resourceInFlight.current = true;
    setWorking(true);
    setError('');
    setNotice('');
    try {
      await checkSnapshot(version, reviewer);
      // Re-read server authority; a cached manifest is never export authorization.
      const verified = await flowArtifactsApi.resourceManifest(flowId, revision, version);
      if (verified.manifest_sha256 !== resourceManifest.manifest_sha256
        || verified.count !== resourceManifest.count
        || verified.total_size_bytes !== resourceManifest.total_size_bytes) {
        throw new Error('Resource manifest changed. Inspect the new snapshot before exporting.');
      }
      const exportResult = await flowArtifactsApi.verifiedResourceBundle(flowId, revision, version, verified);
      if (exportResult.manifest_sha256 !== resourceManifest.manifest_sha256
        || exportResult.flow_revision !== revision
        || exportResult.authorization_version !== version
        || exportResult.resource_count !== resourceManifest.count) {
        throw new Error('ZIP receipt does not match original human-reviewed Flow snapshot.');
      }
      await checkSnapshot(version, reviewer);
      if (generation.current !== current) return;
      const url = URL.createObjectURL(exportResult.blob);
      try {
        const link = document.createElement('a');
        link.href = url;
        link.download = 'flow-resources-' + flowId + '-r' + revision + '.zip';
        link.rel = 'noopener noreferrer';
        link.click();
        setNotice('Downloaded independently SHA-256-verified inert ZIP: ' + exportResult.archive_sha256
          + '. Local operator download ONLY; no worker/container sync or file execution occurred.');
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      setResourceReviewed(false);
      setConfirmedManifestSha('');
    } catch {
      if (generation.current === current) {
        clearResourceReview();
        setError('Resource ZIP outcome UNKNOWN or signed scope changed. Discarded bytes; re-inspect the manifest before another explicit download. No automatic retry.');
      }
    } finally {
      resourceInFlight.current = false;
      if (generation.current === current) setWorking(false);
    }
  }

  return (
    <Card title="Flow evidence artifacts — signed revision">
      <p className="text-on-surface-variant text-[11px] mb-3">
        Owner-scoped inert bytes, never verified vulnerabilities, execution approval or
        container inputs. The backend checks signed authorization and Flow revision.
      </p>
      <p className="text-on-surface-variant text-[11px] mb-3">
        Flow revision {revision} · Authorization {version ?? 'unverified'} · Maximum upload 2 MiB
      </p>
      {error && <p role="alert" className="text-error text-[11px] mb-3">{error}</p>}
      {notice && <p role="status" className="text-secondary text-[11px] mb-3">{notice}</p>}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <button type="button" className="border border-outline px-3 py-2 text-[11px]"
          disabled={loading || working} onClick={() => void reload()}>
          {loading ? 'VERIFYING...' : 'REFRESH INVENTORY'}
        </button>
        <input ref={fileInput} aria-label="Flow artifact file" type="file"
          disabled={!version || loading || working} className="text-[11px] min-w-0"
          onChange={(event) => setCandidate(event.target.files?.[0] ?? null)} />
        <button type="button" className="border border-outline px-3 py-2 text-[11px]"
          disabled={!candidate || !version || loading || working}
          onClick={() => void upload()}>
          {working ? 'PROCESSING...' : 'UPLOAD ARTIFACT'}
        </button>
      </div>
      {files.length === 0 && (
        <p className="text-on-surface-variant text-[11px]">
          {loading ? 'Reading authorized inventory...' : 'No verified artifacts to display.'}
        </p>
      )}
      <div className="space-y-2">
        {files.map((artifact) => (
          <div className="border border-outline-variant p-2 flex flex-wrap items-center justify-between gap-2"
            key={artifact.id}>
            <div className="min-w-0 text-[11px]">
              <p className="text-on-surface break-words">{artifact.name}</p>
              <p className="text-on-surface-variant">
                {artifact.size_bytes} bytes · SHA-256 {artifact.sha256.slice(0, 16)}…
              </p>
            </div>
            <button type="button" className="border border-outline px-3 py-2 text-[11px]"
              disabled={!version || loading || working}
              onClick={() => void download(artifact)}>VERIFY &amp; DOWNLOAD</button>
          </div>
        ))}
      </div>
      <div className="mt-4 border-t border-outline-variant pt-3 space-y-2">
        <p className="text-on-surface text-[11px]">Read-only resource export (no container execution)</p>
        <p className="text-on-surface-variant text-[11px]">
          Only bounded UTF-8 source/text artifacts. Manifest and ZIP member digests must verify;
          no archive is unpacked, interpreted or synchronized to the execution sandbox.
        </p>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="border border-outline px-3 py-2 text-[11px]"
            disabled={!version || loading || working} onClick={() => void inspectResources()}>
            VERIFY RESOURCE MANIFEST
          </button>
          <button type="button" className="border border-outline px-3 py-2 text-[11px]"
            disabled={!version || !resourceManifest || !resourceReviewed
              || confirmedManifestSha !== resourceManifest.manifest_sha256 || loading || working}
            onClick={() => void downloadResourceBundle()}>
            VERIFY &amp; EXPORT INERT ZIP
          </button>
        </div>
        {resourceManifest && <div className="space-y-3 text-[11px]" role="status">
          <p>{resourceManifest.count} inert files · {resourceManifest.total_size_bytes} bytes ·
            signed Flow revision {resourceManifest.flow_revision} · signed ROE version {resourceManifest.authorization_version}.
          </p>
          <p className="font-mono break-all">Verified full manifest SHA-256: {resourceManifest.manifest_sha256}</p>
          {resourceManifest.count === 0 ? <p>Empty manifest (no resource files). Export is still inert metadata only.</p> :
            <ul className="space-y-2">
              {resourceManifest.items.map(item => <li key={item.artifact_id}
                className="border border-outline-variant p-2 font-mono break-all">
                <p>Exact inert path: {item.resource_path}</p>
                <p>Artifact: {item.artifact_id} · {item.size_bytes} bytes · {item.classification}</p>
                <p>Member SHA-256: {item.sha256}</p>
              </li>)}
            </ul>}
          <label className="flex gap-2 items-start">
            <input type="checkbox" checked={resourceReviewed} disabled={loading || working}
              onChange={event => setResourceReviewed(event.target.checked)} />
            I inspected each exact inert manifest path, size and digest. Archive is untrusted data;
            this does NOT authorize execution, workspace file synchronization, or signed report release.
          </label>
          <label className="block text-on-surface-variant">ENTER FULL VERIFIED MANIFEST SHA-256 TO CONFIRM EXACT SNAPSHOT
            <input className="w-full border border-outline bg-background p-2 font-mono"
              aria-label="Confirm verified manifest SHA-256" autoComplete="off" maxLength={64}
              disabled={loading || working} value={confirmedManifestSha}
              onChange={event => setConfirmedManifestSha(event.target.value)} />
          </label>
        </div>}
      </div>
    </Card>
  );
}
