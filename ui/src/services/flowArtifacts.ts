/** Revision-fenced Flow artifacts. Bytes never pass through browser storage. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

export interface FlowArtifact {
  id: string;
  flow_id: string;
  name: string;
  size_bytes: number;
  sha256: string;
  flow_revision: number;
  authorization_version: number;
  created_at: string;
}

export interface FlowResourceManifest {
  format: 'ai-osop-inert-flow-resources-v1';
  flow_id: string;
  flow_revision: number;
  authorization_version: number;
  count: number;
  total_size_bytes: number;
  items: Array<{
    artifact_id: string; name: string; resource_path: string;
    size_bytes: number; sha256: string; classification: string;
  }>;
  manifest_sha256: string;
  read_only: true;
  content_executed: false;
  host_files_created: false;
  archive_compression: 'stored';
  artifact_bytes_untrusted: true;
}

/** Only after ZIP SHA, all local/central members, CRC and manifest are checked. */
export interface VerifiedFlowResourceBundle {
  blob: Blob;
  archive_sha256: string;
  manifest_sha256: string;
  flow_revision: number;
  authorization_version: number;
  resource_count: number;
  total_resource_bytes: number;
}

const maxBytes = 2 * 1024 * 1024;
const maxArchiveBytes = 4 * 1024 * 1024 + 64 * 1024;
const hashPattern = /^[a-f0-9]{64}$/;
const sourceExtensions = new Set(['py', 'go', 'rs', 'java', 'c', 'h', 'cpp', 'hpp', 'ts', 'tsx', 'js', 'jsx', 'sql', 'css']);
const inertExtensions = new Set([...sourceExtensions, 'txt', 'md', 'csv', 'tsv', 'json', 'jsonl', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'log', 'diff', 'patch']);

function currentArtifactIdentity(): { sub: string; bearer: string; exp: number | null } {
  const identity = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!identity?.sub || !['operator', 'senior_operator'].includes(identity.role)
    || typeof bearer !== 'string' || !/^Bearer \S+$/.test(bearer)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Verified current signed operator and secure Flow artifact API required.');
  }
  return { sub: identity.sub, bearer, exp: identity.exp };
}

function assertSameArtifactIdentity(prior: { sub: string; bearer: string; exp: number | null }): void {
  const current = currentArtifactIdentity();
  if (current.sub !== prior.sub || current.bearer !== prior.bearer || current.exp !== prior.exp) {
    throw new Error('Operator identity or bearer changed during signed Flow resource verification.');
  }
}

function digestHex(bytes: ArrayBuffer): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Secure browser digest verification is required.');
  }
  return crypto.subtle.digest('SHA-256', bytes).then((value) =>
    Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, '0')).join(''));
}

// Match Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True)
// on the constrained, ASCII-only server manifest schema.
function canonical(value: unknown): string {
  if (typeof value === 'string' && /[^\x00-\x7f]/.test(value)) {
    throw new Error('Non-ASCII Flow resource metadata is not trusted.');
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (Object.keys(value).some((key) => /[^\x00-\x7f]/.test(key))) {
    throw new Error('Non-ASCII Flow resource metadata keys are not trusted.');
  }
  return '{' + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ':' + canonical((value as Record<string, unknown>)[key])
  ).join(',') + '}';
}

function exactKeys(value: object, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  const allowed = [...expected].sort();
  return keys.length === allowed.length && keys.every((key, i) => key === allowed[i]);
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const manifestKeys = ['format', 'flow_id', 'flow_revision', 'authorization_version',
  'count', 'total_size_bytes', 'items', 'manifest_sha256', 'read_only',
  'content_executed', 'host_files_created', 'archive_compression', 'artifact_bytes_untrusted'];
const itemKeys = ['artifact_id', 'name', 'resource_path', 'size_bytes', 'sha256', 'classification'];

async function boundedResponseBytes(response: Response, bound: number): Promise<ArrayBuffer> {
  const advertised = response.headers.get('Content-Length');
  if (advertised != null && (!/^\d+$/.test(advertised) || Number(advertised) > bound)) {
    throw new Error('Resource bundle exceeds the safe transfer size.');
  }
  // Never call Response.arrayBuffer() on an unbounded untrusted response.
  if (!response.body) throw new Error('Bounded resource stream is unavailable.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > bound) throw new Error('Resource bundle exceeds the safe transfer size.');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes.buffer;
}

/** ZIP_STORED local and central entries must independently bind every byte to the manifest. */
async function verifyInertZip(buffer: ArrayBuffer, manifest: FlowResourceManifest): Promise<void> {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const length = bytes.length;
  const end = length - 22;
  const u16 = (offset: number) => view.getUint16(offset, true);
  const u32 = (offset: number) => view.getUint32(offset, true);
  const deny = () => { throw new Error('Resource archive member integrity is invalid.'); };
  if (end < 0 || u32(end) !== 0x06054b50 || u16(end + 4) !== 0 || u16(end + 6) !== 0
    || u16(end + 8) !== manifest.count + 1 || u16(end + 10) !== manifest.count + 1
    || u16(end + 20) !== 0) deny();
  const centralSize = u32(end + 12);
  const centralOffset = u32(end + 16);
  if (centralOffset > end || centralSize > end - centralOffset
    || centralOffset + centralSize !== end) deny();
  const expected = new Map(manifest.items.map((entry) => [entry.resource_path, entry]));
  const seen = new Map<string, { offset: number; size: number; crc: number }>();
  const decode = (start: number, size: number) => {
    const raw = bytes.subarray(start, start + size);
    if (raw.some((byte) => byte < 32 || byte > 126)) deny();
    return String.fromCharCode(...raw);
  };
  let p = 0;
  while (p < centralOffset) {
    if (centralOffset - p < 30 || u32(p) !== 0x04034b50) deny();
    const flags = u16(p + 6);
    const method = u16(p + 8);
    const stored = u32(p + 18);
    const rawSize = u32(p + 22);
    const localCRC = u32(p + 14);
    const nameLen = u16(p + 26);
    const extraLen = u16(p + 28);
    if (flags !== 0 || method !== 0 || stored !== rawSize || extraLen !== 0
      || nameLen < 1 || nameLen > 145 || nameLen + 30 > centralOffset - p) deny();
    const name = decode(p + 30, nameLen);
    const start = p + 30 + nameLen;
    if (stored > centralOffset - start || seen.has(name)) deny();
    const actualCRC = crc32(bytes.subarray(start, start + stored));
    if (actualCRC !== localCRC) deny();
    const item = expected.get(name);
    if (name === 'resource-manifest.json') {
      const canonicalBytes = new TextEncoder().encode(canonical(manifest));
      if (stored !== canonicalBytes.length || bytes.subarray(start, start + stored)
        .some((byte, i) => byte !== canonicalBytes[i])) deny();
    } else {
      if (!item || item.size_bytes !== stored
        || await digestHex(buffer.slice(start, start + stored)) !== item.sha256) deny();
    }
    seen.set(name, { offset: p, size: stored, crc: actualCRC });
    p = start + stored;
    if (seen.size > manifest.count + 1) deny();
  }
  if (p !== centralOffset || seen.size !== manifest.count + 1
    || !seen.has('resource-manifest.json')) deny();
  let central = centralOffset;
  const centralSeen = new Set<string>();
  for (let i = 0; i < seen.size; i++) {
    if (centralSize < central - centralOffset + 46 || u32(central) !== 0x02014b50) deny();
    const flags = u16(central + 8);
    const method = u16(central + 10);
    const stored = u32(central + 20);
    const rawSize = u32(central + 24);
    const centralCRC = u32(central + 16);
    const nameLen = u16(central + 28);
    const extraLen = u16(central + 30);
    const commentLen = u16(central + 32);
    const unixType = (u32(central + 38) >>> 16) & 0xf000;
    const localOffset = u32(central + 42);
    if (flags !== 0 || method !== 0 || stored !== rawSize || extraLen !== 0
      || commentLen !== 0 || nameLen < 1 || nameLen > 145
      // ZIP metadata can otherwise reinterpret a verified resource as a
      // symlink or special device during later manual extraction.
      || (unixType !== 0 && unixType !== 0x8000)
      || 46 + nameLen > centralOffset + centralSize - central) deny();
    const name = decode(central + 46, nameLen);
    const matching = seen.get(name);
    if (!matching || centralSeen.has(name) || matching.offset !== localOffset
      || matching.size !== stored || matching.crc !== centralCRC) deny();
    centralSeen.add(name);
    central += 46 + nameLen;
  }
  if (central !== end) deny();
}

function exportedResourceLocation(flowId: string, revision: number, version: number,
  kind: 'resource-manifest' | 'resource-bundle'): string {
  const validated = location(flowId, revision, version);
  const [pathname, query] = validated.split('?');
  return pathname + '/' + kind + '?' + query;
}

function verifiedResourceManifest(value: unknown, flowId: string, revision: number,
  version: number): FlowResourceManifest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid signed Flow resource manifest.');
  }
  const manifest = value as FlowResourceManifest;
  if (
    !exactKeys(manifest, manifestKeys)
    || manifest.format !== 'ai-osop-inert-flow-resources-v1'
    || manifest.flow_id !== flowId || manifest.flow_revision !== revision
    || manifest.authorization_version !== version || manifest.read_only !== true
    || manifest.content_executed !== false || manifest.host_files_created !== false
    || manifest.artifact_bytes_untrusted !== true
    || manifest.archive_compression !== 'stored'
    || !Number.isSafeInteger(manifest.count) || manifest.count < 0 || manifest.count > 16
    || !Number.isSafeInteger(manifest.total_size_bytes)
    || manifest.total_size_bytes < 0 || manifest.total_size_bytes > 4 * 1024 * 1024
    || !Array.isArray(manifest.items) || manifest.items.length !== manifest.count
    || !hashPattern.test(manifest.manifest_sha256)
    || !manifest.items.every((item) =>
      item && typeof item === 'object' && !Array.isArray(item) && exactKeys(item, itemKeys)
      && /^artifact-[a-f0-9]{32}$/.test(item.artifact_id)
      && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(item.name)
      && item.resource_path === 'resources/' + item.name
      && Number.isSafeInteger(item.size_bytes) && item.size_bytes > 0
      && item.size_bytes <= maxBytes && hashPattern.test(item.sha256)
      && inertExtensions.has(item.name.slice(item.name.lastIndexOf('.') + 1).toLowerCase())
      && item.classification === (sourceExtensions.has(item.name.slice(item.name.lastIndexOf('.') + 1).toLowerCase())
        ? 'utf8_inert_source' : 'utf8_inert_text')
    )
    || manifest.items.reduce((sum, item) => sum + item.size_bytes, 0) !== manifest.total_size_bytes
    || new Set(manifest.items.map((item) => item.resource_path)).size !== manifest.items.length
    || manifest.items.some((item, index) =>
      index > 0 && manifest.items[index - 1].resource_path >= item.resource_path)
  ) {
    throw new Error('Signed Flow resource manifest integrity or scope is invalid.');
  }
  return manifest;
}

function authorization(): Record<string, string> {
  const headers = authHeaders();
  if (!currentOperator() || !headers.Authorization || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('A verified operator bearer over a secure API connection is required.');
  }
  return headers;
}

function location(flowId: string, revision: number, version: number, artifactId?: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(flowId)
    || (artifactId != null && !/^artifact-[a-f0-9]{32}$/.test(artifactId))
    || !Number.isSafeInteger(revision) || revision < 0
    || !Number.isSafeInteger(version) || version <= 0) {
    throw new Error('Current signed Flow identity, revision and authorization are required.');
  }
  const params = new URLSearchParams({
    expected_revision: String(revision),
    expected_authorization_version: String(version),
  });
  return API_BASE + '/flows/' + encodeURIComponent(flowId) + '/artifacts'
    + (artifactId ? '/' + encodeURIComponent(artifactId) : '') + '?' + params;
}

async function responseError(response: Response): Promise<never> {
  const safe: Record<number, string> = {
    401: 'Operator token expired or invalid.',
    403: 'Artifact access was denied by signed authorization or tenant ownership.',
    404: 'Flow artifact is not present.',
    409: 'Flow revision changed. Refresh and review the current Flow.',
    413: 'Artifact exceeds the server size limit.',
    422: 'Artifact name or request is invalid.',
    503: 'Authoritative artifact storage is unavailable.',
  };
  throw new Error(safe[response.status] ?? 'Artifact service returned HTTP ' + response.status);
}

export function artifactName(name: string): string {
  const value = name.trim();
  if (!value || value.length > 120 || value === '.' || value === '..'
    || /[\\/<>:"|?*\u0000-\u001f\u007f]/.test(value)
    || value.startsWith('.upload-')) {
    throw new Error('Use a simple filename without directories or special characters.');
  }
  return value;
}

function options(method: string, additionalHeaders: Record<string, string> = {}): RequestInit {
  return {
    method,
    headers: authHeaders({ ...authorization(), ...additionalHeaders }),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  };
}

export const flowArtifactsApi = {
  async currentResourceFlow(flowId: string, engagementId: string, revision: number): Promise<void> {
    const identity = currentArtifactIdentity();
    if (!/^flow-[A-Za-z0-9._-]{1,90}$/.test(flowId)
      || !/^eng-[A-Za-z0-9._-]{1,60}$/.test(engagementId)
      || !Number.isSafeInteger(revision) || revision < 0) {
      throw new Error('Exact current signed Flow identity and revision required.');
    }
    const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}`, {
      method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    if (!response.ok) throw new Error('Current owner-scoped Flow is unavailable.');
    const data: unknown = await response.json();
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Current owner-scoped Flow is malformed.');
    }
    const record = (data as Record<string, unknown>).flow;
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('Current owner-scoped Flow is malformed.');
    }
    const actual = record as Record<string, unknown>;
    // Immutable export is a READ and may inspect a completed Flow, unlike an
    // upload/execution admission. Signed authority and revision still required.
    if (actual.id !== flowId || actual.engagement_id !== engagementId
      || actual.revision !== revision || !['pending', 'running', 'paused', 'completed',
        'halted', 'cancelled', 'failed'].includes(String(actual.status))) {
      throw new Error('Flow revision or status changed; resource review is stale.');
    }
    assertSameArtifactIdentity(identity);
  },
  async resourceManifest(flowId: string, revision: number, version: number): Promise<FlowResourceManifest> {
    const identity = currentArtifactIdentity();
    const response = await fetch(
      exportedResourceLocation(flowId, revision, version, 'resource-manifest'),
      options('GET'),
    );
    if (!response.ok) return responseError(response);
    const data = verifiedResourceManifest(await response.json(), flowId, revision, version);
    const header = response.headers.get('X-Resource-Manifest-SHA256');
    if (header !== data.manifest_sha256) {
      throw new Error('Resource manifest digest header mismatch.');
    }
    const { manifest_sha256: omitted, ...fields } = data;
    void omitted;
    const payload = new TextEncoder().encode(canonical(fields));
    if (await digestHex(Uint8Array.from(payload).buffer) !== data.manifest_sha256) {
      throw new Error('Resource manifest SHA-256 verification failed.');
    }
    assertSameArtifactIdentity(identity);
    // Never hand out the untrusted server object; it may have mutable hidden
    // fields, and an old object must not become an approval for later export.
    return {
      ...fields, items: data.items.map(item => ({ ...item })),
      manifest_sha256: data.manifest_sha256,
    };
  },
  async verifiedResourceBundle(flowId: string, revision: number, version: number,
    manifest: FlowResourceManifest): Promise<VerifiedFlowResourceBundle> {
    const identity = currentArtifactIdentity();
    verifiedResourceManifest(manifest, flowId, revision, version);
    const { manifest_sha256: excluded, ...signedFields } = manifest;
    void excluded;
    const canonicalBytes = new TextEncoder().encode(canonical(signedFields));
    if (await digestHex(Uint8Array.from(canonicalBytes).buffer) !== manifest.manifest_sha256) {
      throw new Error('Resource manifest changed after browser verification.');
    }
    const response = await fetch(
      exportedResourceLocation(flowId, revision, version, 'resource-bundle'),
      options('GET'),
    );
    if (!response.ok) return responseError(response);
    if (response.headers.get('X-Resource-Manifest-SHA256') !== manifest.manifest_sha256) {
      throw new Error('Resource bundle refers to a changed signed Flow snapshot.');
    }
    const expected = response.headers.get('X-Resource-Archive-SHA256');
    if (!expected || !hashPattern.test(expected)) {
      throw new Error('Resource bundle SHA-256 receipt missing.');
    }
    const bytes = await boundedResponseBytes(response, maxArchiveBytes);
    if (bytes.byteLength > maxArchiveBytes || bytes.byteLength < 22) {
      throw new Error('Resource bundle size exceeds the safe limit.');
    }
    const actualSha = await digestHex(bytes);
    if (actualSha !== expected) {
      throw new Error('Resource bundle SHA-256 verification failed.');
    }
    await verifyInertZip(bytes, manifest);
    assertSameArtifactIdentity(identity);
    return {
      blob: new Blob([bytes], { type: 'application/zip' }),
      archive_sha256: actualSha,
      manifest_sha256: manifest.manifest_sha256,
      flow_revision: revision,
      authorization_version: version,
      resource_count: manifest.count,
      total_resource_bytes: manifest.total_size_bytes,
    };
  },
  async resourceBundle(flowId: string, revision: number, version: number,
    manifest: FlowResourceManifest): Promise<Blob> {
    return (await this.verifiedResourceBundle(flowId, revision, version, manifest)).blob;
  },
  async list(flowId: string, revision: number, version: number): Promise<FlowArtifact[]> {
    const response = await fetch(location(flowId, revision, version), options('GET'));
    if (!response.ok) return responseError(response);
    const data: unknown = await response.json();
    if (!data || typeof data !== 'object' || !Array.isArray((data as { items?: unknown }).items)) {
      throw new Error('Artifact inventory response is invalid.');
    }
    return (data as { items: FlowArtifact[] }).items;
  },
  async upload(
    flowId: string, revision: number, version: number, file: File,
  ): Promise<FlowArtifact> {
    if (file.size < 1 || file.size > maxBytes) {
      throw new Error('Artifact must contain 1 byte to 2 MiB.');
    }
    const params = new URLSearchParams({
      name: artifactName(file.name),
      expected_revision: String(revision),
      expected_authorization_version: String(version),
    });
    const base = location(flowId, revision, version).split('?')[0];
    const response = await fetch(base + '?' + params, {
      ...options('POST', { 'Content-Type': 'application/octet-stream' }),
      body: file,
    });
    if (!response.ok) return responseError(response);
    return (await response.json()) as FlowArtifact;
  },
  async download(
    flowId: string, revision: number, version: number, artifact: FlowArtifact,
  ): Promise<Blob> {
    const response = await fetch(location(flowId, revision, version, artifact.id), options('GET'));
    if (!response.ok) return responseError(response);
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength !== artifact.size_bytes || bytes.byteLength > maxBytes) {
      throw new Error('Artifact size no longer matches its signed Flow inventory.');
    }
    if (!globalThis.crypto?.subtle) {
      throw new Error('Browser digest verification requires a secure context.');
    }
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const actual = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
    if (actual !== artifact.sha256 || response.headers.get('X-Artifact-SHA256') !== artifact.sha256) {
      throw new Error('Artifact digest mismatch. The download was rejected.');
    }
    return new Blob([bytes], { type: 'application/octet-stream' });
  },
};
