/** Signed Flow, PostgreSQL-backed VIRTUAL folder metadata ONLY.
 * Never moves/downloads/executes any artifact; POST effects require signed GET
 * readback, and an uncertain POST is NEVER retried automatically.
 */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const FLOW = /^flow-[A-Za-z0-9._:-]{1,59}$/;
const ENG = /^eng-[A-Za-z0-9._:-]{1,60}$/;
const AUTH = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SHA = /^[0-9a-f]{64}$/;
const FOLDER = /^folder-[0-9a-f]{32}$/;
const ARTIFACT = /^artifact-[0-9a-f]{32}$/;
const NAME = /^[a-z][a-z0-9_-]{0,47}$/;
const MAX_FOLDERS = 32;
const MAX_ASSIGNMENTS = 128;
const MAX_RESPONSE_BYTES = 32768;
const attemptedWrites = new Set<string>();

export interface ResourceFolderScope {
  flowId: string;
  engagementId: string;
  flowRevision: number;
  authorizationVersion: number;
  authorizationId: string;
  authorizationSha256: string;
  manifestSha256: string;
}
export interface VirtualResourceFolder {
  folder_id: string;
  name: string;
  items: VirtualResourceItem[];
}
export interface VirtualResourceItem {
  artifact_id: string;
  artifact_sha256: string;
  original_name: string;
  classification: string;
  size_bytes: number;
}
export interface FlowResourceFolderCatalog {
  format: 'ai-osop-flow-resource-folders-v1';
  flow_id: string;
  engagement_id: string;
  flow_revision: number;
  authorization_version: number;
  authorization_id: string;
  authorization_sha256: string;
  source_manifest_sha256: string;
  catalog_revision: number;
  folders: VirtualResourceFolder[];
  unassigned: VirtualResourceItem[];
  metadata_only: true;
  host_files_created: false;
  worker_sync_performed: false;
}
export type FolderMutation =
  | {operation:'create'; name:string}
  | {operation:'rename'; folder_id:string; name:string}
  | {operation:'delete'; folder_id:string}
  | {operation:'assign'; folder_id:string; artifact_id:string; artifact_sha256:string}
  | {operation:'unassign'; artifact_id:string; artifact_sha256:string};

type Actor = { sub:string; role:string; exp:number|null; bearer:string };

function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid signed virtual folder metadata.');
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== fields.length
    || fields.some(field => !Object.prototype.hasOwnProperty.call(record, field)))
    throw new Error('Unexpected private, executable or unsupported folder metadata.');
  return record;
}
function rejectDuplicateJsonKeys(raw: string): void {
  // JSON.parse silently takes the last duplicate field. Reject contradictory
  // security flags/identity even when both values parse as otherwise valid.
  // JSON.parse is the syntax validator; this scan identifies string keys only.
  const objects: Array<Set<string>> = [];
  for (let i = 0; i < raw.length;) {
    const char = raw[i];
    if (char === '{') {objects.push(new Set()); i++; continue;}
    if (char === '}') {objects.pop(); i++; continue;}
    if (char !== '"') {i++; continue;}
    const start = i++;
    while (i < raw.length) {
      if (raw[i] === '\\') {i += 2; continue;}
      if (raw[i++] === '"') break;
    }
    let next = i;
    while (next < raw.length && /\s/.test(raw[next])) next++;
    if (raw[next] === ':' && objects.length) {
      const key = JSON.parse(raw.slice(start,i)) as string;
      const keys = objects[objects.length - 1];
      if (keys.has(key)) throw new Error('Duplicate signed Flow folder JSON field.');
      keys.add(key);
    }
  }
}
function integer(value: unknown, min: number, max = 2147483647): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}
function validateScope(scope: ResourceFolderScope): Actor {
  const actor = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!actor || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(actor.sub)
    || !['operator','senior_operator'].includes(actor.role)
    || !integer(actor.exp, 1) || actor.exp * 1000 <= Date.now()
    || typeof bearer !== 'string' || !/^Bearer [^\s]{1,4096}$/.test(bearer)
    || !FLOW.test(scope.flowId) || !ENG.test(scope.engagementId)
    || !integer(scope.flowRevision,0) || !integer(scope.authorizationVersion,1)
    || !AUTH.test(scope.authorizationId) || !SHA.test(scope.authorizationSha256)
    || !SHA.test(scope.manifestSha256)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin())
    throw new Error('Current signed operator/Flow/ROE/manifest identity is required.');
  return {sub:actor.sub,role:actor.role,exp:actor.exp,bearer};
}
function fresh(actor: Actor): void {
  const current = currentOperator();
  if (!current || current.sub !== actor.sub || current.role !== actor.role
    || current.exp !== actor.exp || authHeaders().Authorization !== actor.bearer)
    throw new Error('Operator or bearer changed; signed folder outcome UNKNOWN.');
}
function validateMutation(input: FolderMutation): FolderMutation {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid folder operation.');
  const keys = Object.keys(input).sort();
  const required: Record<string,string[]> = {
    create:['name','operation'], rename:['folder_id','name','operation'],
    delete:['folder_id','operation'],
    assign:['artifact_id','artifact_sha256','folder_id','operation'],
    unassign:['artifact_id','artifact_sha256','operation'],
  };
  const operation = input.operation;
  if (!Object.prototype.hasOwnProperty.call(required, operation)
    || keys.join('|') !== required[operation].sort().join('|'))
    throw new Error('Unsupported folder operation or forbidden metadata.');
  if ('name' in input && (typeof input.name !== 'string' || !NAME.test(input.name)
    || input.name === '.' || input.name === '..' || input.name.endsWith('.')))
    throw new Error('Unsafe virtual folder name or path.');
  if ('folder_id' in input && (typeof input.folder_id !== 'string' || !FOLDER.test(input.folder_id)))
    throw new Error('Invalid virtual folder identifier.');
  if ('artifact_id' in input && (typeof input.artifact_id !== 'string' || !ARTIFACT.test(input.artifact_id)
    || typeof input.artifact_sha256 !== 'string' || !SHA.test(input.artifact_sha256)))
    throw new Error('An exact inert artifact ID/SHA is required.');
  return input;
}
function folder(raw: unknown): VirtualResourceFolder {
  const value = exact(raw,['folder_id','name','items']);
  if (typeof value.folder_id !== 'string' || !FOLDER.test(value.folder_id)
    || typeof value.name !== 'string' || !NAME.test(value.name)
    || !Array.isArray(value.items) || value.items.length > MAX_ASSIGNMENTS)
    throw new Error('Unsafe persisted virtual folder.');
  return {folder_id:value.folder_id,name:value.name,items:value.items.map(resourceItem)};
}
function resourceItem(raw: unknown): VirtualResourceItem {
  const value = exact(raw,['artifact_id','artifact_sha256','original_name','classification','size_bytes']);
  if (typeof value.artifact_id !== 'string' || !ARTIFACT.test(value.artifact_id)
    || typeof value.artifact_sha256 !== 'string' || !SHA.test(value.artifact_sha256)
    || typeof value.original_name !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value.original_name)
    || !['utf8_inert_text','utf8_inert_source'].includes(String(value.classification))
    || !integer(value.size_bytes,1,2097152))
    throw new Error('Unsafe virtual artifact assignment.');
  return value as unknown as VirtualResourceItem;
}
function catalog(raw: unknown, scope: ResourceFolderScope): FlowResourceFolderCatalog {
  const value = exact(raw, [
    'format',
    'flow_id','engagement_id','flow_revision','authorization_version',
    'authorization_id','authorization_sha256','source_manifest_sha256',
    'catalog_revision','folders','unassigned','metadata_only','host_files_created',
    'worker_sync_performed',
  ]);
  if (value.format !== 'ai-osop-flow-resource-folders-v1'
    || value.flow_id !== scope.flowId || value.engagement_id !== scope.engagementId
    || value.flow_revision !== scope.flowRevision
    || value.authorization_version !== scope.authorizationVersion
    || value.authorization_id !== scope.authorizationId
    || value.authorization_sha256 !== scope.authorizationSha256
    || value.source_manifest_sha256 !== scope.manifestSha256
    || !integer(value.catalog_revision,0)
    || !Array.isArray(value.folders) || value.folders.length > MAX_FOLDERS
    || !Array.isArray(value.unassigned) || value.unassigned.length > MAX_ASSIGNMENTS
    || value.metadata_only !== true || value.host_files_created !== false
    || value.worker_sync_performed !== false)
    throw new Error('Signed virtual folders are stale, unbounded or falsely executable.');
  const folders = value.folders.map(folder);
  const unassigned = value.unassigned.map(resourceItem);
  const ids = new Set(folders.map(entry => entry.folder_id));
  const all = [...unassigned,...folders.flatMap(entry => entry.items)];
  if (ids.size !== folders.length || new Set(folders.map(entry => entry.name)).size !== folders.length
    || all.length > MAX_ASSIGNMENTS
    || new Set(all.map(entry => entry.artifact_id)).size !== all.length
    || all.some(entry => all.some(other => other !== entry
      && other.artifact_id === entry.artifact_id && other.artifact_sha256 !== entry.artifact_sha256)))
    throw new Error('Duplicate, dangling or conflicting signed virtual folder assignments.');
  return { ...value, folders, unassigned } as unknown as FlowResourceFolderCatalog;
}
function path(scope: ResourceFolderScope): string {
  return `${API_BASE}/flows/${encodeURIComponent(scope.flowId)}/resource-folders?${new URLSearchParams({
    expected_engagement_id:scope.engagementId,
    expected_revision:String(scope.flowRevision),
    expected_authorization_version:String(scope.authorizationVersion),
    expected_authorization_id:scope.authorizationId,
    expected_authorization_sha256:scope.authorizationSha256,
    expected_manifest_sha256:scope.manifestSha256,
  })}`;
}
async function jsonResponse(response: Response): Promise<unknown> {
  const size = response.headers?.get('content-length');
  if (size !== null && size !== undefined && (!/^\d+$/.test(size) || Number(size) > MAX_RESPONSE_BYTES))
    throw new Error('Unbounded virtual folder response rejected.');
  if (!response.body) throw new Error('Signed virtual folder metadata stream is missing.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) throw new Error('Virtual folder response exceeds limit.');
      chunks.push(part.value);
    }
  } catch (cause) {
    await reader.cancel().catch(() => undefined);
    throw cause;
  } finally {
    reader.releaseLock();
  }
  const buffer = new Uint8Array(bytes);
  let offset = 0;
  for (const part of chunks) {buffer.set(part,offset); offset += part.byteLength;}
  try {
    const decoded = new TextDecoder('utf-8',{fatal:true}).decode(buffer);
    const parsed: unknown = JSON.parse(decoded);
    rejectDuplicateJsonKeys(decoded);
    return parsed;
  }
  catch { throw new Error('Invalid signed folder JSON response.'); }
}
async function read(scope: ResourceFolderScope, who?: Actor): Promise<FlowResourceFolderCatalog> {
  const actor = who ?? validateScope(scope);
  const response = await fetch(path(scope),{
    method:'GET',headers:{Authorization:actor.bearer,Accept:'application/json'},
    credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
  });
  if (response.status !== 200) throw new Error('Current signed virtual folder GET unavailable.');
  const raw = await jsonResponse(response);
  fresh(actor);
  return catalog(raw,scope);
}
function mutationMatches(previous: FlowResourceFolderCatalog, next: FlowResourceFolderCatalog, input: FolderMutation): boolean {
  if (next.catalog_revision !== previous.catalog_revision + 1) return false;
  const prev = new Map(previous.folders.map(row => [row.folder_id,row]));
  const fresh = new Map(next.folders.map(row => [row.folder_id,row]));
  const preservedNames = [...prev].every(([id,existing]) => {
    if (input.operation === 'delete' && id === input.folder_id) return true;
    if (input.operation === 'rename' && id === input.folder_id) return true;
    return fresh.get(id)?.name === existing.name;
  });
  if (!preservedNames) return false;
  const links = (value: FlowResourceFolderCatalog) => new Map([
    ...value.unassigned.map(item => [item.artifact_id, `unassigned:${item.artifact_sha256}`] as const),
    ...value.folders.flatMap(entry => entry.items.map(item =>
      [item.artifact_id, `${entry.folder_id}:${item.artifact_sha256}`] as const)),
  ]);
  const prevLinks = links(previous);
  const newLinks = links(next);
  const same = [...prevLinks].every(([id,assignment]) => newLinks.get(id) === assignment)
    && prevLinks.size === newLinks.size;
  if (input.operation === 'create')
    return next.folders.length === previous.folders.length + 1
      && next.folders.filter(row => row.name === input.name && !prev.has(row.folder_id)
        && row.items.length === 0).length === 1
      && same;
  if (input.operation === 'rename')
    return prev.has(input.folder_id) && prev.get(input.folder_id)?.name !== input.name
      && fresh.get(input.folder_id)?.name === input.name
      && prev.size === fresh.size && same;
  if (input.operation === 'delete')
    return prev.has(input.folder_id) && !fresh.has(input.folder_id)
      && prev.get(input.folder_id)?.items.length === 0
      && prev.size === fresh.size + 1 && same;
  const before = prevLinks.get(input.artifact_id);
  const after = newLinks.get(input.artifact_id);
  const unchangedOther = [...prevLinks].every(([id,location]) => id === input.artifact_id
    || newLinks.get(id) === location);
  return input.operation === 'assign'
    ? fresh.has(input.folder_id)
      && before === `unassigned:${input.artifact_sha256}`
      && after === `${input.folder_id}:${input.artifact_sha256}`
      && unchangedOther && prevLinks.size === newLinks.size
    : before !== undefined && before !== `unassigned:${input.artifact_sha256}`
      && before.endsWith(`:${input.artifact_sha256}`)
      && after === `unassigned:${input.artifact_sha256}`
      && unchangedOther && prevLinks.size === newLinks.size;
}

export const flowResourceFoldersApi = {
  read: async (scope: ResourceFolderScope) => read(scope),
  /** Successful POST is never a remote write acknowledgment alone: recheck current signed GET.
   * A POST fault, lost ACK, changed operator, stale CAS or invalid readback remains UNKNOWN.
   */
  mutate: async (scope: ResourceFolderScope, previous: FlowResourceFolderCatalog,
    mutation: FolderMutation, explicitHumanConfirmation: boolean): Promise<FlowResourceFolderCatalog> => {
    const actor = validateScope(scope);
    const input = validateMutation(mutation);
    if (explicitHumanConfirmation !== true) throw new Error('Explicit operator confirmation is required.');
    // Re-validate the supplied catalog rather than trusting the component.
    if (catalog(previous,scope).catalog_revision !== previous.catalog_revision)
      throw new Error('Current signed folder catalog required.');
    if (!integer(previous.catalog_revision,0)) throw new Error('Invalid catalog CAS revision.');
    if ('folder_id' in input && !previous.folders.some(row => row.folder_id === input.folder_id))
      throw new Error('Folder must belong to current signed catalog.');
    if ('name' in input && input.operation !== 'rename' && previous.folders.some(row => row.name === input.name))
      throw new Error('Folder name already exists.');
    if (input.operation === 'rename' && previous.folders.some(row => row.name === input.name))
      throw new Error('Folder name already exists.');
    if (input.operation === 'delete' && previous.folders.some(row => row.folder_id === input.folder_id && row.items.length))
      throw new Error('Unassign resources before deleting a virtual folder.');
    if (input.operation === 'assign' && !previous.unassigned.some(row => row.artifact_id === input.artifact_id
      && row.artifact_sha256 === input.artifact_sha256))
      throw new Error('Artifact is not unassigned in the current signed catalog.');
    if (input.operation === 'unassign' && !previous.folders.some(row => row.items.some(item =>
      item.artifact_id === input.artifact_id && item.artifact_sha256 === input.artifact_sha256)))
      throw new Error('No matching current virtual folder assignment.');
    const body = JSON.stringify({
      ...input,expected_catalog_revision:previous.catalog_revision,explicit_human_confirmation:true,
    });
    if (body.length > 2048) throw new Error('Virtual folder mutation exceeds bounded metadata size.');
    // Avoid retaining bearer material in the anti-replay set.
    const attempt = JSON.stringify([actor.sub,actor.exp,scope,body]);
    if (attemptedWrites.has(attempt)) throw new Error('Folder mutation already attempted; GET readback only, never auto replay.');
    // Set BEFORE any awaited network operation (including an ambiguous lost ACK).
    attemptedWrites.add(attempt);
    let response: Response;
    try {
      response = await fetch(path(scope),{
        method:'POST',
        headers:{Authorization:actor.bearer,Accept:'application/json','Content-Type':'application/json'},
        body,credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
      });
      fresh(actor);
      if (response.status !== (input.operation === 'create' ? 201 : 200))
        throw new Error('Folder mutation was rejected or UNKNOWN.');
      const raw = await jsonResponse(response);
      fresh(actor);
      const postedFields = [
        'format','flow_id','engagement_id','flow_revision','authorization_version',
        'authorization_id','authorization_sha256','source_manifest_sha256',
        'catalog_revision','folders','unassigned','metadata_only','host_files_created',
        'worker_sync_performed','operation','event_id',
      ];
      const receipt = exact(raw, postedFields);
      if (receipt.operation !== input.operation || typeof receipt.event_id !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(receipt.event_id))
        throw new Error('Folder POST provenance event is unknown.');
      const rest: Record<string,unknown> = {};
      for (const key of postedFields) if (key !== 'operation' && key !== 'event_id') rest[key] = receipt[key];
      const posted = catalog(rest,scope);
      if (!mutationMatches(previous,posted,input))
        throw new Error('Folder POST CAS result is inconsistent; outcome UNKNOWN.');
      const verified = await read(scope,actor);
      if (!mutationMatches(previous,verified,input)
        || JSON.stringify(posted) !== JSON.stringify(verified))
        throw new Error('Current signed GET readback differs; outcome UNKNOWN.');
      fresh(actor);
      return verified;
    } catch {
      throw new Error('Folder POST outcome UNKNOWN or denied. Recheck current signed GET; NEVER automatically retry.');
    }
  },
};
