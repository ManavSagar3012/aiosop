/** Read-only signed Flow virtual folders and approved Task resource preflight. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const FLOW = /^flow-[A-Za-z0-9._-]{1,90}$/;
const SHA = /^[0-9a-f]{64}$/;
const ART = /^artifact-[0-9a-f]{32}$/;
const TASK = /^task-[A-Za-z0-9._:-]{1,85}$/;
const ITEM_FIELDS = ['artifact_id','original_name','alias_path','virtual_folder','classification',
  'sha256','size_bytes','available_as_inert_data_only','approved_for_task',
  'approved_for_agent_instructions','executed'];
const ROOT_FIELDS = ['format','flow_id','flow_revision','authorization_version','source_manifest_sha256',
  'folders','items','count','aliases_persisted','virtual_folders_persisted','read_only',
  'host_files_created','container_resource_sync_performed','artifact_bytes_untrusted'];

export interface FlowAliasItem {
  artifact_id: string;
  original_name: string;
  alias_path: string;
  virtual_folder: 'virtual/text' | 'virtual/source';
  classification: 'utf8_inert_text' | 'utf8_inert_source';
  sha256: string;
  size_bytes: number;
  available_as_inert_data_only: true;
  approved_for_task: false;
  approved_for_agent_instructions: false;
  executed: false;
}
export interface FlowAliases {
  format: 'ai-osop-derived-flow-resource-aliases-v1';
  flow_id: string;
  flow_revision: number;
  authorization_version: number;
  source_manifest_sha256: string;
  folders: { path: 'virtual/text'|'virtual/source'; count: number }[];
  items: FlowAliasItem[];
  count: number;
  aliases_persisted: false;
  virtual_folders_persisted: false;
  read_only: true;
  host_files_created: false;
  container_resource_sync_performed: false;
  artifact_bytes_untrusted: true;
}
const attempts = new Set<string>();

function exact(raw: unknown, fields: string[]): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid signed Flow resource metadata.');
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).length !== fields.length || fields.some(field => !Object.prototype.hasOwnProperty.call(value, field)))
    throw new Error('Flow resource response contains private or unsupported metadata.');
  return value;
}
function item(raw: unknown): FlowAliasItem {
  const v = exact(raw, ITEM_FIELDS);
  if (typeof v.artifact_id !== 'string' || !ART.test(v.artifact_id)
    || typeof v.original_name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(v.original_name)
    || !['utf8_inert_text','utf8_inert_source'].includes(String(v.classification))
    || !['virtual/text','virtual/source'].includes(String(v.virtual_folder))
    || v.alias_path !== `${v.virtual_folder}/${v.artifact_id}/${v.original_name}`
    || typeof v.sha256 !== 'string' || !SHA.test(v.sha256)
    || !Number.isSafeInteger(v.size_bytes) || (v.size_bytes as number) < 1 || (v.size_bytes as number) > 2097152
    || v.available_as_inert_data_only !== true || v.approved_for_task !== false
    || v.approved_for_agent_instructions !== false || v.executed !== false)
    throw new Error('Untrusted executable resource classification or alias path.');
  return v as unknown as FlowAliasItem;
}
function scope(flowId: string, revision: number, version: number) {
  const actor = currentOperator();
  if (!actor?.sub || !['operator','senior_operator'].includes(actor.role)
    || !FLOW.test(flowId) || !Number.isSafeInteger(revision) || revision < 0
    || !Number.isSafeInteger(version) || version < 1
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin())
    throw new Error('Signed current Flow owner required to inspect resources.');
  const bearer = authHeaders().Authorization;
  if (!/^Bearer \S+$/.test(bearer ?? '')) throw new Error('Operator bearer unavailable.');
  return { actor, bearer };
}
function fresh(was: ReturnType<typeof scope>): void {
  const actor = currentOperator();
  if (!actor || actor.sub !== was.actor.sub || actor.role !== was.actor.role
    || actor.exp !== was.actor.exp || authHeaders().Authorization !== was.bearer)
    throw new Error('Operator identity changed during signed Flow resource read.');
}
async function get(url: string, was: ReturnType<typeof scope>): Promise<unknown> {
  const response = await fetch(url, {
    method: 'GET', headers: authHeaders({Accept:'application/json'}),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (response.status !== 200) throw new Error(`Signed resource unavailable (HTTP ${response.status}).`);
  const payload: unknown = await response.json();
  fresh(was);
  return payload;
}
function base(flowId: string, revision: number, version: number): string {
  return `${API_BASE}/flows/${encodeURIComponent(flowId)}/resource-aliases?expected_revision=${revision}&expected_authorization_version=${version}`;
}
export async function readFlowResourceAliases(flowId: string, revision: number, version: number): Promise<FlowAliases> {
  const was = scope(flowId, revision, version);
  const value = exact(await get(base(flowId, revision, version), was), ROOT_FIELDS);
  if (value.format !== 'ai-osop-derived-flow-resource-aliases-v1' || value.flow_id !== flowId
    || value.flow_revision !== revision || value.authorization_version !== version
    || typeof value.source_manifest_sha256 !== 'string' || !SHA.test(value.source_manifest_sha256)
    || !Array.isArray(value.items) || value.items.length > 16
    || !Number.isSafeInteger(value.count) || value.count !== value.items.length
    || !Array.isArray(value.folders) || value.folders.length !== 2
    || value.aliases_persisted !== false || value.virtual_folders_persisted !== false
    || value.read_only !== true || value.host_files_created !== false
    || value.container_resource_sync_performed !== false || value.artifact_bytes_untrusted !== true)
    throw new Error('Flow virtual folders are not a safe signed inert snapshot.');
  const items = value.items.map(item);
  const folderPaths = ['virtual/text','virtual/source'];
  const folders = value.folders.map((f, n) => {
    const record = exact(f,['path','count']);
    if (record.path !== folderPaths[n]
      || !Number.isSafeInteger(record.count)
      || record.count !== items.filter(i => i.virtual_folder === record.path).length)
      throw new Error('Unsafe or forged Flow alias folder.');
    return {path: record.path as 'virtual/text'|'virtual/source', count: record.count as number};
  });
  if (new Set(items.map(i => i.artifact_id)).size !== items.length)
    throw new Error('Duplicate signed Flow artifact alias.');
  return { ...value, items, folders } as unknown as FlowAliases;
}

export async function previewFlowAlias(flowId: string, revision: number, version: number,
  manifestSha: string, artifactId: string): Promise<FlowAliasItem> {
  const was = scope(flowId, revision, version);
  if (!SHA.test(manifestSha) || !ART.test(artifactId)) throw new Error('Current exact resource SHA/ID required.');
  const q = new URLSearchParams({
    expected_revision: String(revision), expected_authorization_version: String(version),
    expected_manifest_sha256: manifestSha,
  });
  const path = `${API_BASE}/flows/${encodeURIComponent(flowId)}/resource-aliases/${encodeURIComponent(artifactId)}/preview?${q}`;
  const raw = exact(await get(path, was), [
    ...ITEM_FIELDS,'flow_id','flow_revision','authorization_version','source_manifest_sha256',
    'preview_contains_artifact_bytes','replayable_or_executable',
  ]);
  if (raw.flow_id !== flowId || raw.flow_revision !== revision || raw.authorization_version !== version
    || raw.source_manifest_sha256 !== manifestSha
    || raw.preview_contains_artifact_bytes !== false || raw.replayable_or_executable !== false)
    throw new Error('Resource metadata preview forged or changed.');
  const copy: Record<string, unknown> = {};
  for (const field of ITEM_FIELDS) copy[field] = raw[field];
  const checked = item(copy);
  if (checked.artifact_id !== artifactId) throw new Error('Foreign Flow resource preview.');
  return checked;
}

/** Explicit approval preflight only. No file transfer, tool call or target mutation. */
export async function previewSignedTaskResource(input: {
  flowId: string; engagementId: string; revision: number; version: number;
  taskId: string; artifactId: string; artifactSha: string;
  authorizationSha: string; manifestSha: string; confirmed: boolean;
}): Promise<{ task_id: string; signed_task_currently_approved: true;
  approved_command_sha256: string; execution_started_by_preview: false }> {
  const was = scope(input.flowId, input.revision, input.version);
  if (!input.confirmed || !/^eng-[A-Za-z0-9._-]{1,60}$/.test(input.engagementId)
    || !TASK.test(input.taskId) || !ART.test(input.artifactId)
    || !SHA.test(input.artifactSha) || !SHA.test(input.authorizationSha) || !SHA.test(input.manifestSha))
    throw new Error('Explicit approved Task and exact current digests required.');
  const key = JSON.stringify([was.actor.sub,input]);
  if (attempts.has(key)) throw new Error('Task preview already attempted; manually recheck, do not auto repeat.');
  attempts.add(key);
  const url = `${API_BASE}/flows/${encodeURIComponent(input.flowId)}/resource-aliases/task-preview`
    + `?expected_revision=${input.revision}&expected_authorization_version=${input.version}`;
  const response = await fetch(url, {
    method: 'POST', headers: authHeaders({'Content-Type':'application/json',Accept:'application/json'}),
    body: JSON.stringify({
      engagement_id: input.engagementId, task_id: input.taskId, artifact_id: input.artifactId,
      artifact_sha256: input.artifactSha, authorization_sha256: input.authorizationSha,
      expected_manifest_sha256: input.manifestSha,
    }),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (response.status !== 200) throw new Error('Approved Task resource preview rejected or UNKNOWN; never auto retry.');
  const raw: unknown = await response.json();
  fresh(was);
  const result = exact(raw, [
    ...ITEM_FIELDS,'flow_id','flow_revision','authorization_version','source_manifest_sha256',
    'task_id','signed_task_currently_approved','approved_command_sha256',
    'preview_contains_artifact_bytes','resource_transferred_to_worker',
    'container_resource_sync_performed','execution_started_by_preview',
  ]);
  if (result.flow_id !== input.flowId || result.flow_revision !== input.revision
    || result.authorization_version !== input.version || result.source_manifest_sha256 !== input.manifestSha
    || result.task_id !== input.taskId || result.signed_task_currently_approved !== true
    || typeof result.approved_command_sha256 !== 'string' || !SHA.test(result.approved_command_sha256)
    || result.preview_contains_artifact_bytes !== false || result.resource_transferred_to_worker !== false
    || result.container_resource_sync_performed !== false || result.execution_started_by_preview !== false)
    throw new Error('Task resource preview falsely claims execution or contains unsafe metadata.');
  const metadata: Record<string, unknown> = {};
  for (const field of ITEM_FIELDS) metadata[field] = result[field];
  const checked = item(metadata);
  if (checked.artifact_id !== input.artifactId || checked.sha256 !== input.artifactSha)
    throw new Error('Task preview resource digest or identity changed.');
  return {task_id: input.taskId, signed_task_currently_approved: true,
    approved_command_sha256: result.approved_command_sha256, execution_started_by_preview: false};
}
