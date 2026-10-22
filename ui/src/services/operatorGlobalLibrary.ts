/** Read-only signed-owner discovery across separately authorized knowledge stores. */
import {
  API_BASE, authHeaders, currentOperator, getRuntimeToken,
  isSecureApiBase, isSecureBrowserOrigin,
} from './api';

export interface PinnedKnowledgeFlow {
  flowId: string;
  revision: number;
  authorizationVersion: number;
}
export type KnowledgeSource = 'user_global_0039' | 'flow_local_0019_0038';
export interface KnowledgeSearchItem {
  id: string;
  title: string;
  doc_type: 'guide' | 'answer' | 'code';
  revision: number;
  sha256: string;
  content_bytes: number;
  source: KnowledgeSource;
  trust: 'untrusted_human_text';
  verified_target_evidence: false;
  approved_for_agent_context: false;
  safe_for_execution: false;
  reportable: false;
  flow_id?: string;
  created_at?: string;
  version_created_at?: string;
  updated_at?: string;
  source_flow_revision?: number;
  authorization_version?: number;
}
export interface KnowledgeSearchPage {
  items: KnowledgeSearchItem[];
  has_more: boolean;
}
export interface OperatorKnowledgeDiscovery {
  status: 'metadata_only';
  query: string;
  sources: Partial<Record<KnowledgeSource, KnowledgeSearchPage>> & {
    user_global_0039: KnowledgeSearchPage;
  };
  atomic_cross_source_snapshot: false;
  synthesis_performed: false;
  independent_target_effect_verified: false;
  approved_for_agent_context: false;
  safe_for_execution: false;
  reportable: false;
}

const DOC = /^(lib-[0-9a-f]{32}|knowledge-[0-9a-f]{32})$/;
const FLOW = /^flow-[A-Za-z0-9._:-]{1,59}$/;
const SHA = /^[a-f0-9]{64}$/;
const MAX_RESPONSE_BYTES = 96 * 1024;
const MAX_RESULTS_PER_SOURCE = 10;
const ITEM_KEYS = new Set([
  'id', 'flow_id', 'title', 'doc_type', 'revision', 'sha256', 'content_bytes',
  'created_at', 'version_created_at', 'updated_at', 'source_flow_revision',
  'authorization_version', 'source', 'trust', 'verified_target_evidence',
  'approved_for_agent_context', 'safe_for_execution', 'reportable',
]);
const FLAGS = ['verified_target_evidence', 'approved_for_agent_context', 'safe_for_execution', 'reportable'] as const;

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Knowledge discovery returned an invalid metadata envelope.');
  }
  return value as Record<string, unknown>;
}

function scope() {
  const actor = currentOperator();
  const token = getRuntimeToken();
  if (!actor?.sub || !['operator', 'senior_operator'].includes(actor.role) ||
      !token || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current signed human operator session required for knowledge discovery.');
  }
  return { sub: actor.sub, role: actor.role, exp: actor.exp, token };
}

function assertCurrent(original: ReturnType<typeof scope>) {
  const actor = currentOperator();
  if (!actor || actor.sub !== original.sub || actor.role !== original.role ||
      actor.exp !== original.exp || getRuntimeToken() !== original.token) {
    throw new Error('Operator identity changed during knowledge discovery.');
  }
}

function item(value: unknown, source: KnowledgeSource, flow?: PinnedKnowledgeFlow): KnowledgeSearchItem {
  const row = object(value);
  if (Object.keys(row).some(key => !ITEM_KEYS.has(key)) ||
      typeof row.id !== 'string' || !DOC.test(row.id) ||
      (source === 'user_global_0039' ? !row.id.startsWith('lib-') : !row.id.startsWith('knowledge-')) ||
      typeof row.title !== 'string' || !row.title.trim() || row.title.length > 128 ||
      !['guide', 'answer', 'code'].includes(String(row.doc_type)) ||
      !Number.isSafeInteger(row.revision) || (row.revision as number) < 1 ||
      typeof row.sha256 !== 'string' || !SHA.test(row.sha256) ||
      !Number.isSafeInteger(row.content_bytes) || (row.content_bytes as number) < 1 ||
      (row.content_bytes as number) > 8192 || row.source !== source ||
      row.trust !== 'untrusted_human_text' || FLAGS.some(key => row[key] !== false) ||
      (source === 'user_global_0039' && row.flow_id !== undefined) ||
      (source === 'flow_local_0019_0038' && row.flow_id !== flow?.flowId) ||
      (row.source_flow_revision !== undefined &&
        (!Number.isSafeInteger(row.source_flow_revision) || (row.source_flow_revision as number) < 0 ||
          (row.source_flow_revision as number) > (flow?.revision ?? -1))) ||
      (row.authorization_version !== undefined &&
        (!Number.isSafeInteger(row.authorization_version) || row.authorization_version !== flow?.authorizationVersion))) {
    throw new Error('Knowledge source metadata or original provenance mismatch.');
  }
  return row as unknown as KnowledgeSearchItem;
}

function page(value: unknown, source: KnowledgeSource, flow?: PinnedKnowledgeFlow): KnowledgeSearchPage {
  const response = object(value);
  if (Object.keys(response).some(key => key !== 'items' && key !== 'has_more') ||
      !Array.isArray(response.items) || response.items.length > MAX_RESULTS_PER_SOURCE ||
      typeof response.has_more !== 'boolean') {
    throw new Error('Knowledge source page is incomplete or unbounded.');
  }
  const items = response.items.map(value => item(value, source, flow));
  if (new Set(items.map(doc => doc.id)).size !== items.length) {
    throw new Error('Duplicate original knowledge document identifier.');
  }
  return { items, has_more: response.has_more as boolean };
}

async function boundedJson(response: Response): Promise<unknown> {
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    throw new Error('Knowledge search response exceeds limits.');
  }
  if (!response.body) throw new Error('Knowledge search original response unavailable.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error('Knowledge search response exceeds limits.');
      chunks.push(chunk.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new Error('Knowledge search returned invalid UTF-8 JSON.');
  }
}

export async function searchOperatorKnowledge(
  query: string, flow?: PinnedKnowledgeFlow,
): Promise<OperatorKnowledgeDiscovery> {
  const actor = scope();
  if (typeof query !== 'string' || !query.trim() || query.length > 128 ||
      /[\x00-\x1f\x7f\uD800-\uDFFF]/u.test(query)) {
    throw new Error('Knowledge search must be printable bounded text.');
  }
  if (flow && (!FLOW.test(flow.flowId) ||
      !Number.isSafeInteger(flow.revision) || flow.revision < 0 ||
      !Number.isSafeInteger(flow.authorizationVersion) || flow.authorizationVersion < 1)) {
    throw new Error('Complete current signed Flow identity and revisions required.');
  }
  const url = new URL(`${API_BASE}/operator/search/knowledge`);
  url.searchParams.set('query', query.trim());
  url.searchParams.set('limit_per_source', String(MAX_RESULTS_PER_SOURCE));
  if (flow) {
    url.searchParams.set('flow_id', flow.flowId);
    url.searchParams.set('expected_flow_revision', String(flow.revision));
    url.searchParams.set('expected_authorization_version', String(flow.authorizationVersion));
  }
  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: authHeaders({ Accept: 'application/json' }),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  assertCurrent(actor);
  if (response.status !== 200) {
    throw new Error(`Signed knowledge discovery denied (HTTP ${response.status}); no partial results.`);
  }
  const raw = object(await boundedJson(response));
  assertCurrent(actor);
  if (raw.status !== 'metadata_only' || raw.query !== query.trim() ||
      raw.atomic_cross_source_snapshot !== false || raw.synthesis_performed !== false ||
      raw.independent_target_effect_verified !== false ||
      raw.approved_for_agent_context !== false || raw.safe_for_execution !== false ||
      raw.reportable !== false ||
      Object.keys(raw).some(key => ![
        'status', 'query', 'sources', 'atomic_cross_source_snapshot',
        'synthesis_performed', 'independent_target_effect_verified',
        'approved_for_agent_context', 'safe_for_execution', 'reportable',
      ].includes(key))) {
    throw new Error('Knowledge discovery cannot establish target effect or release authority.');
  }
  const sourcePages = object(raw.sources);
  const expectedKeys = flow
    ? ['user_global_0039', 'flow_local_0019_0038']
    : ['user_global_0039'];
  if (Object.keys(sourcePages).length !== expectedKeys.length ||
      expectedKeys.some(key => !Object.prototype.hasOwnProperty.call(sourcePages, key))) {
    throw new Error('Knowledge source denied or missing; partial results unavailable.');
  }
  const sources: OperatorKnowledgeDiscovery['sources'] = {
    user_global_0039: page(sourcePages.user_global_0039, 'user_global_0039'),
  };
  if (flow) sources.flow_local_0019_0038 = page(
    sourcePages.flow_local_0019_0038, 'flow_local_0019_0038', flow,
  );
  return {
    status: 'metadata_only', query: query.trim(), sources,
    atomic_cross_source_snapshot: false, synthesis_performed: false,
    independent_target_effect_verified: false, approved_for_agent_context: false,
    safe_for_execution: false, reportable: false,
  };
}
