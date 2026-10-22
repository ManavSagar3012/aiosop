/** Owner-scoped inert knowledge documents: never injected into agent prompts. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

export interface OperatorKnowledgeDocument {
  id: string;
  title: string;
  doc_type: 'guide' | 'answer' | 'code';
  revision: number;
  sha256: string;
  content?: string;
}

export interface KnowledgeScope {
  flowId: string;
  revision: number;
  authorizationVersion: number;
}

export interface KnowledgePage {
  items: OperatorKnowledgeDocument[];
  has_more: boolean;
  limit: number;
  offset: number;
}

export interface KnowledgePageOptions {
  offset?: number;
  docType?: 'guide' | 'answer' | 'code';
}

export const KNOWLEDGE_PAGE_SIZE = 20;

const flowPattern = /^flow-[A-Za-z0-9._-]{1,59}$/;
const documentPattern = /^knowledge-[A-Za-z0-9._-]{1,100}$/;

function location(scope: KnowledgeScope): string {
  if (!flowPattern.test(scope.flowId) || !Number.isSafeInteger(scope.revision) || scope.revision < 0
    || !Number.isSafeInteger(scope.authorizationVersion) || scope.authorizationVersion < 1
    || !currentOperator() || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current signed Flow authorization and operator identity required.');
  }
  const params = new URLSearchParams({
    expected_revision: String(scope.revision),
    expected_authorization_version: String(scope.authorizationVersion),
  });
  return `${API_BASE}/flows/${encodeURIComponent(scope.flowId)}/operator-knowledge?${params}`;
}

async function request<T>(url: string, method: string, data?: object): Promise<T> {
  const result = await fetch(url, {
    method, headers: authHeaders({ Accept: 'application/json', ...(data ? { 'Content-Type': 'application/json' } : {}) }),
    ...(data ? { body: JSON.stringify(data) } : {}),
    cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (!result.ok) throw new Error(`Operator knowledge request rejected (${result.status}). Refresh signed Flow authority.`);
  if (result.status === 204) return {} as T;
  const payload: unknown = await result.json();
  if (!payload || typeof payload !== 'object') throw new Error('Invalid knowledge response.');
  return payload as T;
}

function itemUrl(scope: KnowledgeScope, id: string): string {
  if (!documentPattern.test(id)) throw new Error('Invalid bounded knowledge document identifier.');
  return location(scope).replace('/operator-knowledge?', `/operator-knowledge/${encodeURIComponent(id)}?`);
}

function pageLocation(scope: KnowledgeScope, options: KnowledgePageOptions, query?: string): string {
  const offset = options.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000) {
    throw new Error('Knowledge page exceeds the authorized bounds.');
  }
  if (options.docType !== undefined && !['guide', 'answer', 'code'].includes(options.docType)) {
    throw new Error('Unrecognized knowledge type.');
  }
  if (query !== undefined && (query.trim().length < 1 || query.length > 128 || /[\x00-\x1f\x7f]/.test(query))) {
    throw new Error('Search must be bounded printable text.');
  }
  const url = new URL(location(scope));
  if (query !== undefined) {
    url.pathname += '/search';
    url.searchParams.set('query', query.trim());
  }
  url.searchParams.set('limit', String(KNOWLEDGE_PAGE_SIZE));
  url.searchParams.set('offset', String(offset));
  if (options.docType) url.searchParams.set('doc_type', options.docType);
  return url.toString();
}

function checkedPage(data: KnowledgePage, scope: KnowledgeScope, requestedOffset: number): KnowledgePage {
  const raw = data as unknown;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Knowledge page invalid.');
  const page = raw as Record<string, unknown>;
  if (!Array.isArray(page.items) || page.items.length > KNOWLEDGE_PAGE_SIZE ||
    typeof page.has_more !== 'boolean' || page.limit !== KNOWLEDGE_PAGE_SIZE || page.offset !== requestedOffset) {
    throw new Error('Knowledge page invalid.');
  }
  const seen = new Set<string>();
  const items: OperatorKnowledgeDocument[] = [];
  for (const item of page.items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Knowledge document invalid.');
    const row = item as Record<string, unknown>;
    if (typeof row.id !== 'string' || !documentPattern.test(row.id) || seen.has(row.id) ||
      row.flow_id !== scope.flowId || row.authorization_version !== scope.authorizationVersion ||
      typeof row.title !== 'string' || row.title.length < 1 || row.title.length > 128 ||
      !['guide', 'answer', 'code'].includes(String(row.doc_type)) ||
      !Number.isSafeInteger(row.revision) || (row.revision as number) < 1 ||
      typeof row.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(row.sha256) ||
      row.approved_for_agent_context !== false || row.content_classification !== 'untrusted_operator_text' ||
      'content' in row || 'untrusted_content' in row) {
      throw new Error('Knowledge document has untrusted or foreign metadata.');
    }
    seen.add(row.id);
    items.push({ id: row.id, title: row.title, doc_type: row.doc_type as OperatorKnowledgeDocument['doc_type'],
      revision: row.revision as number, sha256: row.sha256 });
  }
  return { items, has_more: page.has_more, limit: KNOWLEDGE_PAGE_SIZE, offset: requestedOffset };
}

function checkedDocument(raw: unknown, scope: KnowledgeScope, expectedId: string): OperatorKnowledgeDocument {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Knowledge document invalid.');
  const item = raw as Record<string, unknown>;
  // The GET contract intentionally calls editable text `untrusted_content`.
  // The legacy client expected `content` and silently opened an EMPTY editor,
  // allowing an accidental overwrite of an existing record on Save.
  if (item.id !== expectedId || item.flow_id !== scope.flowId ||
    item.authorization_version !== scope.authorizationVersion ||
    typeof item.title !== 'string' || item.title.length < 1 || item.title.length > 128 ||
    !['guide', 'answer', 'code'].includes(String(item.doc_type)) ||
    !Number.isSafeInteger(item.revision) || (item.revision as number) < 1 ||
    typeof item.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(item.sha256) ||
    typeof item.untrusted_content !== 'string' || item.untrusted_content.length > 8192 ||
    item.content_classification !== 'untrusted_operator_text' ||
    item.approved_for_agent_context !== false || 'content' in item) {
    throw new Error('Knowledge content is stale, foreign or not explicitly untrusted.');
  }
  return { id: expectedId, title: item.title, doc_type: item.doc_type as OperatorKnowledgeDocument['doc_type'],
    revision: item.revision as number, sha256: item.sha256, content: item.untrusted_content };
}

export const operatorKnowledgeApi = {
  async list(scope: KnowledgeScope, options: KnowledgePageOptions = {}): Promise<KnowledgePage> {
    const offset = options.offset ?? 0;
    const page = await request<KnowledgePage>(pageLocation(scope, options), 'GET');
    return checkedPage(page, scope, offset);
  },
  async search(scope: KnowledgeScope, query: string, options: KnowledgePageOptions = {}): Promise<KnowledgePage> {
    const offset = options.offset ?? 0;
    const page = await request<KnowledgePage>(pageLocation(scope, options, query), 'GET');
    return checkedPage(page, scope, offset);
  },
  async get(scope: KnowledgeScope, id: string): Promise<OperatorKnowledgeDocument> {
    const result: unknown = await request(itemUrl(scope, id), 'GET');
    return checkedDocument(result, scope, id);
  },
  create(scope: KnowledgeScope, title: string, doc_type: 'guide' | 'answer' | 'code', content: string): Promise<OperatorKnowledgeDocument> {
    if (!title.trim() || title.length > 128 || !content.trim() || content.length > 8192)
      throw new Error('Title/content exceed bounded knowledge limits.');
    return request(location(scope), 'POST', { title, doc_type, content });
  },
  update(scope: KnowledgeScope, doc: OperatorKnowledgeDocument, title: string, content: string): Promise<OperatorKnowledgeDocument> {
    if (!Number.isSafeInteger(doc.revision) || doc.revision < 1 || !title.trim() || title.length > 128 || !content.trim() || content.length > 8192)
      throw new Error('Document revision and bounded content required.');
    return request(itemUrl(scope, doc.id), 'PUT', {
      title, doc_type: doc.doc_type, content, expected_document_revision: doc.revision,
    });
  },
  remove(scope: KnowledgeScope, doc: OperatorKnowledgeDocument): Promise<object> {
    if (!Number.isSafeInteger(doc.revision) || doc.revision < 1)
      throw new Error('Exact document revision required.');
    return request(itemUrl(scope, doc.id), 'DELETE', { expected_document_revision: doc.revision });
  },
};
