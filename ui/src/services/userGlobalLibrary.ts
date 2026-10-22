/** Signed-user-owned inert knowledge. No Flow delegation or agent instruction source. */
import { API_BASE, authHeaders, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin } from './api';

export type UserLibraryKind = 'guide' | 'answer' | 'code';

export interface UserLibraryDocument {
  id: string;
  revision: number;
  title: string;
  doc_type: UserLibraryKind;
  sha256: string;
  content_bytes: number;
  created_at: string;
  version_created_at: string;
  content?: string;
}

export interface UserLibraryPage {
  items: UserLibraryDocument[];
  has_more: boolean;
}

export const GLOBAL_LIBRARY_PAGE_SIZE = 20;
const MAX_WIRE = 512 * 1024;
const idPattern = /^lib-[0-9a-f]{32}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const kinds = new Set(['guide', 'answer', 'code']);

function principalToken(): string {
  const operator = currentOperator();
  const token = getRuntimeToken();
  if (!operator || !['operator', 'senior_operator'].includes(operator.role) || !token ||
      !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('A current signed human operator session over a secure origin is required.');
  }
  return token;
}

function resource(id?: string, query?: string, offset: number = 0): string {
  principalToken();
  if (id !== undefined && !idPattern.test(id)) throw new Error('Invalid immutable library ID.');
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000) throw new Error('Library page outside bounds.');
  if (query !== undefined && (!query.trim() || query.length > 128 || /[\x00-\x1f\x7f]/.test(query))) {
    throw new Error('Library search must be printable bounded text.');
  }
  const url = new URL(`${API_BASE}/operator/library/documents${id ? `/${encodeURIComponent(id)}` : ''}`);
  if (query !== undefined) url.searchParams.set('query', query.trim());
  if (id === undefined) {
    url.searchParams.set('limit', String(GLOBAL_LIBRARY_PAGE_SIZE));
    url.searchParams.set('offset', String(offset));
  }
  return url.toString();
}

async function boundedResponse(response: Response): Promise<unknown> {
  const header = response.headers.get('content-length');
  if (header !== null && (!/^\d+$/.test(header) || Number(header) > MAX_WIRE)) {
    throw new Error('Unbounded library response rejected.');
  }
  if (!response.body) throw new Error('Original library response unavailable.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_WIRE) throw new Error('Library response exceeds maximum accepted size.');
      chunks.push(part.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let index = 0;
  for (const chunk of chunks) { bytes.set(chunk, index); index += chunk.byteLength; }
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('Original user library JSON is invalid.');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Library envelope denied.');
  return data;
}

async function request(url: string, method: string, data?: object): Promise<unknown> {
  const token = principalToken();
  const response = await fetch(url, {
    method,
    headers: authHeaders({ Accept: 'application/json', ...(data ? { 'Content-Type': 'application/json' } : {}) }),
    ...(data ? { body: JSON.stringify(data) } : {}),
    credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
  });
  // Never render data fetched under a previous human's token after signout.
  if (getRuntimeToken() !== token) throw new Error('Signed operator identity changed during library read.');
  if (!response.ok) throw new Error(`User library operation denied (HTTP ${response.status}).`);
  const payload = await boundedResponse(response);
  if (getRuntimeToken() !== token) throw new Error('Signed operator identity changed during library read.');
  return payload;
}

function checkedDocument(value: unknown, expectedId?: string, withContent = false): UserLibraryDocument {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Library document invalid.');
  const row = value as Record<string, unknown>;
  if (typeof row.id !== 'string' || !idPattern.test(row.id) ||
      (expectedId !== undefined && row.id !== expectedId) ||
      typeof row.title !== 'string' || !row.title.trim() || row.title.length > 128 ||
      typeof row.doc_type !== 'string' || !kinds.has(row.doc_type) ||
      !Number.isSafeInteger(row.revision) || (row.revision as number) < 1 ||
      typeof row.sha256 !== 'string' || !digestPattern.test(row.sha256) ||
      !Number.isSafeInteger(row.content_bytes) || (row.content_bytes as number) < 1 ||
      (row.content_bytes as number) > 8192 ||
      typeof row.created_at !== 'string' || typeof row.version_created_at !== 'string' ||
      row.content_classification !== 'untrusted_user_text' ||
      row.approved_for_agent_context !== false || row.verified_target_evidence !== false ||
      'untrusted_content' in row || 'owner_id' in row || 'owner_sub' in row ||
      (withContent ? typeof row.content !== 'string' : 'content' in row)) {
    throw new Error('Library content identity or classification cannot be trusted.');
  }
  return {
    id: row.id, revision: row.revision as number, title: row.title,
    doc_type: row.doc_type as UserLibraryKind, sha256: row.sha256,
    content_bytes: row.content_bytes as number, created_at: row.created_at,
    version_created_at: row.version_created_at,
    ...(withContent ? { content: row.content as string } : {}),
  };
}

function checkedPage(value: unknown): UserLibraryPage {
  const page = value as Record<string, unknown>;
  if (!page || typeof page !== 'object' || Array.isArray(page) || !Array.isArray(page.items) ||
      page.items.length > GLOBAL_LIBRARY_PAGE_SIZE || typeof page.has_more !== 'boolean' ||
      page.content_classification !== 'untrusted_user_text' || page.approved_for_agent_context !== false) {
    throw new Error('Unbounded or untrusted library page rejected.');
  }
  const items = page.items.map(item => checkedDocument(item));
  if (new Set(items.map(item => item.id)).size !== items.length) throw new Error('Duplicate original library item.');
  return { items, has_more: page.has_more };
}

function input(title: string, content: string, kind: UserLibraryKind): void {
  const raw = new TextEncoder().encode(content);
  if (!title.trim() || title.length > 128 || /[\x00-\x1f\x7f]/.test(title) ||
      !kinds.has(kind) || raw.byteLength < 1 || raw.byteLength > 8192 ||
      /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(content)) {
    throw new Error('Bounded plain-text user document required; no control sequences.');
  }
}

async function checkedReadContent(document: UserLibraryDocument): Promise<UserLibraryDocument> {
  const originalToken = principalToken();
  const raw = new TextEncoder().encode(document.content ?? '');
  if (raw.byteLength !== document.content_bytes || !globalThis.crypto?.subtle) {
    throw new Error('Original library SHA-256 verification unavailable.');
  }
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', raw));
  const hex = [...hash].map(value => value.toString(16).padStart(2, '0')).join('');
  if (hex !== document.sha256) throw new Error('Original library bytes no longer match advertised digest.');
  if (principalToken() !== originalToken) throw new Error('Signed owner changed during original byte verification.');
  return document;
}

async function confirmOriginalWrite(
  committed: UserLibraryDocument, title: string, kind: UserLibraryKind, content: string,
  originalToken: string,
): Promise<UserLibraryDocument> {
  // A successful POST/PUT response is not custody of the committed original.
  // An independent, current owner-scoped GET must return exactly the bytes
  // that were submitted, with its original SHA-256 checked by get(). Never
  // retry a mutation if the response/readback is lost or ambiguous.
  if (principalToken() !== originalToken) {
    throw new Error('Original write outcome UNKNOWN: signed owner changed before readback.');
  }
  let original: UserLibraryDocument;
  try {
    original = await userGlobalLibraryApi.get(committed.id);
  } catch {
    throw new Error('Original write outcome UNKNOWN: current SHA-checked readback unavailable. Do not retry automatically.');
  }
  if (principalToken() !== originalToken ||
      original.revision !== committed.revision || original.sha256 !== committed.sha256 ||
      original.content_bytes !== committed.content_bytes || original.title !== title ||
      original.doc_type !== kind || original.content !== content) {
    throw new Error('Original write outcome UNKNOWN: committed bytes or revision differ from current owner readback.');
  }
  return original;
}

export const userGlobalLibraryApi = {
  async list(offset = 0, query?: string): Promise<UserLibraryPage> {
    return checkedPage(await request(resource(undefined, query, offset), 'GET'));
  },
  async get(id: string): Promise<UserLibraryDocument> {
    return checkedReadContent(checkedDocument(await request(resource(id), 'GET'), id, true));
  },
  async create(title: string, doc_type: UserLibraryKind, content: string): Promise<UserLibraryDocument> {
    title = title.trim();
    input(title, content, doc_type);
    const originalToken = principalToken();
    const result = checkedDocument(await request(resource(), 'POST', { title, doc_type, content }));
    if (result.revision !== 1) throw new Error('First user library revision not admitted.');
    return confirmOriginalWrite(result, title, doc_type, content, originalToken);
  },
  async update(document: UserLibraryDocument, title: string, content: string): Promise<UserLibraryDocument> {
    title = title.trim();
    input(title, content, document.doc_type);
    if (!Number.isSafeInteger(document.revision) || document.revision < 1) throw new Error('Exact version required.');
    const originalToken = principalToken();
    const result = checkedDocument(await request(resource(document.id), 'PUT', {
      title, doc_type: document.doc_type, content, expected_revision: document.revision,
    }), document.id);
    if (result.revision !== document.revision + 1) throw new Error('Library revision CAS mismatch.');
    return confirmOriginalWrite(result, title, document.doc_type, content, originalToken);
  },
  async remove(document: UserLibraryDocument): Promise<void> {
    if (!Number.isSafeInteger(document.revision) || document.revision < 1) throw new Error('Exact version required.');
    const result = await request(resource(document.id), 'DELETE', { expected_revision: document.revision }) as Record<string, unknown>;
    if (result.id !== document.id || result.revision !== document.revision || result.status !== 'tombstoned' ||
        result.safe_for_execution !== false) {
      throw new Error('User library tombstone confirmation was ambiguous.');
    }
  },
};
