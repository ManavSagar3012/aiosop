/** Authenticated read-only 0039 global-original -> Flow review preflight.
 * Never copy source bytes, grant agent context, or treat PENDING as admission.
 */
import {
  API_BASE, authHeaders, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

export interface ReviewedFlowPreflightInput {
  flowId: string;
  engagement_id: string;
  expected_flow_revision: number;
  task_id: string;
  authorization_id: string;
  authorization_version: number;
  authorization_sha256: string;
  global_document_id: string;
  global_revision: number;
  global_sha256: string;
}

export interface PendingReviewedCitation {
  status: 'pending_atomic_reviewed_bind';
  source_id: string;
  original_revision: number;
  original_sha256: string;
  source_kind: 'guide' | 'answer' | 'code';
  engagement_id: string;
  flow_id: string;
  flow_revision: number;
  approved_for_agent_context: false;
  operator_knowledge_created: false;
  verified_target_evidence: false;
  safe_for_execution: false;
}

export interface RecordedReviewedCitation {
  citation_id: string;
  source_id: string;
  source_revision: number;
  source_sha256: string;
  engagement_id: string;
  flow_id: string;
  task_id: string;
  status: 'recorded_untrusted_source_citation';
  transaction_committed_citation: true;
  flow_local_document_created: false;
  approved_for_agent_context: false;
  verified_target_evidence: false;
  safe_for_execution: false;
  source_original_returned: false;
}

export interface StoredReviewedFlowOriginal {
  citation_id: string;
  source_id: string;
  source_revision: number;
  source_sha256: string;
  original_utf8_bytes: number;
  engagement_id: string;
  flow_id: string;
  task_id: string;
  status: 'reviewed_flow_original_stored_inert';
  transaction_committed_source_and_citation: true;
  flow_local_original_stored: true;
  approved_for_agent_context: false;
  verified_target_evidence: false;
  safe_for_execution: false;
  source_original_returned: false;
}

const SHA = /^[a-f0-9]{64}$/;
const LIBRARY = /^lib-[a-f0-9]{32}$/;
const FLOW = /^flow-[a-zA-Z0-9._:-]{1,59}$/;

function assertCitationInput(input: ReviewedFlowPreflightInput): void {
  if (!FLOW.test(input.flowId) || !LIBRARY.test(input.global_document_id) ||
      !SHA.test(input.global_sha256) || !SHA.test(input.authorization_sha256) ||
      !/^eng-[a-zA-Z0-9._:-]{1,60}$/.test(input.engagement_id) ||
      !/^task-[a-zA-Z0-9._:-]{1,123}$/.test(input.task_id) ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._@+:-]{0,127}$/.test(input.authorization_id) ||
      !Number.isSafeInteger(input.expected_flow_revision) || input.expected_flow_revision < 0 ||
      !Number.isSafeInteger(input.global_revision) || input.global_revision < 1 ||
      !Number.isSafeInteger(input.authorization_version) || input.authorization_version < 1) {
    throw new Error('Exact current original and signed Flow/Task/ROE identities are required.');
  }
}

async function boundedOriginalMetadata(response: Response): Promise<string> {
  if (!response.body) throw new Error('Reviewed source metadata body unavailable.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let count = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (count + next.value.byteLength > 4096) {
        throw new Error('Unbounded independent reviewer metadata rejected.');
      }
      count += next.value.byteLength;
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(count);
  let position = 0;
  for (const chunk of chunks) { bytes.set(chunk, position); position += chunk.byteLength; }
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new Error('Invalid reviewer metadata UTF-8.'); }
}

export async function preflightReviewedLibrarySource(input: ReviewedFlowPreflightInput): Promise<PendingReviewedCitation> {
  const actor = currentOperator();
  const originalToken = getRuntimeToken();
  if (!actor || !['operator', 'senior_operator'].includes(actor.role) || !originalToken ||
      !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current verified signed operator over a secure origin required.');
  }
  assertCitationInput(input);
  const { flowId, ...fields } = input;
  const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/reviewed-library-import/preflight`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
    body: JSON.stringify({ ...fields, flow_owner: actor.sub }),
    credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
  });
  if (getRuntimeToken() !== originalToken || currentOperator()?.sub !== actor.sub) {
    throw new Error('Signed principal changed during preflight.');
  }
  if (!response.ok) {
    throw new Error(response.status === 503
      ? 'Independent host reviewer, original source, Flow and ROE roots not enrolled; import remains unavailable.'
      : `Reviewed global-to-Flow preflight denied (HTTP ${response.status}).`);
  }
  const claimedSize = response.headers.get('content-length');
  if (claimedSize && (!/^\d+$/.test(claimedSize) || Number(claimedSize) > 4096)) {
    throw new Error('Unbounded reviewer response rejected.');
  }
  const wire = await boundedOriginalMetadata(response);
  if (getRuntimeToken() !== originalToken) throw new Error('Signed owner changed during reviewed preflight readback.');
  let value: Record<string, unknown>;
  try { value = JSON.parse(wire) as Record<string, unknown>; }
  catch { throw new Error('Invalid reviewed preflight response.'); }
  if (!value || Array.isArray(value) || value.status !== 'pending_atomic_reviewed_bind' ||
      value.source_id !== input.global_document_id || value.original_revision !== input.global_revision ||
      value.original_sha256 !== input.global_sha256 || value.flow_id !== input.flowId ||
      value.flow_revision !== input.expected_flow_revision || value.engagement_id !== input.engagement_id ||
      !['guide', 'answer', 'code'].includes(String(value.source_kind)) ||
      value.approved_for_agent_context !== false || value.operator_knowledge_created !== false ||
      value.safe_for_execution !== false || value.verified_target_evidence !== false ||
      'content' in value || 'source_original' in value || 'approval_token' in value) {
    throw new Error('Source was not a bounded non-promotable PENDING metadata citation.');
  }
  return value as unknown as PendingReviewedCitation;
}

/** One explicit protected request. Only `record-citation` writes; readback is nonmutating. */
async function reviewedCitationRequest(
  input: ReviewedFlowPreflightInput, action: 'record-citation' | 'record-citation/readback',
): Promise<RecordedReviewedCitation> {
  const actor = currentOperator();
  const token = getRuntimeToken();
  if (!actor || !['operator', 'senior_operator'].includes(actor.role) || !token ||
      !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Signed operator and secure API origin required for citation recording.');
  }
  assertCitationInput(input);
  const { flowId, ...fields } = input;
  // A network exception or discarded response means UNKNOWN. Never attempt a
  // second write or treat a preflight PENDING response as committed evidence.
  const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/reviewed-library-import/${action}`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
    body: JSON.stringify({ ...fields, flow_owner: actor.sub }),
    credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
  });
  if (getRuntimeToken() !== token || currentOperator()?.sub !== actor.sub || currentOperator()?.role !== actor.role) {
    throw new Error('Signed owner changed; citation completion UNKNOWN — do not retry.');
  }
  if (!response.ok) throw new Error(
    response.status === 503 ? 'Independent reviewer/citation writer not enrolled; nothing recorded.' :
      `Reviewed citation denied or completion UNKNOWN (HTTP ${response.status}); do not retry blindly.`,
  );
  const size = response.headers.get('content-length');
  if (size && (!/^\d+$/.test(size) || Number(size) > 4096)) throw new Error('Unbounded citation receipt; completion UNKNOWN.');
  const wire = await boundedOriginalMetadata(response);
  if (getRuntimeToken() !== token || currentOperator()?.sub !== actor.sub) {
    throw new Error('Signed owner changed during receipt; completion UNKNOWN.');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(wire); } catch { throw new Error('Citation completion UNKNOWN: unreadable receipt.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Citation completion UNKNOWN: unverified receipt.');
  }
  const row = parsed as Record<string, unknown>;
  const expected = new Set([
    'citation_id', 'source_id', 'source_revision', 'source_sha256', 'engagement_id', 'flow_id',
    'task_id', 'status', 'transaction_committed_citation', 'flow_local_document_created',
    'approved_for_agent_context', 'verified_target_evidence', 'safe_for_execution', 'source_original_returned',
  ]);
  if (Object.keys(row).length !== expected.size || Object.keys(row).some(key => !expected.has(key)) ||
      typeof row.citation_id !== 'string' || !/^citation-[a-f0-9]{32}$/.test(row.citation_id) ||
      row.source_id !== input.global_document_id || row.source_revision !== input.global_revision ||
      row.source_sha256 !== input.global_sha256 || row.engagement_id !== input.engagement_id ||
      row.flow_id !== input.flowId || row.task_id !== input.task_id ||
      row.status !== 'recorded_untrusted_source_citation' ||
      row.transaction_committed_citation !== true || row.flow_local_document_created !== false ||
      row.approved_for_agent_context !== false || row.verified_target_evidence !== false ||
      row.safe_for_execution !== false || row.source_original_returned !== false) {
    throw new Error('Citation completion UNKNOWN: inconsistent receipt; do not retry blindly.');
  }
  return row as unknown as RecordedReviewedCitation;
}

/** One explicit irreversible metadata write; never retries after lost HTTP ACK. */
export async function recordReviewedLibraryCitation(input: ReviewedFlowPreflightInput): Promise<RecordedReviewedCitation> {
  return reviewedCitationRequest(input, 'record-citation');
}

/** Fresh independent signed original/Task/ROE readback, no write or retry. */
export async function readbackReviewedLibraryCitation(input: ReviewedFlowPreflightInput): Promise<RecordedReviewedCitation> {
  return reviewedCitationRequest(input, 'record-citation/readback');
}

/** Immutable original+reference atomic Flow resource; it is NEVER agent context. */
async function reviewedOriginalRequest(
  input: ReviewedFlowPreflightInput,
  action: 'store-reviewed-original' | 'store-reviewed-original/readback',
): Promise<StoredReviewedFlowOriginal> {
  const actor = currentOperator();
  const token = getRuntimeToken();
  if (!actor || !['operator', 'senior_operator'].includes(actor.role) || !token ||
      !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current signed operator over secure origin required to store reviewed original.');
  }
  assertCitationInput(input);
  const { flowId, ...fields } = input;
  // A lost acknowledgement never triggers a resend. Manual readback is an
  // independently reverified, nonmutating operation with its own route.
  const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/reviewed-library-import/${action}`, {
    method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
    body: JSON.stringify({ ...fields, flow_owner: actor.sub }),
    credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
  });
  if (getRuntimeToken() !== token || currentOperator()?.sub !== actor.sub || currentOperator()?.role !== actor.role) {
    throw new Error('Signed original owner changed: operation UNKNOWN; do not resend.');
  }
  if (!response.ok) throw new Error(response.status === 503
    ? 'Independent source/review/Flow/ROE host roots not enrolled; reviewed original unavailable.'
    : `Reviewed original transaction/readback UNKNOWN (HTTP ${response.status}); do not retry the write.`);
  const length = response.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > 4096)) {
    throw new Error('Unbounded inert original receipt; completion UNKNOWN.');
  }
  const wire = await boundedOriginalMetadata(response);
  if (getRuntimeToken() !== token || currentOperator()?.sub !== actor.sub) {
    throw new Error('Signed original owner changed during receipt; completion UNKNOWN.');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(wire); } catch { throw new Error('Original completion UNKNOWN: unreadable metadata.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Original completion UNKNOWN: invalid metadata.');
  }
  const value = parsed as Record<string, unknown>;
  const fieldsExpected = new Set([
    'citation_id', 'source_id', 'source_revision', 'source_sha256', 'original_utf8_bytes',
    'engagement_id', 'flow_id', 'task_id', 'status', 'transaction_committed_source_and_citation',
    'flow_local_original_stored', 'approved_for_agent_context', 'verified_target_evidence',
    'safe_for_execution', 'source_original_returned',
  ]);
  if (Object.keys(value).length !== fieldsExpected.size || Object.keys(value).some(k => !fieldsExpected.has(k)) ||
      typeof value.citation_id !== 'string' || !/^citation-[a-f0-9]{32}$/.test(value.citation_id) ||
      value.source_id !== input.global_document_id || value.source_revision !== input.global_revision ||
      value.source_sha256 !== input.global_sha256 || value.engagement_id !== input.engagement_id ||
      value.flow_id !== input.flowId || value.task_id !== input.task_id ||
      typeof value.original_utf8_bytes !== 'number' || !Number.isSafeInteger(value.original_utf8_bytes) ||
      value.original_utf8_bytes < 1 || value.original_utf8_bytes > 8192 ||
      value.status !== 'reviewed_flow_original_stored_inert' ||
      value.transaction_committed_source_and_citation !== true || value.flow_local_original_stored !== true ||
      value.approved_for_agent_context !== false || value.verified_target_evidence !== false ||
      value.safe_for_execution !== false || value.source_original_returned !== false) {
    throw new Error('Reviewed original completion UNKNOWN: foreign, privileged or unbounded receipt.');
  }
  return value as unknown as StoredReviewedFlowOriginal;
}

/** An intentional one-shot write only. */
export async function storeReviewedFlowOriginal(input: ReviewedFlowPreflightInput): Promise<StoredReviewedFlowOriginal> {
  return reviewedOriginalRequest(input, 'store-reviewed-original');
}

/** Independent signed current joint citation+original readback, no write. */
export async function readbackStoredReviewedFlowOriginal(input: ReviewedFlowPreflightInput): Promise<StoredReviewedFlowOriginal> {
  return reviewedOriginalRequest(input, 'store-reviewed-original/readback');
}
