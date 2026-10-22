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

const SHA = /^[a-f0-9]{64}$/;
const LIBRARY = /^lib-[a-f0-9]{32}$/;
const FLOW = /^flow-[a-zA-Z0-9._:-]{1,59}$/;

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
