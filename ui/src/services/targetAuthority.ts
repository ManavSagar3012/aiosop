/** Target-owned detached assertion intake. Never asserts a verified finding. */
import { API_BASE, authHeaders, currentOperator, getRuntimeToken, isSecureApiBase, isSecureBrowserOrigin } from './api';

export interface TargetAssertionSubmission {
  engagementId: string;
  flowId: string;
  originalTaskId: string;
  sourceTaskId: string;
  targetTaskId: string;
  canonicalClaims: string;
  signature: string;
  ownershipAuditJson?: string;
  ownershipAuditSignature?: string;
  accessAuditJson?: string;
  accessAuditSignature?: string;
}

export interface TargetAssertionReceipt {
  status: 'target_assertion_admitted_candidate_only' | 'target_assertion_reverified_candidate_only';
  engagement_id: string;
  flow_id: string;
  source_task_id: string;
  target_task_id: string;
  proof_sha256: string;
  target_controlled_signature_verified: true;
  independent_target_authority_verified: true;
  finding_verified: false;
  authorization_violation_verified: false;
  report_release_approved: false;
  independent_audit_records_correlated?: boolean;
  durable_source_review_status?: 'UNKNOWN' | 'candidate_only';
}

const ID = /^(eng|flow|task)-[A-Za-z0-9._-]{1,78}$/;

export async function submitTargetAssertion(input: TargetAssertionSubmission, reverifyProofSha?: string): Promise<TargetAssertionReceipt> {
  if (currentOperator()?.role !== 'senior_operator' || !getRuntimeToken()
      || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Verified senior bearer and secure API required.');
  }
  if (![input.engagementId, input.flowId, input.originalTaskId, input.sourceTaskId, input.targetTaskId]
    .every(value => ID.test(value))
      || input.originalTaskId === input.sourceTaskId || input.originalTaskId === input.targetTaskId
      || input.sourceTaskId === input.targetTaskId
      || input.canonicalClaims.length < 2 || new TextEncoder().encode(input.canonicalClaims).length > 4096
      || !/^[A-Za-z0-9_-]{86}$/.test(input.signature)) {
    throw new Error('Exact signed source, two distinct observations and bounded detached assertion required.');
  }
  const auditFields = [input.ownershipAuditJson, input.ownershipAuditSignature, input.accessAuditJson, input.accessAuditSignature];
  const supplied = auditFields.filter(value => value !== undefined).length;
  if (supplied !== 0 && supplied !== 4) {
    throw new Error('All independent ownership and access audit fields are required together.');
  }
  if (supplied === 4 && (!/^[A-Za-z0-9_-]{86}$/.test(input.ownershipAuditSignature!)
      || !/^[A-Za-z0-9_-]{86}$/.test(input.accessAuditSignature!)
      || [input.ownershipAuditJson!, input.accessAuditJson!].some(value => new TextEncoder().encode(value).length > 4096 || value.length < 2))) {
    throw new Error('Malformed or oversized independent target audit.');
  }
  if (reverifyProofSha !== undefined && !/^[0-9a-f]{64}$/.test(reverifyProofSha)) {
    throw new Error('Exact immutable original proof digest is required for re-verification.');
  }
  const receiptPath = `${API_BASE}/engagements/${encodeURIComponent(input.engagementId)}/flows/${encodeURIComponent(input.flowId)}/target-authority/attestations`;
  const response = await fetch(
    reverifyProofSha === undefined ? receiptPath : `${receiptPath}/${reverifyProofSha}/reverify`,
    {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      body: JSON.stringify({
        original_source_task_id: input.originalTaskId,
        source_task_id: input.sourceTaskId,
        target_task_id: input.targetTaskId,
        claims_json: input.canonicalClaims,
        signature_b64url: input.signature,
        ...(supplied === 4 ? {
          ownership_audit_json: input.ownershipAuditJson,
          ownership_audit_signature: input.ownershipAuditSignature,
          access_audit_json: input.accessAuditJson,
          access_audit_signature: input.accessAuditSignature,
        } : {}),
      }),
    },
  );
  if (!response.ok) throw new Error(`Independent target assertion denied (HTTP ${response.status}); finding unverified.`);
  const data: unknown = await response.json();
  if (!data || typeof data !== 'object') throw new Error('Target assertion acknowledgement malformed.');
  const row = data as Partial<TargetAssertionReceipt>;
  if (row.status !== (reverifyProofSha === undefined ? 'target_assertion_admitted_candidate_only' : 'target_assertion_reverified_candidate_only')
      || row.engagement_id !== input.engagementId || row.flow_id !== input.flowId
      || row.source_task_id !== input.sourceTaskId || row.target_task_id !== input.targetTaskId
      || typeof row.proof_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(row.proof_sha256)
      || row.target_controlled_signature_verified !== true
      || row.independent_target_authority_verified !== true
      || row.finding_verified !== false
      || row.authorization_violation_verified !== false
      || row.report_release_approved !== false) {
    throw new Error('Target assertion was not independently acknowledged as candidate only.');
  }
  if (reverifyProofSha !== undefined && row.proof_sha256 !== reverifyProofSha) {
    throw new Error('Historical target authority source digest did not match the original immutable receipt.');
  }
  if (supplied === 4 && row.independent_audit_records_correlated !== true) {
    throw new Error('Independent target audit corroboration was not acknowledged.');
  }
  return row as TargetAssertionReceipt;
}

/** Read-only original signed-source verification; no body, nonce, or target call. */
export async function reverifyStoredTargetAssertion(engagementId: string, flowId: string, proofSha256: string): Promise<TargetAssertionReceipt> {
  if (currentOperator()?.role !== 'senior_operator' || !getRuntimeToken()
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Verified senior bearer and secure API required.');
  }
  if (!/^eng-[A-Za-z0-9._-]{1,60}$/.test(engagementId)
    || !/^flow-[A-Za-z0-9._-]{1,59}$/.test(flowId)
    || !/^[0-9a-f]{64}$/.test(proofSha256)) {
    throw new Error('Exact scoped immutable proof identity required.');
  }
  const response = await fetch(
    `${API_BASE}/engagements/${encodeURIComponent(engagementId)}/flows/${encodeURIComponent(flowId)}/target-authority/attestations/${proofSha256}/reverify`,
    { method: 'GET', headers: authHeaders({ Accept: 'application/json' }), credentials: 'omit',
      cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' },
  );
  if (!response.ok) throw new Error(`Archived target evidence unavailable (${response.status}); finding unverified.`);
  const data: unknown = await response.json();
  if (!data || typeof data !== 'object') throw new Error('Archived candidate evidence malformed.');
  const row = data as Partial<TargetAssertionReceipt>;
  if (row.status !== 'target_assertion_reverified_candidate_only'
    || row.engagement_id !== engagementId || row.flow_id !== flowId
    || row.proof_sha256 !== proofSha256
    || typeof row.source_task_id !== 'string' || typeof row.target_task_id !== 'string'
    || row.finding_verified !== false || row.authorization_violation_verified !== false
    || row.report_release_approved !== false
    || row.target_controlled_signature_verified !== true
    || !['UNKNOWN', 'candidate_only'].includes(row.durable_source_review_status ?? '')) {
    throw new Error('Archived signed source review lacks independent candidate-only proof.');
  }
  return row as TargetAssertionReceipt;
}
