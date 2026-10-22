/** Signed-source senior review: candidate-only, never a verified vulnerability. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const engagement = /^eng-[A-Za-z0-9._-]{1,60}$/;
const flow = /^flow-[A-Za-z0-9._-]{1,59}$/;
const task = /^task-[A-Za-z0-9._-]{1,58}$/;
const finding = /^[A-Za-z0-9_.-]{1,128}$/;
const sha = /^[0-9a-f]{64}$/;
const versionSuffix = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

function validReport(engagementId: string, reportId: string): boolean {
  const prefix = `report-${engagementId}-`;
  return reportId.startsWith(prefix) && reportId.length <= 128
    && versionSuffix.test(reportId.slice(prefix.length));
}

export interface CandidateFindingReviewRequest {
  finding_id: string;
  report_id: string;
  original_source_task_id: string;
  source_task_id: string;
  target_task_id: string;
  proof_sha256: string;
  audit_sha256: string;
  report_source_evidence_sha256: string;
  expected_authorization_version: number;
  expected_flow_revision: number;
  expected_review_revision: number;
  decision_status: 'candidate_only' | 'UNKNOWN' | 'independent_verification_required';
}

export interface TargetEffectQualificationRequest extends CandidateFindingReviewRequest {
  review_decision_id: string;
  review_decision_sha256: string;
  expected_qualification_revision: number;
}

export interface IndependentEffectVerificationRequest extends TargetEffectQualificationRequest {
  qualification_id: string;
  qualification_sha256: string;
}

const reviewDecision = /^vfdec-[0-9a-f]{32}$/;
const qualificationId = /^teqa-[0-9a-f]{32}$/;
const verificationId = /^itefv-[0-9a-f]{32}$/;
const verificationFields = [
  'status', 'finding_verified', 'independent_effect_verified',
  'authorization_violation_verified', 'report_release_approved',
  'finding_release_eligible', 'verification_id', 'verification_sha256',
  'report_source_evidence_sha256',
] as const;

function checkedVerification(reply: unknown): Record<string, unknown> {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error('Malformed independent verification response.');
  const verdict = reply as Record<string, unknown>;
  // The API should return only these bounded public fields. Fail closed at
  // the browser too, rather than caching/forwarding private observer payloads
  // or treating a signed receipt as an authorization-violation verdict.
  if (Object.keys(verdict).length !== verificationFields.length
    || verificationFields.some((key) => !Object.prototype.hasOwnProperty.call(verdict, key))
    || verdict.status !== 'VERIFIED' || verdict.finding_verified !== true
    || verdict.independent_effect_verified !== true
    || verdict.authorization_violation_verified !== true
    || verdict.report_release_approved !== false
    || verdict.finding_release_eligible !== false || typeof verdict.verification_id !== 'string'
    || !verificationId.test(verdict.verification_id)
    || typeof verdict.verification_sha256 !== 'string' || !sha.test(verdict.verification_sha256)
    || typeof verdict.report_source_evidence_sha256 !== 'string'
    || !sha.test(verdict.report_source_evidence_sha256)) {
    throw new Error('Current signed verification unavailable or revoked; finding remains UNKNOWN.');
  }
  return verdict;
}

function effectEndpoint(engagementId: string, flowId: string): string {
  return endpoint(engagementId, flowId).replace(/finding-candidate-reviews$/, 'finding-effect-qualifications');
}

function validSource(engagementId: string, body: CandidateFindingReviewRequest): boolean {
  return finding.test(body.finding_id) && task.test(body.original_source_task_id)
    && task.test(body.source_task_id) && task.test(body.target_task_id)
    && new Set([body.original_source_task_id, body.source_task_id, body.target_task_id]).size === 3
    && sha.test(body.proof_sha256) && sha.test(body.audit_sha256)
    && sha.test(body.report_source_evidence_sha256)
    && Number.isSafeInteger(body.expected_authorization_version) && body.expected_authorization_version >= 1
    && Number.isSafeInteger(body.expected_flow_revision) && body.expected_flow_revision >= 0
    && Number.isSafeInteger(body.expected_review_revision) && body.expected_review_revision >= 0
    && ['candidate_only', 'UNKNOWN', 'independent_verification_required'].includes(body.decision_status)
    && validReport(engagementId, body.report_id);
}

function endpoint(engagementId: string, flowId: string): string {
  if (!engagement.test(engagementId) || !flow.test(flowId)
      || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
      || currentOperator()?.role !== 'senior_operator') {
    throw new Error('A securely authenticated senior operator and signed Flow are required.');
  }
  return `${API_BASE}/engagements/${encodeURIComponent(engagementId)}/flows/${encodeURIComponent(flowId)}/target-authority/finding-candidate-reviews`;
}

async function readReply(res: Response): Promise<Record<string, unknown>> {
  if (!res.ok) throw new Error(`Signed candidate review denied (${res.status}); no finding was verified.`);
  const body: unknown = await res.json();
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Malformed candidate-review response.');
  const result = body as Record<string, unknown>;
  if (result.finding_verified !== false || result.report_release_approved !== false) {
    throw new Error('Unsupported finding/release verification response.');
  }
  return result;
}

export const candidateFindingReviews = {
  async create(engagementId: string, flowId: string, body: CandidateFindingReviewRequest): Promise<Record<string, unknown>> {
    if (!validSource(engagementId, body)) {
      throw new Error('Exact source identity, independently signed hashes and current revision required.');
    }
    const response = await fetch(endpoint(engagementId, flowId), {
      method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
      body: JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    return readReply(response);
  },

  async read(engagementId: string, flowId: string, findingId: string, reportId: string,
             authorizationVersion: number): Promise<Record<string, unknown>> {
    if (!finding.test(findingId) || !validReport(engagementId, reportId)
      || !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1) {
      throw new Error('Exact finding, report and signed authorization required.');
    }
    const params = new URLSearchParams({ report_id: reportId, expected_authorization_version: String(authorizationVersion) });
    const response = await fetch(`${endpoint(engagementId, flowId)}/${encodeURIComponent(findingId)}?${params}`, {
      method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    return readReply(response);
  },

  async qualifyUnknown(engagementId: string, flowId: string,
                       body: TargetEffectQualificationRequest): Promise<Record<string, unknown>> {
    if (!validSource(engagementId, body) || !reviewDecision.test(body.review_decision_id)
      || !sha.test(body.review_decision_sha256)
      || !Number.isSafeInteger(body.expected_qualification_revision)
      || body.expected_qualification_revision < 0 || body.expected_qualification_revision >= 1000000) {
      throw new Error('Exact signed source, latest review and qualification CAS revision required.');
    }
    const response = await fetch(effectEndpoint(engagementId, flowId), {
      method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
      body: JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    const reply = await readReply(response);
    if (reply.status !== 'UNKNOWN' || reply.independent_target_effect_verified !== false
      || reply.finding_release_eligible !== false) {
      throw new Error('Unsupported independent target-effect verification claim.');
    }
    return reply;
  },

  async readEffectUnknown(engagementId: string, flowId: string,
                          findingId: string, reportId: string,
                          authorizationVersion: number): Promise<Record<string, unknown>> {
    if (!finding.test(findingId) || !validReport(engagementId, reportId)
      || !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1) {
      throw new Error('Exact signed current finding and report binding required.');
    }
    const params = new URLSearchParams({ report_id: reportId, expected_authorization_version: String(authorizationVersion) });
    const response = await fetch(`${effectEndpoint(engagementId, flowId)}/${encodeURIComponent(findingId)}?${params}`, {
      method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    const reply = await readReply(response);
    if (reply.status !== 'UNKNOWN' || reply.independent_target_effect_verified !== false
      || reply.finding_release_eligible !== false) {
      throw new Error('Independent target-effect verification still unavailable.');
    }
    return reply;
  },

  async verifyIndependent(engagementId: string, flowId: string,
                          body: IndependentEffectVerificationRequest): Promise<Record<string, unknown>> {
    if (!validSource(engagementId, body) || !reviewDecision.test(body.review_decision_id)
        || !sha.test(body.review_decision_sha256) || !qualificationId.test(body.qualification_id)
        || !sha.test(body.qualification_sha256)
        || !Number.isSafeInteger(body.expected_qualification_revision)
        || body.expected_qualification_revision < 1 || body.expected_qualification_revision >= 1000000) {
      throw new Error('Exact current immutable UNKNOWN and signed review must be selected.');
    }
    // Sends NO target URL, role credentials, nonce, observer signature or verification flag.
    // The API mints an atomic PostgreSQL challenge, reads only the separately
    // configured live audit witness and cryptographically rechecks all sources.
    const base = endpoint(engagementId, flowId).replace(/finding-candidate-reviews$/, 'finding-effect-verifications');
    const response = await fetch(base, {
      method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' }),
      body: JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    if (!response.ok) throw new Error(`Independent live verification unavailable (${response.status}). Original evidence remains UNKNOWN.`);
    const verdict = checkedVerification(await response.json());
    if (verdict.report_source_evidence_sha256 !== body.report_source_evidence_sha256) {
      throw new Error('POST verification source mismatch; finding remains UNKNOWN.');
    }
    return this.readIndependent(engagementId, flowId, body.finding_id, body.report_id,
      body.expected_authorization_version, verdict.verification_id as string,
      verdict.verification_sha256 as string, body.report_source_evidence_sha256);
  },

  async readIndependent(engagementId: string, flowId: string, findingId: string,
                        reportId: string, authorizationVersion: number,
                        expectedVerificationId: string, expectedVerificationSha256: string,
                        expectedSourceSha256: string): Promise<Record<string, unknown>> {
    if (!finding.test(findingId) || !validReport(engagementId, reportId)
      || !Number.isSafeInteger(authorizationVersion) || authorizationVersion < 1
      || !verificationId.test(expectedVerificationId) || !sha.test(expectedVerificationSha256)
      || !sha.test(expectedSourceSha256)) {
      throw new Error('Exact signed finding, current authorization and verification receipt required.');
    }
    const base = endpoint(engagementId, flowId).replace(/finding-candidate-reviews$/, 'finding-effect-verifications');
    const params = new URLSearchParams({ report_id: reportId, expected_authorization_version: String(authorizationVersion) });
    const response = await fetch(`${base}/${encodeURIComponent(findingId)}?${params}`, {
      method: 'GET', headers: authHeaders({ Accept: 'application/json' }),
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    });
    if (!response.ok) throw new Error(`Current independent verification denied (${response.status}); finding remains UNKNOWN.`);
    const verdict = checkedVerification(await response.json());
    if (verdict.verification_id !== expectedVerificationId
      || verdict.verification_sha256 !== expectedVerificationSha256
      || verdict.report_source_evidence_sha256 !== expectedSourceSha256) {
      throw new Error('Independent verification readback differs from signed receipt; finding remains UNKNOWN.');
    }
    return { ...verdict, durable_readback_verified: true, final_senior_signoff: false };
  },
};
