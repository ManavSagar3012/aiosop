/** Inert signed-Flow candidate evidence references; never verified target effects. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const ENGAGEMENT_ID = /^eng-[A-Za-z0-9._-]{1,60}$/;
const FLOW_ID = /^flow-[A-Za-z0-9._-]{1,90}$/;
const FINDING_ID = /^[A-Za-z0-9._-]{1,128}$/;
const ARTIFACT_ID = /^ev-[A-Za-z0-9._-]{1,60}$/;
const SOURCE_TASK_ID = /^task-[A-Za-z0-9._-]{1,90}$/;
const DIGEST = /^[0-9a-f]{64}$/;

const RESULT_FIELDS = [
  'engagement_id', 'finding_id', 'flow_id', 'flow_revision',
  'authorization_version', 'verification_state', 'finding_verified',
  'independent_target_effect_verified', 'artifacts',
] as const;
const ARTIFACT_FIELDS = [
  'artifact_id', 'source_task_id', 'merkle_leaf_sha256',
  'verification_state', 'independent_target_effect_verified',
] as const;
const ASSOCIATION_FIELDS = [
  'status', 'artifact_id', 'merkle_leaf_sha256', 'finding_verified',
  'independent_target_effect_verified', 'safe_to_automatically_retry',
] as const;
// A single tab must not issue the same association POST twice after a lost
// acknowledgement. Deliberately retain attempts across component unmounts,
// including HTTP 503 and malformed/unknown responses. This is NOT a durable
// deduplication guarantee: server-side source CAS remains authoritative.
const attemptedAssociationKeys = new Set<string>();

function associationKey(engagementId: string, findingId: string, flowId: string, sourceTaskId: string): string {
  return JSON.stringify([engagementId, findingId, flowId, sourceTaskId]);
}

export function signedNavigationAssociationAlreadyAttempted(
  engagementId: string, findingId: string, flowId: string, sourceTaskId: string,
): boolean {
  return attemptedAssociationKeys.has(associationKey(engagementId, findingId, flowId, sourceTaskId));
}

export interface CandidateEvidenceReference {
  artifact_id: string;
  source_task_id: string;
  merkle_leaf_sha256: string;
  verification_state: 'candidate_unverified';
  independent_target_effect_verified: false;
}

export interface CandidateEvidenceReadback {
  engagement_id: string;
  finding_id: string;
  flow_id: string;
  flow_revision: number;
  authorization_version: number;
  verification_state: 'candidate_unverified';
  finding_verified: false;
  independent_target_effect_verified: false;
  artifacts: CandidateEvidenceReference[];
}

export interface SignedNavigationCandidateAssociation {
  status: 'candidate_evidence_recorded_unverified';
  artifact_id: string;
  merkle_leaf_sha256: string;
  finding_verified: false;
  independent_target_effect_verified: false;
  safe_to_automatically_retry: false;
}

export interface AssociateSignedNavigationInput {
  engagementId: string;
  findingId: string;
  flowId: string;
  sourceTaskId: string;
  expectedFlowRevision: number;
  expectedAuthorizationVersion: number;
  explicitHumanConfirmation: boolean;
}

export function validCandidateFindingId(findingId: string): boolean {
  return typeof findingId === 'string' && FINDING_ID.test(findingId);
}

export function validSignedNavigationSourceTaskId(sourceTaskId: string): boolean {
  return typeof sourceTaskId === 'string' && SOURCE_TASK_ID.test(sourceTaskId);
}

function exactFields(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Candidate evidence response is not a public schema object.');
  }
  const object = value as Record<string, unknown>;
  if (Object.keys(object).length !== fields.length ||
      fields.some(field => !Object.prototype.hasOwnProperty.call(object, field))) {
    // Fail closed on body, headers, URL, private witness, replay recipe, etc.
    throw new Error('Candidate evidence response includes unsupported or private fields.');
  }
  return object;
}

/** Strictly verify only the server's candidate-only public schema, then copy it. */
export async function readCandidateEvidenceArtifacts(
  engagementId: string, findingId: string, flowId: string,
  expectedFlowRevision: number, expectedAuthorizationVersion: number,
): Promise<CandidateEvidenceReadback> {
  const identity = currentOperator();
  if (!identity || identity.role !== 'senior_operator' || !identity.sub.trim()
    || !ENGAGEMENT_ID.test(engagementId) || !validCandidateFindingId(findingId)
    || !FLOW_ID.test(flowId)
    || !Number.isSafeInteger(expectedFlowRevision) || expectedFlowRevision < 0
    || !Number.isSafeInteger(expectedAuthorizationVersion) || expectedAuthorizationVersion < 1
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current senior operator, signed Flow and bounded candidate identifiers required.');
  }
  const headers = authHeaders({ Accept: 'application/json' });
  const bearer = headers.Authorization;
  if (typeof bearer !== 'string' || !/^Bearer \S+$/.test(bearer)) {
    throw new Error('Verified senior operator bearer required.');
  }
  const query = new URLSearchParams({
    flow_id: flowId,
    expected_flow_revision: String(expectedFlowRevision),
    expected_authorization_version: String(expectedAuthorizationVersion),
  });
  const url = `${API_BASE}/engagements/${encodeURIComponent(engagementId)}`
    + `/findings/${encodeURIComponent(findingId)}/candidate-evidence-artifacts?${query.toString()}`;
  const response = await fetch(url, {
    method: 'GET', headers, credentials: 'omit', cache: 'no-store',
    redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (!response.ok) {
    // Response body is never surfaced; it may include private provider text.
    throw new Error(`Current signed candidate evidence unavailable (HTTP ${response.status}).`);
  }
  const body: unknown = await response.json();
  const result = exactFields(body, RESULT_FIELDS);
  if (result.engagement_id !== engagementId || result.finding_id !== findingId
    || result.flow_id !== flowId || result.flow_revision !== expectedFlowRevision
    || result.authorization_version !== expectedAuthorizationVersion
    || result.verification_state !== 'candidate_unverified'
    || result.finding_verified !== false
    || result.independent_target_effect_verified !== false
    || !Array.isArray(result.artifacts) || result.artifacts.length > 100) {
    throw new Error('Stale or falsely verified candidate evidence readback.');
  }
  const seen = new Set<string>();
  const artifacts = result.artifacts.map(entry => {
    const artifact = exactFields(entry, ARTIFACT_FIELDS);
    if (typeof artifact.artifact_id !== 'string' || !ARTIFACT_ID.test(artifact.artifact_id)
      || seen.has(artifact.artifact_id)
      || typeof artifact.source_task_id !== 'string' || !SOURCE_TASK_ID.test(artifact.source_task_id)
      || typeof artifact.merkle_leaf_sha256 !== 'string' || !DIGEST.test(artifact.merkle_leaf_sha256)
      || artifact.verification_state !== 'candidate_unverified'
      || artifact.independent_target_effect_verified !== false) {
      throw new Error('Private, duplicate or unverified source artifact declaration.');
    }
    seen.add(artifact.artifact_id);
    return {
      artifact_id: artifact.artifact_id,
      source_task_id: artifact.source_task_id,
      merkle_leaf_sha256: artifact.merkle_leaf_sha256,
      verification_state: 'candidate_unverified' as const,
      independent_target_effect_verified: false as const,
    };
  });
  const current = currentOperator();
  if (!current || current.role !== 'senior_operator' || current.sub !== identity.sub
    || current.exp !== identity.exp || authHeaders().Authorization !== bearer) {
    throw new Error('Senior operator changed during candidate evidence readback.');
  }
  return {
    engagement_id: engagementId,
    finding_id: findingId,
    flow_id: flowId,
    flow_revision: expectedFlowRevision,
    authorization_version: expectedAuthorizationVersion,
    verification_state: 'candidate_unverified',
    finding_verified: false,
    independent_target_effect_verified: false,
    artifacts,
  };
}

/**
 * Associate an ALREADY completed/approved signed navigate Task; never drive a
 * browser or accept provider testimony from the UI. One explicit POST only.
 * An HTTP timeout, 503, or malformed acknowledgement is UNKNOWN: callers must
 * use independent GET readback, not auto-POST again.
 */
export async function associateCompletedSignedNavigationCandidate(
  input: AssociateSignedNavigationInput,
): Promise<SignedNavigationCandidateAssociation> {
  const {
    engagementId, findingId, flowId, sourceTaskId,
    expectedFlowRevision, expectedAuthorizationVersion, explicitHumanConfirmation,
  } = input;
  const identity = currentOperator();
  if (!identity || identity.role !== 'senior_operator' || !identity.sub.trim()
      || explicitHumanConfirmation !== true
      || !ENGAGEMENT_ID.test(engagementId) || !validCandidateFindingId(findingId)
      || !FLOW_ID.test(flowId) || !validSignedNavigationSourceTaskId(sourceTaskId)
      || !Number.isSafeInteger(expectedFlowRevision) || expectedFlowRevision < 0
      || !Number.isSafeInteger(expectedAuthorizationVersion) || expectedAuthorizationVersion < 1
      || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Explicit senior signoff and current bounded signed source/Flow required.');
  }
  const headers = authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' });
  const bearer = headers.Authorization;
  if (typeof bearer !== 'string' || !/^Bearer \S+$/.test(bearer)) {
    throw new Error('Verified senior operator bearer required.');
  }
  // Crucial: no raw URLs, header/body captures, fake receipts or model output
  // are forwarded. The backend reconstructs signed source provenance itself.
  const body = {
    flow_id: flowId,
    source_task_id: sourceTaskId,
    expected_flow_revision: expectedFlowRevision,
    expected_authorization_version: expectedAuthorizationVersion,
  };
  const tuple = associationKey(engagementId, findingId, flowId, sourceTaskId);
  if (attemptedAssociationKeys.has(tuple)) {
    throw new Error('Association already attempted; outcome may be UNKNOWN. Use manual candidate GET readback, not another POST.');
  }
  if (attemptedAssociationKeys.size >= 1024) {
    throw new Error('Association attempt limit reached. Use manual GET readback.');
  }
  attemptedAssociationKeys.add(tuple); // Before network: no duplicate even on concurrent clicks.
  let response: Response;
  try {
    response = await fetch(
      `${API_BASE}/engagements/${encodeURIComponent(engagementId)}`
        + `/findings/${encodeURIComponent(findingId)}/candidate-evidence-artifacts/from-signed-navigation`,
      {
        method: 'POST', headers, body: JSON.stringify(body),
        credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      },
    );
  } catch {
    // Transport failures may hide a committed write. Never forward exception
    // strings: they can contain target URLs, bearer values or response bodies.
    throw new Error('Candidate association outcome UNKNOWN; manual GET readback required.');
  }
  if (!response.ok || response.status !== 200) {
    // A 503 might follow a committed write. No provider text or response body.
    throw new Error('Candidate association outcome UNKNOWN; manual GET readback required.');
  }
  let rawReceipt: unknown;
  try {
    rawReceipt = await response.json() as unknown;
  } catch {
    throw new Error('Candidate association response UNKNOWN; manual GET readback required.');
  }
  const receipt = exactFields(rawReceipt, ASSOCIATION_FIELDS);
  if (receipt.status !== 'candidate_evidence_recorded_unverified'
      || typeof receipt.artifact_id !== 'string' || !ARTIFACT_ID.test(receipt.artifact_id)
      || typeof receipt.merkle_leaf_sha256 !== 'string' || !DIGEST.test(receipt.merkle_leaf_sha256)
      || receipt.finding_verified !== false
      || receipt.independent_target_effect_verified !== false
      || receipt.safe_to_automatically_retry !== false) {
    throw new Error('Candidate association response UNKNOWN or falsely verified; manual GET readback required.');
  }
  const current = currentOperator();
  if (!current || current.role !== 'senior_operator' || current.sub !== identity.sub
      || current.exp !== identity.exp || authHeaders().Authorization !== bearer) {
    throw new Error('Senior operator changed during association; outcome UNKNOWN. Manually read back.');
  }
  return {
    status: 'candidate_evidence_recorded_unverified',
    artifact_id: receipt.artifact_id,
    merkle_leaf_sha256: receipt.merkle_leaf_sha256,
    finding_verified: false,
    independent_target_effect_verified: false,
    safe_to_automatically_retry: false,
  };
}
