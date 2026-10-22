/**
 * Administration-facing nonsecret credential-reference workflow.
 *
 * The mounted /flows/{flow}/provider-credential-profile-refs router operates
 * only on symbolic PostgreSQL profile references. It does not provision vault
 * material, verify providers or enable model routes. Reuse the existing
 * strictly bounded signed-ROE service; there is no separate credential API.
 *
 * No bearer is cached here. api.ts keeps it in tab memory, and its identity
 * is rechecked by providerCredentialProfiles before and after every request.
 */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';
import {
  providerCredentialProfiles, readCredentialScope, verifyCredentialScope,
  type ProviderCredentialProfile, type ProviderCredentialProposal, type ProviderCredentialScope,
} from './providerCredentialProfiles';
import { providerPolicyReviews, type ProviderPolicyReview } from './providerPolicyReviews';

export const PROVIDER_CREDENTIAL_ADMIN_NOTICE = 'NOT VAULT-MATERIAL VERIFIED / NO PROVIDER CALL';

export interface CredentialAdministrationInput {
  flowId: string;
  engagementId: string;
  flowRevision: number;
  authorizationId: string;
}

export interface CredentialAdministrationPage {
  scope: ProviderCredentialScope;
  items: ProviderCredentialProfile[];
  approvedPolicies: ProviderPolicyReview[];
  hasMore: boolean;
}

type CurrentActor = { sub: string; role: string; exp: number; bearer: string };

function actor(): CurrentActor {
  const principal = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!principal || !['operator', 'senior_operator'].includes(principal.role)
      || typeof principal.sub !== 'string' || !principal.sub.trim()
      || !Number.isSafeInteger(principal.exp) || principal.exp === null
      || principal.exp * 1000 <= Date.now()
      || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
      || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer)) {
    throw new Error('Current signed operator, secure origin and memory-only bearer required.');
  }
  return {sub: principal.sub, role: principal.role, exp: principal.exp, bearer};
}

function sameActor(original: CurrentActor): void {
  const current = actor();
  if (current.sub !== original.sub || current.role !== original.role
      || current.exp !== original.exp || current.bearer !== original.bearer) {
    throw new Error('Operator session changed: credential-reference outcome UNKNOWN. Refresh signed metadata.');
  }
}

function sameScope(actual: ProviderCredentialScope, original: ProviderCredentialScope): void {
  if (actual.flowId !== original.flowId || actual.engagementId !== original.engagementId
      || actual.flowRevision !== original.flowRevision
      || actual.authorizationId !== original.authorizationId
      || actual.authorizationVersion !== original.authorizationVersion
      || actual.authorizationSha256 !== original.authorizationSha256) {
    throw new Error('Signed Flow/authorization changed; no credential-reference mutation permitted.');
  }
}

function validateInput(input: CredentialAdministrationInput): void {
  if (!input || !/^flow-[A-Za-z0-9._:-]{1,59}$/.test(input.flowId)
      || !/^eng-[A-Za-z0-9._:-]{1,60}$/.test(input.engagementId)
      || !Number.isSafeInteger(input.flowRevision) || input.flowRevision < 0
      || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(input.authorizationId)) {
    throw new Error('Exact Flow, engagement, revision and signed authorization ID required.');
  }
}

async function refreshScope(scope: ProviderCredentialScope, signed: CurrentActor): Promise<void> {
  sameActor(signed);
  await verifyCredentialScope(scope);
  sameActor(signed);
  const actual = await readCredentialScope(
    scope.flowId, scope.engagementId, scope.flowRevision, scope.authorizationId,
  );
  sameScope(actual, scope);
  sameActor(signed);
}

export async function readCredentialAdministration(
  input: CredentialAdministrationInput,
): Promise<CredentialAdministrationPage> {
  validateInput(input);
  const signed = actor();
  const scope = await readCredentialScope(
    input.flowId, input.engagementId, input.flowRevision, input.authorizationId,
  );
  sameActor(signed);
  const listing = await providerCredentialProfiles.list(scope, 20, 0);
  sameActor(signed);
  // Policy reviews are signed intent metadata only. They are not proof that
  // a provider credential exists or that spending is enabled.
  const policies = signed.role === 'senior_operator' ? [] : await providerPolicyReviews.list(scope);
  await refreshScope(scope, signed);
  return {
    scope,
    items: listing.items,
    approvedPolicies: policies.filter(p => p.status === 'approved' && p.senior_reviewed),
    hasMore: listing.has_more,
  };
}

/** Check exact observed source revision before any mutation. */
export async function readCurrentCredentialReference(
  scope: ProviderCredentialScope, original: ProviderCredentialProfile,
): Promise<ProviderCredentialProfile> {
  const signed = actor();
  await refreshScope(scope, signed);
  const current = await providerCredentialProfiles.get(scope, original.ref_id);
  sameActor(signed);
  if (current.ref_id !== original.ref_id
      || current.reference_revision !== original.reference_revision
      || current.reference_sha256 !== original.reference_sha256
      || current.generation !== original.generation || current.status !== original.status
      || current.policy_review_id !== original.policy_review_id
      || current.policy_sha256 !== original.policy_sha256
      || current.provider !== original.provider || current.slot !== original.slot) {
    throw new Error('Credential reference changed; reload current metadata before requesting a change.');
  }
  return current;
}

async function completeReadback(
  scope: ProviderCredentialScope, updated: ProviderCredentialProfile, signed: CurrentActor,
): Promise<ProviderCredentialProfile> {
  sameActor(signed);
  await refreshScope(scope, signed);
  const current = await providerCredentialProfiles.get(scope, updated.ref_id);
  sameActor(signed);
  if (current.reference_revision !== updated.reference_revision
      || current.reference_sha256 !== updated.reference_sha256
      || current.generation !== updated.generation || current.status !== updated.status) {
    throw new Error('Credential reference readback inconsistent; outcome UNKNOWN, never repeat POST.');
  }
  return current;
}

export const providerCredentialAdministration = {
  read: readCredentialAdministration,
  /** Record pending symbolic alias metadata only; no vault-material creation. */
  register: async (
    scope: ProviderCredentialScope, policy: ProviderPolicyReview,
    slot: ProviderCredentialProposal['slot'], confirmed: true,
  ): Promise<ProviderCredentialProfile> => {
    if (confirmed !== true || policy.status !== 'approved' || !policy.senior_reviewed
        || policy.flow_id !== scope.flowId || policy.engagement_id !== scope.engagementId
        || policy.flow_revision !== scope.flowRevision
        || policy.authorization_sha256 !== scope.authorizationSha256
        || policy.authorization_version !== scope.authorizationVersion
        || policy.authorization_id !== scope.authorizationId) {
      throw new Error('Current independent signed provider policy review required.');
    }
    const signed = actor();
    if (signed.role !== 'operator') throw new Error('Operator creates pending references for separate senior review.');
    await refreshScope(scope, signed);
    const output = await providerCredentialProfiles.register(scope, {
      provider: policy.policy.provider, slot,
      policyReviewId: policy.review_id, policySha256: policy.policy_sha256,
      confirmed: true,
    });
    return completeReadback(scope, output, signed);
  },
  /** Rotate reference generation only; no secret or external provider rotation. */
  rotationIntent: async (
    scope: ProviderCredentialScope, original: ProviderCredentialProfile,
    expectedRevision: number, confirmed: true,
  ): Promise<ProviderCredentialProfile> => {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1
        || expectedRevision !== original.reference_revision || confirmed !== true) {
      throw new Error('Exact expected reference revision and human confirmation required.');
    }
    const signed = actor();
    if (signed.role !== 'operator') throw new Error('Separate operator and senior review roles required.');
    const current = await readCurrentCredentialReference(scope, original);
    sameActor(signed);
    if (current.status !== 'approved') throw new Error('Only a currently approved alias can be proposed for rotation.');
    const output = await providerCredentialProfiles.rotate(scope, current, {
      provider: current.provider, slot: current.slot,
      policyReviewId: current.policy_review_id, policySha256: current.policy_sha256,
      confirmed: true,
    });
    return completeReadback(scope, output, signed);
  },
  decide: async (
    scope: ProviderCredentialScope, original: ProviderCredentialProfile,
    expectedRevision: number, operation: 'approve' | 'revoke', reason: string, confirmed: true,
  ): Promise<ProviderCredentialProfile> => {
    if (confirmed !== true || expectedRevision !== original.reference_revision
        || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      throw new Error('Exact expected reference revision and human confirmation required.');
    }
    const signed = actor();
    if (signed.role !== 'senior_operator') throw new Error('Independent signed senior operator required.');
    const current = await readCurrentCredentialReference(scope, original);
    sameActor(signed);
    const output = await providerCredentialProfiles.decide(scope, current, operation, reason, true);
    return completeReadback(scope, output, signed);
  },
};
