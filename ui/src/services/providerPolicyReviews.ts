/** Durable, senior-reviewed PROVIDER INTENT only; never credentials, remote test or dispatch. */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const FLOW = /^flow-[A-Za-z0-9._:-]{1,59}$/;
const ENG = /^eng-[A-Za-z0-9._:-]{1,60}$/;
const AUTH_ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SHA = /^[0-9a-f]{64}$/;
const REVIEW = /^provider-review-[0-9a-f]{32}$/;
const META = [
  'review_id', 'engagement_id', 'flow_id', 'policy_revision', 'policy_sha256', 'policy',
  'status', 'flow_revision', 'authorization_version', 'authorization_id',
  'authorization_sha256', 'senior_reviewed', 'purpose',
  'provider_served_model_verified', 'provider_capability_verified', 'callable_remotely',
  'execution_enabled', 'budget_reserved', 'credentials_stored', 'created_at', 'updated_at',
] as const;

export interface ProviderPolicyIntent {
  provider: 'openai' | 'anthropic' | 'gemini' | 'deepseek';
  model: string;
  operations: ('completion' | 'embedding')[];
  allowed_roles: string[];
  capabilities: ('text_completion' | 'tool_calls' | 'json_mode' | 'reasoning' | 'embeddings')[];
  max_output_tokens: number;
  budget_source: 'signed_postgres_roe';
}
export interface ProviderPolicyReview {
  review_id: string;
  engagement_id: string;
  flow_id: string;
  policy_revision: number;
  policy_sha256: string;
  policy: ProviderPolicyIntent;
  status: 'pending' | 'approved' | 'revoked';
  flow_revision: number;
  authorization_version: number;
  authorization_id: string;
  authorization_sha256: string;
  senior_reviewed: boolean;
  purpose: 'operator_declared_policy_only';
  provider_served_model_verified: false;
  provider_capability_verified: false;
  callable_remotely: false;
  execution_enabled: false;
  budget_reserved: false;
  credentials_stored: false;
  created_at: string;
  updated_at: string;
}
export interface ProviderReviewScope {
  flowId: string;
  engagementId: string;
  flowRevision: number;
  authorizationVersion: number;
  authorizationId: string;
  authorizationSha256: string;
}
const attempts = new Set<string>();

function exact(raw: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Malformed signed provider policy response.');
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).length !== fields.length || fields.some(k => !Object.prototype.hasOwnProperty.call(value, k)))
    throw new Error('Private or unsupported provider policy fields returned.');
  return value;
}
function identity(scope: ProviderReviewScope, write: boolean): { bearer: string; sub: string; role: string; exp: number | null } {
  const actor = currentOperator();
  if (!actor || !actor.sub || !['operator','senior_operator'].includes(actor.role)
    || !FLOW.test(scope.flowId) || !ENG.test(scope.engagementId)
    || !Number.isSafeInteger(scope.flowRevision) || scope.flowRevision < 0
    || !Number.isSafeInteger(scope.authorizationVersion) || scope.authorizationVersion < 1
    || !AUTH_ID.test(scope.authorizationId) || !SHA.test(scope.authorizationSha256)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin())
    throw new Error('Current signed provider-policy reviewer and Flow required.');
  const bearer = authHeaders().Authorization;
  if (!/^Bearer \S+$/.test(bearer ?? '') || (write && bearer.length > 4100))
    throw new Error('Verified operator bearer required.');
  return { bearer, sub: actor.sub, role: actor.role, exp: actor.exp };
}
function query(scope: ProviderReviewScope): string {
  return new URLSearchParams({
    expected_engagement_id: scope.engagementId,
    expected_revision: String(scope.flowRevision),
    expected_authorization_version: String(scope.authorizationVersion),
    expected_authorization_id: scope.authorizationId,
    expected_authorization_sha256: scope.authorizationSha256,
  }).toString();
}
function checkActor(initial: ReturnType<typeof identity>): void {
  const current = currentOperator();
  if (!current || current.sub !== initial.sub || current.role !== initial.role
    || current.exp !== initial.exp || authHeaders().Authorization !== initial.bearer)
    throw new Error('Operator changed; signed provider review outcome UNKNOWN.');
}
function validatePolicy(raw: unknown): ProviderPolicyIntent {
  const v = exact(raw, ['provider','model','operations','allowed_roles','capabilities','max_output_tokens','budget_source']);
  if (!['openai','anthropic','gemini','deepseek'].includes(String(v.provider))
    || typeof v.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,89}$/.test(v.model)
    || !Array.isArray(v.operations) || !(v.operations.length >= 1 && v.operations.length <= 2)
    || !v.operations.every(op => ['completion','embedding'].includes(String(op)))
    || !Array.isArray(v.allowed_roles) || !v.allowed_roles.length || v.allowed_roles.length > 24
    || !v.allowed_roles.every(role => typeof role === 'string' && /^[a-z_]{2,32}$/.test(role))
    || !Array.isArray(v.capabilities) || !v.capabilities.length || v.capabilities.length > 5
    || !v.capabilities.every(cap => ['text_completion','tool_calls','json_mode','reasoning','embeddings'].includes(String(cap)))
    || !Number.isSafeInteger(v.max_output_tokens) || (v.max_output_tokens as number) < 1
    || (v.max_output_tokens as number) > 16384 || v.budget_source !== 'signed_postgres_roe'
    || new Set(v.operations).size !== v.operations.length
    || new Set(v.allowed_roles).size !== v.allowed_roles.length
    || new Set(v.capabilities).size !== v.capabilities.length)
    throw new Error('Invalid bounded provider route policy.');
  return v as unknown as ProviderPolicyIntent;
}
function review(raw: unknown, scope: ProviderReviewScope): ProviderPolicyReview {
  const v = exact(raw, META);
  const policy = validatePolicy(v.policy);
  if (typeof v.review_id !== 'string' || !REVIEW.test(v.review_id)
    || v.engagement_id !== scope.engagementId || v.flow_id !== scope.flowId
    || !Number.isSafeInteger(v.policy_revision) || (v.policy_revision as number) < 1
    || typeof v.policy_sha256 !== 'string' || !SHA.test(v.policy_sha256)
    || !['pending','approved','revoked'].includes(String(v.status))
    || v.flow_revision !== scope.flowRevision || v.authorization_version !== scope.authorizationVersion
    || v.authorization_id !== scope.authorizationId || v.authorization_sha256 !== scope.authorizationSha256
    || typeof v.senior_reviewed !== 'boolean'
    || v.purpose !== 'operator_declared_policy_only' || v.provider_served_model_verified !== false
    || v.provider_capability_verified !== false || v.callable_remotely !== false
    || v.execution_enabled !== false || v.budget_reserved !== false || v.credentials_stored !== false
    || typeof v.created_at !== 'string' || v.created_at.length > 48
    || typeof v.updated_at !== 'string' || v.updated_at.length > 48)
    throw new Error('Untrusted or falsely enabled provider policy review.');
  return { ...v, policy } as unknown as ProviderPolicyReview;
}
async function request(scope: ProviderReviewScope, suffix: string, method: 'GET'|'POST'|'PUT',
  body?: Record<string, unknown>): Promise<unknown> {
  const actor = identity(scope, method !== 'GET');
  const headers = authHeaders({ Accept: 'application/json', ...(body ? {'Content-Type':'application/json'} : {}) });
  const response = await fetch(`${API_BASE}/flows/${encodeURIComponent(scope.flowId)}/provider-route-policy-reviews${suffix}?${query(scope)}`, {
    method, headers, ...(body ? {body: JSON.stringify(body)} : {}),
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error(`Signed provider review unavailable or outcome UNKNOWN (HTTP ${response.status}); read back, never auto retry.`);
  const raw: unknown = await response.json();
  checkActor(actor);
  return raw;
}
export const providerPolicyReviews = {
  list: async (scope: ProviderReviewScope): Promise<ProviderPolicyReview[]> => {
    const v = exact(await request(scope, '', 'GET'), ['items','has_more']);
    if (!Array.isArray(v.items) || v.items.length > 20 || typeof v.has_more !== 'boolean')
      throw new Error('Unbounded provider policy list.');
    return v.items.map(row => review(row, scope));
  },
  create: async (scope: ProviderReviewScope, intent: ProviderPolicyIntent): Promise<ProviderPolicyReview> => {
    const policy = validatePolicy(intent);
    const key = JSON.stringify(['create',scope,intent]);
    if (attempts.has(key)) throw new Error('Provider policy submission previously attempted; manually refresh, never retry.');
    attempts.add(key);
    return review(await request(scope, '', 'POST', policy as unknown as Record<string, unknown>), scope);
  },
  update: async (scope: ProviderReviewScope, item: ProviderPolicyReview,
    intent: ProviderPolicyIntent): Promise<ProviderPolicyReview> => {
    const policy = validatePolicy(intent);
    if (!REVIEW.test(item.review_id) || item.flow_id !== scope.flowId
      || item.engagement_id !== scope.engagementId || item.flow_revision !== scope.flowRevision
      || item.authorization_version !== scope.authorizationVersion || item.status !== 'pending'
      || !Number.isSafeInteger(item.policy_revision) || item.policy_revision < 1)
      throw new Error('Only a current pending signed policy revision can be edited.');
    const key = JSON.stringify(['update',scope,item.review_id,item.policy_revision,policy]);
    if (attempts.has(key)) throw new Error('Provider policy edit already attempted; manually refresh, never retry.');
    attempts.add(key);
    const result = review(await request(scope, `/${encodeURIComponent(item.review_id)}`, 'PUT', {
      ...policy, expected_policy_revision: item.policy_revision,
    }),scope);
    if (result.review_id !== item.review_id || result.status !== 'pending'
      || result.policy_revision !== item.policy_revision + 1
      || result.policy_sha256 === item.policy_sha256)
      throw new Error('Provider policy CAS update outcome UNKNOWN; manually read back.');
    return result;
  },
  decide: async (scope: ProviderReviewScope, item: ProviderPolicyReview,
    decision: 'approve'|'revoke', reason: string): Promise<ProviderPolicyReview> => {
    const actor = currentOperator();
    if (actor?.role !== 'senior_operator' || !REVIEW.test(item.review_id)
      || !['approve','revoke'].includes(decision)
      || !Number.isSafeInteger(item.policy_revision) || item.policy_revision < 1
      || !/^[A-Za-z0-9][A-Za-z0-9 .,:;()_-]{9,255}$/.test(reason.trim()))
      throw new Error('Separate signed senior human review, scoped delegation and reason required.');
    const key = JSON.stringify(['decision',scope,item.review_id,item.policy_revision,decision]);
    if (attempts.has(key)) throw new Error('Senior policy decision already attempted; manually read back.');
    attempts.add(key);
    const result = review(await request(scope,
      `/${encodeURIComponent(item.review_id)}/decision`, 'POST', {
        expected_policy_revision: item.policy_revision, decision, reason: reason.trim(),
      }),scope);
    if (result.review_id !== item.review_id || result.policy_revision !== item.policy_revision + 1
      || result.status !== (decision === 'approve' ? 'approved' : 'revoked'))
      throw new Error('Senior decision outcome UNKNOWN; manually read back.');
    return result;
  },
};
