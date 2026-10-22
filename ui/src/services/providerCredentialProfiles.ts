/**
 * Provider credential alias PROFILE operator controls.
 *
 * This UI sends no credential, API key, secret, password, bearer in a URL,
 * environment variable, or provider request. All mutations are metadata-only,
 * signed-Flow-fenced, one-shot actions requiring backend independent review.
 * A profile is never proof that a model route or provider is activated.
 */
import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';
import { supervisionApi } from './supervision';

const FLOW = /^flow-[A-Za-z0-9._:-]{1,59}$/;
const ENG = /^eng-[A-Za-z0-9._:-]{1,60}$/;
const AUTH = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SHA = /^[0-9a-f]{64}$/;
const REFERENCE = /^pcref-[0-9a-f]{32}$/;
const POLICY_REVIEW = /^provider-review-[0-9a-f]{32}$/;
const PROVIDERS = ['openai', 'anthropic', 'gemini', 'deepseek'] as const;
const SLOTS = ['primary', 'backup'] as const;
const SECRET = /(?:sk[-_](?:live|test)|gh[pousr]_|bearer|password|secret|credential[_-]?(?:key|value)|api[_-]?key|private[_-]?key|token|-----BEGIN|\b(?:credential|authorization|http|env|path|vault|key)\b)/i;
const MAX_BYTES = 32768;
const seenMutations = new Set<string>();
const referenceFields = [
  'ref_id', 'engagement_id', 'flow_id', 'provider', 'slot', 'policy_review_id',
  'policy_sha256', 'reference_sha256', 'reference_revision', 'generation',
  'status', 'flow_revision', 'authorization_version', 'authorization_id',
  'authorization_sha256', 'senior_reviewed', 'created_at', 'updated_at',
  'credentials_stored', 'credential_available_verified', 'credential_rotated',
  'execution_enabled', 'provider_contacted', 'route_activated', 'server_reference_only',
  'policy_current_approval_verified', 'status_is_historical_review_only',
] as const;

export interface ProviderCredentialProfile {
  ref_id: string;
  engagement_id: string;
  flow_id: string;
  provider: typeof PROVIDERS[number];
  slot: typeof SLOTS[number];
  policy_review_id: string;
  policy_sha256: string;
  reference_sha256: string;
  reference_revision: number;
  generation: number;
  status: 'pending' | 'approved' | 'revoked';
  flow_revision: number;
  authorization_version: number;
  authorization_id: string;
  authorization_sha256: string;
  senior_reviewed: boolean;
  created_at: string;
  updated_at: string;
  credentials_stored: false;
  credential_available_verified: false;
  credential_rotated: false;
  execution_enabled: false;
  provider_contacted: false;
  route_activated: false;
  server_reference_only: true;
  policy_current_approval_verified: false;
  status_is_historical_review_only: true;
}

export interface ProviderCredentialProposal {
  provider: ProviderCredentialProfile['provider'];
  slot: ProviderCredentialProfile['slot'];
  policyReviewId: string;
  policySha256: string;
  confirmed: true;
}

export interface ProviderCredentialScope {
  flowId: string;
  engagementId: string;
  flowRevision: number;
  authorizationVersion: number;
  authorizationId: string;
  authorizationSha256: string;
}

type Actor = { sub: string; role: 'operator' | 'senior_operator'; exp: number; bearer: string };

function signedActor(scope: ProviderCredentialScope): Actor {
  const principal = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!principal || !['operator', 'senior_operator'].includes(principal.role)
    || !AUTH.test(principal.sub) || !Number.isSafeInteger(principal.exp)
    || (principal.exp ?? 0) * 1000 <= Date.now()
    || !FLOW.test(scope.flowId) || !ENG.test(scope.engagementId)
    || !Number.isSafeInteger(scope.flowRevision) || scope.flowRevision < 0
    || !Number.isSafeInteger(scope.authorizationVersion) || scope.authorizationVersion < 1
    || !AUTH.test(scope.authorizationId) || !SHA.test(scope.authorizationSha256)
    || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Current signed Flow, verified operator and ROE are required.');
  }
  return {
    sub: principal.sub, role: principal.role as Actor['role'],
    exp: principal.exp!, bearer,
  };
}

function sameActor(actor: Actor): void {
  const value = currentOperator();
  if (!value || value.sub !== actor.sub || value.role !== actor.role
    || value.exp !== actor.exp || value.exp === null
    || value.exp * 1000 <= Date.now()
    || authHeaders().Authorization !== actor.bearer) {
    throw new Error('Signed operator identity changed; credential profile outcome UNKNOWN.');
  }
}

export async function verifyCredentialScope(scope: ProviderCredentialScope, original?: Actor): Promise<void> {
  const actor = original ?? signedActor(scope);
  sameActor(actor);
  const signed = await supervisionApi.authorizationStatus(scope.engagementId);
  sameActor(actor);
  if (signed.status !== 'active' || signed.version !== scope.authorizationVersion
    || signed.policy_sha256 !== scope.authorizationSha256
    || !SHA.test(signed.policy_sha256 ?? '')) {
    throw new Error('Signed ROE revoked or changed; credential profile state UNKNOWN.');
  }
}

export async function readCredentialScope(
  flowId: string, engagementId: string, flowRevision: number, authorizationId: string,
): Promise<ProviderCredentialScope> {
  const scope: ProviderCredentialScope = {
    flowId, engagementId, flowRevision, authorizationId,
    authorizationVersion: 1, authorizationSha256: '0'.repeat(64),
  };
  const actor = signedActor(scope);
  const signed = await supervisionApi.authorizationStatus(engagementId);
  sameActor(actor);
  if (signed.status !== 'active'
    || !Number.isSafeInteger(signed.version) || (signed.version ?? 0) < 1
    || !SHA.test(signed.policy_sha256 ?? '')) {
    throw new Error('Current signed provider credential authorization unavailable.');
  }
  return {
    ...scope, authorizationVersion: signed.version!, authorizationSha256: signed.policy_sha256!,
  };
}

/** Strictly reject duplicate JSON keys, including Unicode-escaped aliases. */
function uniqueJson(text: string): unknown {
  const keys: Array<Set<string>> = [];
  for (let i = 0; i < text.length;) {
    if (text[i] === '{') { keys.push(new Set()); i++; continue; }
    if (text[i] === '}') {
      if (!keys.pop()) throw new Error('Ambiguous profile response object.');
      i++; continue;
    }
    if (text[i] !== '"') { i++; continue; }
    const start = i++;
    let closed = false;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') { closed = true; break; }
    }
    if (!closed) throw new Error('Malformed profile response string.');
    let j = i;
    while (j < text.length && /\s/.test(text[j])) j++;
    if (text[j] === ':' && keys.length) {
      const name = JSON.parse(text.slice(start, i)) as string;
      const object = keys[keys.length - 1];
      if (object.has(name)) throw new Error('Duplicate sensitive profile metadata field.');
      object.add(name);
    }
  }
  if (keys.length) throw new Error('Incomplete profile response metadata.');
  return JSON.parse(text) as unknown;
}

async function safeJson(response: Response): Promise<unknown> {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers?.get('content-type') ?? '')) {
    throw new Error('Profile response was not bounded JSON.');
  }
  const length = response.headers?.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES)) {
    throw new Error('Credential profile metadata exceeds response size bound.');
  }
  const content = await response.text();
  if (new TextEncoder().encode(content).byteLength > MAX_BYTES) {
    throw new Error('Credential profile response exceeds size bound.');
  }
  return uniqueJson(content);
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Untrusted credential profile metadata.');
  }
  const data = value as Record<string, unknown>;
  if (Object.keys(data).length !== fields.length
    || !fields.every(field => Object.prototype.hasOwnProperty.call(data, field))) {
    throw new Error('Unexpected private or forged profile response fields.');
  }
  return data;
}

function exactlyOneShot(actor: Actor, scope: ProviderCredentialScope, operation: string, payload: unknown): void {
  const semantic = payload && typeof payload === 'object' && !Array.isArray(payload)
    ? Object.fromEntries(Object.entries(payload).filter(([name]) => name !== 'operation_id'))
    : payload;
  const key = JSON.stringify([actor.sub, scope, operation, semantic]);
  if (seenMutations.has(key)) {
    throw new Error('Credential profile change previously attempted; refresh the signed ledger, never retry.');
  }
  seenMutations.add(key);
}

function query(scope: ProviderCredentialScope): string {
  return new URLSearchParams({
    expected_engagement_id: scope.engagementId,
    expected_revision: String(scope.flowRevision),
    expected_authorization_version: String(scope.authorizationVersion),
    expected_authorization_id: scope.authorizationId,
    expected_authorization_sha256: scope.authorizationSha256,
  }).toString();
}

async function fetchProfileMetadata(
  scope: ProviderCredentialScope,
  suffix: string,
  method: 'GET' | 'POST',
  body?: Record<string, unknown>,
  pagination?: { limit: number; offset: number },
  expectedStatus?: 200 | 201,
): Promise<unknown> {
  const actor = signedActor(scope);
  await verifyCredentialScope(scope, actor);
  if (method === 'POST') exactlyOneShot(actor, scope, suffix, body);
  sameActor(actor);
  const url = `${API_BASE}/flows/${encodeURIComponent(scope.flowId)}/provider-credential-profile-refs${suffix}?${query(scope)}`
    + (pagination ? `&limit=${pagination.limit}&offset=${pagination.offset}` : '');
  const response = await fetch(
    url,
    {
      method,
      headers: {
        Authorization: actor.bearer, Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    },
  );
  sameActor(actor);
  if (response.status !== (expectedStatus ?? 200)) {
    throw new Error('Credential profile request denied or outcome UNKNOWN; never automatically retry.');
  }
  const result = await safeJson(response);
  sameActor(actor);
  await verifyCredentialScope(scope, actor);
  return result;
}

function reference(
  raw: unknown, scope: ProviderCredentialScope, mutation = false,
): ProviderCredentialProfile {
  const fields = mutation
    ? [...referenceFields, 'operation_recorded', 'idempotent_replay']
    : referenceFields;
  const value = exactRecord(raw, fields);
  if (!REFERENCE.test(String(value.ref_id))
    || value.flow_id !== scope.flowId || value.engagement_id !== scope.engagementId
    || !PROVIDERS.includes(value.provider as ProviderCredentialProfile['provider'])
    || !SLOTS.includes(value.slot as ProviderCredentialProfile['slot'])
    || typeof value.policy_review_id !== 'string' || !POLICY_REVIEW.test(value.policy_review_id)
    || typeof value.policy_sha256 !== 'string' || !SHA.test(value.policy_sha256)
    || typeof value.reference_sha256 !== 'string' || !SHA.test(value.reference_sha256)
    || !Number.isSafeInteger(value.reference_revision) || Number(value.reference_revision) < 1
    || !Number.isSafeInteger(value.generation) || Number(value.generation) < 1
    || !['pending', 'approved', 'revoked'].includes(String(value.status))
    || value.flow_revision !== scope.flowRevision
    || value.authorization_version !== scope.authorizationVersion
    || value.authorization_id !== scope.authorizationId
    || value.authorization_sha256 !== scope.authorizationSha256
    || typeof value.senior_reviewed !== 'boolean'
    || (value.status === 'approved' && value.senior_reviewed !== true)
    || typeof value.created_at !== 'string'
    || !/^20\d\d-[01]\d-[0-3]\dT[\d:.+Z-]{8,40}$/.test(value.created_at)
    || typeof value.updated_at !== 'string'
    || !/^20\d\d-[01]\d-[0-3]\dT[\d:.+Z-]{8,40}$/.test(value.updated_at)
    || value.credentials_stored !== false
    || value.credential_available_verified !== false
    || value.credential_rotated !== false
    || value.execution_enabled !== false
    || value.provider_contacted !== false
    || value.route_activated !== false || value.server_reference_only !== true
    || value.policy_current_approval_verified !== false
    || value.status_is_historical_review_only !== true
    || (mutation && (value.operation_recorded !== true || value.idempotent_replay !== false))) {
    throw new Error('Forged, secret-bearing or falsely activated provider credential reference.');
  }
  return value as unknown as ProviderCredentialProfile;
}

function validProposal(input: ProviderCredentialProposal): void {
  if (!input || input.confirmed !== true
    || !PROVIDERS.includes(input.provider) || !SLOTS.includes(input.slot)
    || !POLICY_REVIEW.test(input.policyReviewId)
    || !SHA.test(input.policySha256)) {
    throw new Error('Exact approved 0025 policy reference and explicit human confirmation required.');
  }
}

function checkExisting(item: ProviderCredentialProfile, scope: ProviderCredentialScope): void {
  // Do not trust a previously cached record: re-read before every mutation.
  reference(item, scope);
}

function safeReason(reason: string): string {
  const text = reason?.trim();
  if (typeof text !== 'string' || text.length < 10 || text.length > 160
    || !/^[A-Za-z0-9][A-Za-z0-9 .,:;()_-]*$/.test(text)
    || SECRET.test(text)) {
    throw new Error('Bounded non-secret independent review reason (10–160 characters) required.');
  }
  return text;
}

function freshOperationId(): string {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new Error('Secure random operation ID unavailable; no profile request sent.');
  }
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return `pcop-${Array.from(nonce, byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

async function list(
  scope: ProviderCredentialScope, limit: number, offset: number,
): Promise<{items:ProviderCredentialProfile[];has_more:boolean}> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 20
    || !Number.isSafeInteger(offset) || offset < 0 || offset > 10000) {
    throw new Error('Bounded credential reference pagination required.');
  }
  const result = exactRecord(await fetchProfileMetadata(
    scope, '', 'GET', undefined, {limit, offset},
  ), ['items', 'has_more']);
  if (!Array.isArray(result.items) || result.items.length > limit
    || typeof result.has_more !== 'boolean') {
    throw new Error('Untrusted credential profile listing.');
  }
  const items = result.items.map(row => reference(row, scope));
  if (new Set(items.map(item => item.ref_id)).size !== items.length) {
    throw new Error('Duplicate identity in signed profile reference catalog.');
  }
  return {items, has_more:result.has_more};
}

async function read(scope: ProviderCredentialScope, refId: string): Promise<ProviderCredentialProfile> {
  if (!REFERENCE.test(refId)) throw new Error('Exact durable reference ID required.');
  const result = reference(await fetchProfileMetadata(scope, `/${encodeURIComponent(refId)}`, 'GET'), scope);
  if (result.ref_id !== refId) throw new Error('Foreign credential reference readback.');
  return result;
}

async function writeAndRead(
  scope: ProviderCredentialScope, body: Record<string, unknown>,
  verify: (item: ProviderCredentialProfile) => boolean,
): Promise<ProviderCredentialProfile> {
  const actor = signedActor(scope);
  const response = reference(await fetchProfileMetadata(
    scope, '', 'POST', body, undefined, body.operation === 'register' ? 201 : 200,
  ), scope, true);
  sameActor(actor);
  if (!verify(response)) {
    throw new Error('Credential profile mutation outcome UNKNOWN; refresh only, never replay.');
  }
  const current = await read(scope, response.ref_id);
  sameActor(actor);
  if (!verify(current) || current.reference_revision !== response.reference_revision
    || current.generation !== response.generation
    || current.reference_sha256 !== response.reference_sha256
    || current.policy_sha256 !== response.policy_sha256
    || current.status !== response.status) {
    throw new Error('Credential profile durable outcome UNKNOWN; read back, never replay.');
  }
  await verifyCredentialScope(scope, actor);
  return current;
}

export const providerCredentialProfiles = {
  list: async (scope: ProviderCredentialScope, limit=20, offset=0) => list(scope, limit, offset),
  get: read,
  register: async (
    scope: ProviderCredentialScope, data: ProviderCredentialProposal,
  ): Promise<ProviderCredentialProfile> => {
    validProposal(data);
    const payload = {
      operation: 'register', operation_id: freshOperationId(),
      provider: data.provider, slot: data.slot,
      policy_review_id: data.policyReviewId, policy_sha256: data.policySha256,
    };
    return writeAndRead(scope, payload, item =>
      item.status === 'pending' && item.senior_reviewed === false
      && item.provider === data.provider && item.slot === data.slot
      && item.policy_review_id === data.policyReviewId
      && item.policy_sha256 === data.policySha256
      && item.reference_revision === 1 && item.generation === 1);
  },
  rotate: async (
    scope: ProviderCredentialScope, existing: ProviderCredentialProfile,
    data: ProviderCredentialProposal,
  ): Promise<ProviderCredentialProfile> => {
    checkExisting(existing, scope);
    validProposal(data);
    if (existing.status !== 'approved' || existing.policy_review_id !== data.policyReviewId
      || existing.policy_sha256 !== data.policySha256
      || existing.provider !== data.provider || existing.slot !== data.slot) {
      throw new Error('Rotation requires exact approved reference and unchanged managed slot and policy.');
    }
    const payload = {
      operation: 'rotate', operation_id: freshOperationId(),
      ref_id: existing.ref_id, expected_ref_revision: existing.reference_revision,
      provider:data.provider, slot:data.slot,
      policy_review_id:data.policyReviewId, policy_sha256:data.policySha256,
    };
    const item = await writeAndRead(scope, payload, result =>
      result.ref_id === existing.ref_id && result.status === 'pending'
      && result.senior_reviewed === false && result.generation === existing.generation + 1
      && result.reference_revision === existing.reference_revision + 1
      && result.provider === existing.provider && result.slot === data.slot
      && result.policy_review_id === existing.policy_review_id
      && result.policy_sha256 === existing.policy_sha256);
    return item;
  },
  decide: async (
    scope: ProviderCredentialScope, existing: ProviderCredentialProfile,
    operation: 'approve' | 'revoke', reason: string, confirmed: true,
  ): Promise<ProviderCredentialProfile> => {
    const actor = signedActor(scope);
    checkExisting(existing, scope);
    if (actor.role !== 'senior_operator' || confirmed !== true
      || (operation !== 'approve' && operation !== 'revoke')
      || (operation === 'approve' && existing.status !== 'pending')
      || existing.status === 'revoked') {
      throw new Error('Distinct delegated senior reviewer, current candidate and explicit confirmation required.');
    }
    const payload = {
      operation, operation_id: freshOperationId(), ref_id: existing.ref_id,
      expected_ref_revision: existing.reference_revision, reason: safeReason(reason),
    };
    return writeAndRead(scope, payload, result =>
      result.ref_id === existing.ref_id && result.status === (operation === 'approve' ? 'approved' : 'revoked')
      && result.senior_reviewed === true
      && result.reference_revision === existing.reference_revision + 1
      && result.generation === existing.generation
      && result.policy_review_id === existing.policy_review_id
      && result.policy_sha256 === existing.policy_sha256
      && result.provider === existing.provider && result.slot === existing.slot);
  },
};

