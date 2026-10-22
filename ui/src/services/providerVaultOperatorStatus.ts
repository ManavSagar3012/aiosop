/**
 * Senior-only provider vault readback. This is an advisory PENDING snapshot:
 * it cannot enroll a signer, reserve usage, read keys, or authorize a send.
 *
 * The verified operator bearer lives only in services/api.ts session memory.
 * Never accept a URL, token, origin, or raw provider status from a caller.
 */
import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

const ENDPOINT = '/system/provider/vault-join-status';
const MAX_RESPONSE_BYTES = 2_048;
const FIELDS = [
  'code', 'next_action', 'host_enrollment_verified',
  'shared_call_fence_enrolled', 'provider_dispatch_authorized',
  'provider_contacted', 'credential_exported',
] as const;

export const PROVIDER_VAULT_PENDING_CODES = [
  'PENDING_HOST_ENROLLMENT',
  'PENDING_DURABLE_CALL_FENCE',
  'PENDING_CURRENT_HOST_AUTHORITY',
] as const;

export type ProviderVaultPendingCode = typeof PROVIDER_VAULT_PENDING_CODES[number];

/**
 * Only the exact, already-reviewed nonsecret backend messages can be shown.
 * Unknown strings (including secrets or links) are never rendered.
 */
const NEXT_ACTION: Record<ProviderVaultPendingCode, string> = {
  PENDING_HOST_ENROLLMENT:
    'Enroll an independently signed host guard and all eleven authority roots.',
  PENDING_DURABLE_CALL_FENCE:
    'Enroll a host-signed independent atomic one-use PostgreSQL call fence.',
  PENDING_CURRENT_HOST_AUTHORITY:
    'Renew the signed host enrollment and durable call-fence lease.',
};

export interface ProviderVaultOperatorStatus {
  code: ProviderVaultPendingCode;
  next_action: string;
  host_enrollment_verified: false;
  shared_call_fence_enrolled: false;
  provider_dispatch_authorized: false;
  provider_contacted: false;
  credential_exported: false;
}

/** Fail closed on any unsupported status or additional private metadata. */
export function validateProviderVaultOperatorStatus(value: unknown): ProviderVaultOperatorStatus {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Provider vault status is unavailable.');
  const obj = value as Record<string, unknown>;
  if (Object.keys(obj).length !== FIELDS.length
    || FIELDS.some(field => !Object.prototype.hasOwnProperty.call(obj, field)))
    throw new Error('Provider vault status has unapproved fields.');
  const code = obj.code;
  if (typeof code !== 'string'
    || !PROVIDER_VAULT_PENDING_CODES.includes(code as ProviderVaultPendingCode)
    || obj.next_action !== NEXT_ACTION[code as ProviderVaultPendingCode]
    || obj.host_enrollment_verified !== false
    || obj.shared_call_fence_enrolled !== false
    || obj.provider_dispatch_authorized !== false
    || obj.provider_contacted !== false
    || obj.credential_exported !== false)
    throw new Error('Provider vault trust remains unverified; PENDING-only readback required.');
  return {
    code: code as ProviderVaultPendingCode,
    next_action: NEXT_ACTION[code as ProviderVaultPendingCode],
    host_enrollment_verified: false,
    shared_call_fence_enrolled: false,
    provider_dispatch_authorized: false,
    provider_contacted: false,
    credential_exported: false,
  };
}

/**
 * Parse only a flat, bounded JSON object, rejecting duplicate properties
 * before JSON.parse can overwrite a conflicting false/true field.
 */
export function parseProviderVaultStatusJson(raw: string): unknown {
  if (typeof raw !== 'string' || !raw || new TextEncoder().encode(raw).length > MAX_RESPONSE_BYTES)
    throw new Error('Provider vault status exceeds the bounded metadata limit.');
  const keys = new Set<string>();
  // The exact schema contains only scalar fields. Scanning strings while
  // skipping escaped quotes distinguishes JSON keys from string values.
  for (let index = 0; index < raw.length;) {
    if (raw[index] !== '"') { index++; continue; }
    const start = index++;
    let closed = false;
    while (index < raw.length) {
      if (raw[index] === '\\') {
        index += 2;
        continue;
      }
      if (raw[index++] === '"') { closed = true; break; }
    }
    if (!closed) throw new Error('Malformed provider vault metadata.');
    let after = index;
    while (/\s/.test(raw[after] ?? '')) after++;
    if (raw[after] !== ':') continue;
    let name: unknown;
    try { name = JSON.parse(raw.slice(start, index)) as unknown; }
    catch { throw new Error('Malformed provider vault metadata.'); }
    if (typeof name !== 'string' || keys.has(name))
      throw new Error('Duplicate provider vault metadata field.');
    keys.add(name);
  }
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)
    || Object.values(parsed).some(value => value !== null && typeof value === 'object'))
    throw new Error('Provider vault response must be a flat metadata object.');
  return parsed;
}

interface SeniorSession {
  sub: string;
  exp: number;
  bearer: string;
}

function currentSeniorSession(): SeniorSession {
  const principal = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!principal || principal.role !== 'senior_operator'
    || typeof principal.sub !== 'string' || !principal.sub.trim()
    || typeof principal.exp !== 'number' || !Number.isSafeInteger(principal.exp)
    || principal.exp * 1000 <= Date.now()
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
    || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer)) {
    throw new Error('Current senior operator session on a secure origin is required.');
  }
  return { sub: principal.sub, exp: principal.exp, bearer };
}

function assertSameSenior(original: SeniorSession): void {
  const current = currentSeniorSession();
  if (current.sub !== original.sub || current.exp !== original.exp
    || current.bearer !== original.bearer)
    throw new Error('Senior operator identity changed during vault readback.');
}

/**
 * Exactly one authenticated GET, with no cookies, redirects, persisted token,
 * caller-supplied URL, provider action, fallback, or automatic retry.
 */
export async function readProviderVaultOperatorStatus(
  signal?: AbortSignal,
): Promise<ProviderVaultOperatorStatus> {
  const original = currentSeniorSession();
  if (signal?.aborted) throw new Error('Provider vault status read cancelled.');
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${ENDPOINT}`, {
      method: 'GET',
      headers: { Authorization: original.bearer, Accept: 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal,
    });
  } catch {
    throw new Error('Provider vault status read unavailable.');
  }
  assertSameSenior(original);
  if (signal?.aborted || !response.ok || response.status !== 200)
    throw new Error('Senior provider vault status unavailable.');
  const type = response.headers?.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (type !== 'application/json')
    throw new Error('Provider vault metadata must be JSON.');
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES))
    throw new Error('Provider vault status exceeds the bounded metadata limit.');
  let raw: string;
  try { raw = await response.text(); }
  catch { throw new Error('Provider vault response body unavailable.'); }
  assertSameSenior(original);
  if (signal?.aborted) throw new Error('Provider vault status read cancelled.');
  const result = validateProviderVaultOperatorStatus(parseProviderVaultStatusJson(raw));
  assertSameSenior(original);
  return result;
}
