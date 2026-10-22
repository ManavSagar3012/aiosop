/**
 * Senior-only operator readback of ORIGINAL Browser screenshot/DOM/HAR custody.
 *
 * The endpoint is a host READ ONLY reconciliation POST, never a Browser MCP
 * navigation, a target-effect receipt, or a retry of the original Action.
 * The only submitted data are the original engagement_id and request_id.
 *
 * A server 200 is insufficient. This consumer requires a separately supplied,
 * previously enrolled Ed25519 custody public-key pin; it checks the actual
 * custody signature, bounded original-file manifest, signed manifest digest,
 * requested identity, five-second freshness and explicit non-effect flags.
 * No trust roots are learned from the server, URL, provider or response.
 */

import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';

export const BROWSER_CUSTODY_ENDPOINT = '/system/browser/custody/readback';
const CUSTODY_DOMAIN = 'ai-osop/browser-host-readonly-original-custody/v1\0';
const MAX_RESPONSE_BYTES = 16_384;
const SHA = /^[a-f0-9]{64}$/;
const REQUEST = /^req-[a-f0-9]{48}$/;
const ENGAGEMENT = /^eng-[A-Za-z0-9._:@-]{1,75}$/;
const IDENT = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}$/;
const KID = /^[A-Za-z][A-Za-z0-9_-]{2,47}$/;
const BASE64_KEY = /^(?:[A-Za-z0-9+/]{4}){10}(?:[A-Za-z0-9+/]{3}=)$/;
const BASE64_URL_SIG = /^[A-Za-z0-9_-]{86}$/;
const EVIDENCE_KINDS = ['screenshot', 'dom', 'har'] as const;
const CUSTODY_CLAIMS = [
  'version', 'request_id', 'engagement_id', 'flow_id', 'task_id', 'subtask_id',
  'action_id', 'owner_id', 'preflight_id', 'authorization_sha256',
  'original_intent_sha256', 'evidence_attestation_sha256',
  'first_current_sha256', 'last_current_sha256', 'artifacts_sha256',
  'checked_at', 'expires_at', 'original_bytes_read', 'target_effect_verified',
  'automatic_retry_authorized', 'purpose',
] as const;
const VERIFIED_FIELDS = [
  'status', 'current_original_artifact_bytes_verified',
  'independent_target_effect_verified', 'automatic_retry_authorized',
  'production_release_certified', 'custody_proof', 'artifacts',
] as const;
const FAILURE_FIELDS = [
  'status', 'reason', 'current_original_artifact_bytes_verified',
  'independent_target_effect_verified', 'automatic_retry_authorized',
  'production_release_certified',
] as const;
const KNOWN_REASONS = [
  'INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED', 'ORIGINAL_HOST_RECORD_UNAVAILABLE',
  'ORIGINAL_HOST_RECORD_UNVERIFIED', 'ORIGINAL_HOST_IDENTITY_MISMATCH',
  'CURRENT_ORIGINAL_CUSTODY_UNVERIFIED', 'CURRENT_ORIGINAL_READBACK_UNAVAILABLE',
  'OPERATOR_QUERY_FORBIDDEN', 'INDEPENDENT_TRANSPORT_UNVERIFIED',
  'OPERATOR_BEARER_REQUIRED', 'INVALID_OPERATOR_REQUEST',
  'SIGNED_SENIOR_OPERATOR_REQUIRED',
] as const;

export type BrowserCustodyReason = typeof KNOWN_REASONS[number] |
  'OPERATOR_NOT_AUTHORIZED' | 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED';

export interface BrowserCustodyArtifact {
  sha256: string;
  size_bytes: number;
}

export interface BrowserCustodyVerified {
  status: 'CURRENT_ORIGINAL_CUSTODY_VERIFIED';
  engagement_id: string;
  request_id: string;
  checked_at: number;
  expires_at: number;
  custody_signer_kid: string;
  artifacts: Record<typeof EVIDENCE_KINDS[number], BrowserCustodyArtifact>;
  current_original_artifact_bytes_verified: true;
  independent_target_effect_verified: false;
  automatic_retry_authorized: false;
  production_release_certified: false;
}

export class BrowserCustodyUnverifiedError extends Error {
  readonly reason: BrowserCustodyReason;
  constructor(reason: BrowserCustodyReason = 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED') {
    super(`Browser original custody UNVERIFIED: ${reason}`);
    this.name = 'BrowserCustodyUnverifiedError';
    this.reason = reason;
  }
}

function deny(reason?: BrowserCustodyReason): never {
  throw new BrowserCustodyUnverifiedError(reason);
}

export function validBrowserEngagementId(id: unknown): id is string {
  return typeof id === 'string' && ENGAGEMENT.test(id);
}

export function validOriginalBrowserRequestId(id: unknown): id is string {
  return typeof id === 'string' && REQUEST.test(id);
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) deny();
  const record = value as Record<string, unknown>;
  const existing = Object.keys(record);
  if (existing.length !== keys.length || keys.some(key => !Object.prototype.hasOwnProperty.call(record, key)))
    deny();
  return record;
}

/** Reject duplicate JSON members before JSON.parse silently overwrites them. */
export function parseBoundedBrowserCustodyJson(raw: string): unknown {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_RESPONSE_BYTES)
    deny();
  const stack: Array<Set<string>> = [];
  for (let i = 0; i < raw.length;) {
    const ch = raw[i];
    if (ch === '"') {
      const start = i++;
      let finished = false;
      while (i < raw.length) {
        if (raw[i] === '\\') {
          if (i + 1 >= raw.length) deny();
          i += 2;
        } else if (raw[i++] === '"') { finished = true; break; }
      }
      if (!finished) deny();
      let next = i;
      while (/\s/.test(raw[next] ?? '')) next++;
      if (raw[next] === ':' && stack.length) {
        let name: unknown;
        try { name = JSON.parse(raw.slice(start, i)) as unknown; }
        catch { deny(); }
        if (typeof name !== 'string' || stack[stack.length - 1].has(name)) deny();
        stack[stack.length - 1].add(name);
      }
    } else if (ch === '{') { stack.push(new Set<string>()); i++; }
    else if (ch === '}') {
      if (!stack.length) deny();
      stack.pop(); i++;
    } else { i++; }
  }
  if (stack.length) deny();
  try { return JSON.parse(raw) as unknown; }
  catch { deny(); }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map(
      key => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`,
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function fromBase64(raw: string, urlSafe: boolean): Uint8Array {
  if (typeof raw !== 'string') deny();
  if (urlSafe ? !BASE64_URL_SIG.test(raw) : !BASE64_KEY.test(raw)) deny();
  const normalized = urlSafe ? raw.replace(/-/g, '+').replace(/_/g, '/') + '==' : raw;
  let bytes: Uint8Array;
  try {
    const decoded = atob(normalized);
    bytes = Uint8Array.from(decoded, char => char.charCodeAt(0));
  } catch { deny(); }
  if ((urlSafe && bytes.length !== 64) || (!urlSafe && bytes.length !== 32)) deny();
  // Refuse noncanonical Base64 / alternate signature encodings.
  const canonical = btoa(String.fromCharCode(...bytes));
  if (urlSafe
    ? canonical.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') !== raw
    : canonical !== raw) deny();
  return bytes;
}

function requireFreshClaims(claims: Record<string, unknown>, now: number): void {
  const ids = ['request_id', 'engagement_id', 'flow_id', 'task_id',
    'subtask_id', 'action_id', 'owner_id', 'preflight_id'];
  if (ids.some(key => typeof claims[key] !== 'string' || !IDENT.test(claims[key] as string))
    || !validBrowserEngagementId(claims.engagement_id)
    || !validOriginalBrowserRequestId(claims.request_id)
    || claims.version !== 1
    || claims.original_bytes_read !== true
    || claims.target_effect_verified !== false
    || claims.automatic_retry_authorized !== false
    || claims.purpose !== 'host_readonly_original_custody'
    || !Number.isSafeInteger(claims.checked_at)
    || !Number.isSafeInteger(claims.expires_at)
    || (claims.checked_at as number) > now
    || (claims.checked_at as number) < now - 2
    || (claims.expires_at as number) <= now
    || (claims.expires_at as number) > (claims.checked_at as number) + 5
    || ['authorization_sha256', 'original_intent_sha256',
      'evidence_attestation_sha256', 'first_current_sha256',
      'last_current_sha256', 'artifacts_sha256'].some(key =>
      typeof claims[key] !== 'string' || !SHA.test(claims[key] as string))) deny();
  if (!/^nbp-[a-f0-9]{32}$/.test(claims.preflight_id as string)) deny();
}

function validateManifest(value: unknown): Record<typeof EVIDENCE_KINDS[number], BrowserCustodyArtifact> {
  const manifest = exactRecord(value, EVIDENCE_KINDS);
  const output = {} as Record<typeof EVIDENCE_KINDS[number], BrowserCustodyArtifact>;
  for (const kind of EVIDENCE_KINDS) {
    const item = exactRecord(manifest[kind], ['path', 'sha256', 'size_bytes']);
    const ext = kind === 'screenshot' ? 'png' : kind === 'dom' ? 'html' : 'har';
    const max = kind === 'dom' ? 1024 * 1024 : 4 * 1024 * 1024;
    if (typeof item.path !== 'string'
      || !new RegExp(`^captures/[a-f0-9]{32}\\.${ext}$`).test(item.path)
      || typeof item.sha256 !== 'string' || !SHA.test(item.sha256)
      || !Number.isSafeInteger(item.size_bytes) || (item.size_bytes as number) <= 0
      || (item.size_bytes as number) > max) deny();
    // Only inert digest and size leave the validator; no paths/URLs are displayed.
    output[kind] = { sha256: item.sha256, size_bytes: item.size_bytes as number };
  }
  return output;
}

function getCrypto(): SubtleCrypto {
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) deny();
  return globalThis.crypto.subtle;
}

/** Copy into an ordinary ArrayBuffer for TypeScript 6 WebCrypto BufferSource. */
function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const result = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  result.set(bytes);
  return result.buffer;
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** The only accepted success requires a distinct, pinned host custody signer. */
export async function validateBrowserCustodyProof(
  response: unknown,
  engagementId: string,
  requestId: string,
  enrolledCustodyRoots: Readonly<Record<string, string>>,
): Promise<BrowserCustodyVerified> {
  if (!validBrowserEngagementId(engagementId) || !validOriginalBrowserRequestId(requestId))
    deny();
  const top = exactRecord(response, VERIFIED_FIELDS);
  if (top.status !== 'CURRENT_ORIGINAL_CUSTODY_VERIFIED'
    || top.current_original_artifact_bytes_verified !== true
    || top.independent_target_effect_verified !== false
    || top.automatic_retry_authorized !== false
    || top.production_release_certified !== false) deny();
  const envelope = exactRecord(top.custody_proof, ['claims', 'kid', 'signature']);
  const claims = exactRecord(envelope.claims, CUSTODY_CLAIMS);
  const now = Math.floor(Date.now() / 1000);
  requireFreshClaims(claims, now);
  if (claims.engagement_id !== engagementId || claims.request_id !== requestId) deny();
  const artifacts = validateManifest(top.artifacts);

  if (!enrolledCustodyRoots || typeof enrolledCustodyRoots !== 'object'
    || Array.isArray(enrolledCustodyRoots)
    || Object.keys(enrolledCustodyRoots).length < 1
    || Object.keys(enrolledCustodyRoots).length > 16
    || typeof envelope.kid !== 'string'
    || !KID.test(envelope.kid)
    || !Object.prototype.hasOwnProperty.call(enrolledCustodyRoots, envelope.kid)) deny();
  const enrolled = enrolledCustodyRoots[envelope.kid];
  const keyBytes = fromBase64(enrolled, false);
  const signature = fromBase64(envelope.signature as string, true);
  const crypto = getCrypto();
  const digest = hex(await crypto.digest('SHA-256', new TextEncoder().encode(canonicalJson(top.artifacts))));
  if (claims.artifacts_sha256 !== digest) deny();

  let valid = false;
  try {
    const key = await crypto.importKey('raw', ownedBuffer(keyBytes), 'Ed25519', false, ['verify']);
    valid = await crypto.verify(
      'Ed25519', key, ownedBuffer(signature),
      new TextEncoder().encode(CUSTODY_DOMAIN + canonicalJson(claims)),
    );
  } catch { deny(); }
  if (!valid) deny();
  requireFreshClaims(claims, Math.floor(Date.now() / 1000));
  return {
    status: 'CURRENT_ORIGINAL_CUSTODY_VERIFIED',
    engagement_id: engagementId,
    request_id: requestId,
    checked_at: claims.checked_at as number,
    expires_at: claims.expires_at as number,
    custody_signer_kid: envelope.kid,
    artifacts,
    current_original_artifact_bytes_verified: true,
    independent_target_effect_verified: false,
    automatic_retry_authorized: false,
    production_release_certified: false,
  };
}

interface SeniorSession {
  sub: string;
  exp: number;
  bearer: string;
}

function seniorSession(): SeniorSession {
  const operator = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!operator || operator.role !== 'senior_operator' || !operator.sub.trim()
    || !Number.isSafeInteger(operator.exp) || operator.exp === null
    || operator.exp * 1000 <= Date.now()
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()
    || typeof bearer !== 'string' || !/^Bearer \S{1,4096}$/.test(bearer)) {
    deny('OPERATOR_NOT_AUTHORIZED');
  }
  return { sub: operator.sub, exp: operator.exp, bearer };
}

function assertSameSenior(expected: SeniorSession): void {
  const actual = seniorSession();
  if (actual.sub !== expected.sub || actual.exp !== expected.exp
    || actual.bearer !== expected.bearer) deny('OPERATOR_NOT_AUTHORIZED');
}

function knownServerReason(input: unknown): BrowserCustodyReason {
  if (typeof input !== 'string' || !KNOWN_REASONS.includes(input as typeof KNOWN_REASONS[number]))
    return 'INDEPENDENT_CUSTODY_PROOF_UNVERIFIED';
  return input as typeof KNOWN_REASONS[number];
}

async function boundedBody(response: Response): Promise<unknown> {
  const mime = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (mime !== 'application/json') deny();
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) deny();
  if (!response.body) deny();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let lengthRead = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      lengthRead += part.value.byteLength;
      if (lengthRead > MAX_RESPONSE_BYTES) deny();
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  const merged = new Uint8Array(lengthRead);
  let position = 0;
  for (const chunk of chunks) { merged.set(chunk, position); position += chunk.byteLength; }
  let decoded: string;
  try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(merged); }
  catch { deny(); }
  return parseBoundedBrowserCustodyJson(decoded);
}

/**
 * One explicit host-only readback. HTTP errors and lost ACK remain UNVERIFIED;
 * there is no retry, alternate endpoint, proxy, storage, image or DOM request.
 */
export async function readBrowserCurrentCustodyReadback(
  engagementId: string,
  requestId: string,
  enrolledCustodyRoots: Readonly<Record<string, string>>,
  signal?: AbortSignal,
): Promise<BrowserCustodyVerified> {
  const original = seniorSession();
  if (!validBrowserEngagementId(engagementId) || !validOriginalBrowserRequestId(requestId)
    || !enrolledCustodyRoots || typeof enrolledCustodyRoots !== 'object'
    || Array.isArray(enrolledCustodyRoots) || !Object.keys(enrolledCustodyRoots).length)
    deny();
  if (signal?.aborted) deny();
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${BROWSER_CUSTODY_ENDPOINT}`, {
      method: 'POST',
      headers: {
        Authorization: original.bearer, Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ engagement_id: engagementId, request_id: requestId }),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal,
    });
  } catch { deny(); }
  assertSameSenior(original);
  if (signal?.aborted) deny();
  if (response.status === 503) {
    try {
      const payload = exactRecord(await boundedBody(response), ['detail']);
      assertSameSenior(original);
      const detail = exactRecord(payload.detail, FAILURE_FIELDS);
      if (detail.status === 'UNVERIFIED'
        && detail.current_original_artifact_bytes_verified === false
        && detail.independent_target_effect_verified === false
        && detail.automatic_retry_authorized === false
        && detail.production_release_certified === false) {
        deny(knownServerReason(detail.reason));
      }
    } catch (error) {
      if (error instanceof BrowserCustodyUnverifiedError) throw error;
    }
    deny();
  }
  if (response.status !== 200 || !response.ok) deny();
  let parsed: unknown;
  try { parsed = await boundedBody(response); }
  catch { deny(); }
  assertSameSenior(original);
  if (signal?.aborted) deny();
  const verified = await validateBrowserCustodyProof(
    parsed, engagementId, requestId, enrolledCustodyRoots,
  );
  assertSameSenior(original);
  if (signal?.aborted) deny();
  return verified;
}
