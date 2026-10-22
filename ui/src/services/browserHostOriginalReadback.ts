/** Host-attested four ORIGINAL Browser digests, never target-effect proof. */
import {
  API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin,
} from './api';
import {
  validBrowserEngagementId, validOriginalBrowserRequestId,
} from './browserCurrentCustodyReadback';

const ENDPOINT = '/system/browser/original-host/readback';
const MAX_BYTES = 8192;
const SHA = /^[a-f0-9]{64}$/;
const KINDS = ['http_raw', 'screenshot', 'dom', 'har'] as const;
const FIELDS = [
  'status', 'engagement_id', 'request_id', 'host_enrollment_sha256',
  'custody_claims_sha256', 'artifacts', 'current_original_artifact_bytes_verified',
  'raw_http_original_bytes_verified', 'independent_target_effect_verified',
  'automatic_retry_authorized', 'production_release_certified',
] as const;

type OriginalKind = typeof KINDS[number];
type ArtifactDigest = { sha256: string; size_bytes: number };
export type BrowserHostOriginalDigestReadback = {
  status: 'CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK';
  engagement_id: string;
  request_id: string;
  host_enrollment_sha256: string;
  custody_claims_sha256: string;
  artifacts: Record<OriginalKind, ArtifactDigest>;
  current_original_artifact_bytes_verified: true;
  raw_http_original_bytes_verified: true;
  independent_target_effect_verified: false;
  automatic_retry_authorized: false;
  production_release_certified: false;
};

export class BrowserHostOriginalUnverified extends Error {
  constructor() {
    super('UNVERIFIED: independently enrolled Browser original host authority unavailable.');
    this.name = 'BrowserHostOriginalUnverified';
  }
}

function deny(): never {
  throw new BrowserHostOriginalUnverified();
}

function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) deny();
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some(key => !keys.includes(key))) deny();
  return value as Record<string, unknown>;
}

async function originalBody(response: Response): Promise<unknown> {
  const kind = response.headers.get('content-type')?.trim() ?? '';
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(kind)) deny();
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length))
    || Number(length) > MAX_BYTES)) deny();
  if (!response.body) deny();
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let content = '';
  let total = 0;
  let finished = false;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) { finished = true; break; }
      total += part.value.byteLength;
      if (total > MAX_BYTES) deny();
      content += decoder.decode(part.value, { stream: true });
    }
    content += decoder.decode();
  } catch { deny(); }
  finally {
    if (!finished) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  try { return JSON.parse(content); } catch { deny(); }
}

/**
 * The backend checks independently enrolled host ORIGINAL bytes and CURRENT
 * signers, but the browser gets only the host's verified-shape digest receipt,
 * NOT the independently signed original claims. This is operator readback,
 * not independently authenticated client/target evidence.
 */
export async function readBrowserHostOriginalDigests(
  engagementId: string, requestId: string, signal?: AbortSignal,
): Promise<BrowserHostOriginalDigestReadback> {
  if (!validBrowserEngagementId(engagementId) || !validOriginalBrowserRequestId(requestId)
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin() || signal?.aborted) deny();
  const actor = currentOperator();
  const bearer = authHeaders().Authorization;
  if (!actor || actor.role !== 'senior_operator' || !/^Bearer [^\s,]+$/.test(bearer || '')) deny();
  const unchanged = () => {
    const latest = currentOperator();
    return latest?.sub === actor.sub && latest.role === 'senior_operator'
      && latest.exp === actor.exp && authHeaders().Authorization === bearer && !signal?.aborted;
  };
  let reply: Response;
  try {
    reply = await fetch(`${API_BASE}${ENDPOINT}`, {
      method: 'POST',
      headers: {
        Authorization: bearer, 'Content-Type': 'application/json', Accept: 'application/json',
      },
      body: JSON.stringify({ engagement_id: engagementId, request_id: requestId }),
      credentials: 'omit', cache: 'no-store', redirect: 'error',
      referrerPolicy: 'no-referrer', signal,
    });
  } catch { deny(); }
  if (!unchanged()) deny();
  if (reply.status !== 200 || !reply.ok) deny();
  let parsed: unknown;
  try { parsed = await originalBody(reply); } catch { deny(); }
  if (!unchanged()) deny();
  const value = record(parsed, FIELDS);
  if (value.status !== 'CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK'
    || value.engagement_id !== engagementId || value.request_id !== requestId
    || typeof value.host_enrollment_sha256 !== 'string'
    || !SHA.test(value.host_enrollment_sha256)
    || typeof value.custody_claims_sha256 !== 'string'
    || !SHA.test(value.custody_claims_sha256)
    || value.current_original_artifact_bytes_verified !== true
    || value.raw_http_original_bytes_verified !== true
    || value.independent_target_effect_verified !== false
    || value.automatic_retry_authorized !== false
    || value.production_release_certified !== false) deny();
  const artifacts = record(value.artifacts, KINDS);
  for (const kind of KINDS) {
    const item = record(artifacts[kind], ['sha256', 'size_bytes']);
    if (typeof item.sha256 !== 'string' || !SHA.test(item.sha256)
      || !Number.isSafeInteger(item.size_bytes)
      || (item.size_bytes as number) < 1 || (item.size_bytes as number) > 32 * 1024 * 1024) deny();
  }
  if (!unchanged()) deny();
  return value as BrowserHostOriginalDigestReadback;
}
