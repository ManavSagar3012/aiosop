/** Senior-only exact-byte Flow-artifact human review.
 *
 * This is a decision/lineage receipt, NOT verification of a security finding,
 * model-safe content, a successful tool call, or implicit agent knowledge.
 */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const digest = /^[a-f0-9]{64}$/;
const identifier = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const artifactIdentifier = /^artifact-[a-f0-9]{32}$/;

export interface ReviewScope {
  flowId: string;
  engagementId: string;
  revision: number;
  authorizationVersion: number;
  authorizationId: string;
  authorizationSha256: string;
}

export interface ReviewBoundary extends ReviewScope {
  artifactId: string;
  artifactSha256: string;
}

export interface ReviewCandidate {
  artifact_id: string;
  name: string;
  size_bytes: number;
  sha256: string;
  flow_revision: number;
  authorization_version: number;
  review_decision: 'UNKNOWN' | 'approve' | 'reject';
  verified_bytes: true;
  approved: false;
}

export interface ReviewCandidatePage {
  engagement_id: string;
  flow_id: string;
  items: ReviewCandidate[];
  limit: number;
  offset: number;
  next_offset: number | null;
}

export interface FlowArtifactReviewReceipt {
  review_id: string;
  decision: 'approve' | 'reject';
  artifact_id: string;
  flow_id: string;
  engagement_id: string;
  artifact_sha256: string;
  flow_revision: number;
  authorization_version: number;
  authorization_id: string;
  authorization_sha256: string;
  reviewer_sub: string;
  uploader_sub: string;
  reviewed_at: string;
  reviewer_role: 'senior_operator';
  approved: boolean;
  verified_review: true;
}

function checkedScope(boundary: ReviewScope): void {
  if (!identifier.test(boundary.flowId)
    || !identifier.test(boundary.engagementId)
    || !digest.test(boundary.authorizationSha256)
    || typeof boundary.authorizationId !== 'string'
    || boundary.authorizationId.length < 1 || boundary.authorizationId.length > 128
    || /[\x00-\x20\x7f]/.test(boundary.authorizationId)
    || !Number.isSafeInteger(boundary.revision) || boundary.revision < 0
    || !Number.isSafeInteger(boundary.authorizationVersion) || boundary.authorizationVersion < 1) {
    throw new Error('Current signed Flow and exact artifact integrity fields are required.');
  }
  const identity = currentOperator();
  if (!identity || identity.role !== 'senior_operator'
    || !isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('A securely verified senior operator is required for artifact review.');
  }
}

function checkedBoundary(boundary: ReviewBoundary): void {
  checkedScope(boundary);
  if (!artifactIdentifier.test(boundary.artifactId) || !digest.test(boundary.artifactSha256)) {
    throw new Error('An exact immutable artifact ID and digest are required.');
  }
}

function sourceQuery(boundary: ReviewScope): URLSearchParams {
  checkedScope(boundary);
  return new URLSearchParams({
    expected_engagement_id: boundary.engagementId,
    expected_revision: String(boundary.revision),
    expected_authorization_version: String(boundary.authorizationVersion),
    expected_authorization_id: boundary.authorizationId,
    expected_authorization_sha256: boundary.authorizationSha256,
  });
}

function reviewLocation(boundary: ReviewBoundary): string {
  checkedBoundary(boundary);
  return `${API_BASE}/flows/${encodeURIComponent(boundary.flowId)}/artifacts/${encodeURIComponent(boundary.artifactId)}/review`;
}

function verifyReceipt(value: unknown, boundary: ReviewBoundary): FlowArtifactReviewReceipt {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Review receipt was not confirmed.');
  }
  const receipt = value as FlowArtifactReviewReceipt;
  if (!/^review-[a-z0-9-]{8,64}$/.test(receipt.review_id)
    || !['approve', 'reject'].includes(receipt.decision)
    || receipt.flow_id !== boundary.flowId
    || receipt.artifact_id !== boundary.artifactId
    || receipt.engagement_id !== boundary.engagementId
    || receipt.artifact_sha256 !== boundary.artifactSha256
    || receipt.flow_revision !== boundary.revision
    || receipt.authorization_id !== boundary.authorizationId
    || receipt.authorization_version !== boundary.authorizationVersion
    || receipt.authorization_sha256 !== boundary.authorizationSha256
    || typeof receipt.reviewer_sub !== 'string' || !receipt.reviewer_sub
    || typeof receipt.uploader_sub !== 'string' || !receipt.uploader_sub
    || receipt.reviewer_sub === receipt.uploader_sub
    || typeof receipt.reviewed_at !== 'string' || !receipt.reviewed_at
    || receipt.reviewer_role !== 'senior_operator'
    || receipt.approved !== (receipt.decision === 'approve')
    || receipt.verified_review !== true) {
    throw new Error('Review receipt does not match the signed Flow and exact artifact.');
  }
  return receipt;
}

async function failure(response: Response): Promise<never> {
  // Never reflect server exception strings or arbitrary content in a panel.
  if (response.status === 401 || response.status === 403) {
    throw new Error('Signed senior access, independent reviewer or current ROE denied.');
  }
  if (response.status === 404) throw new Error('Artifact or reviewed receipt is unavailable.');
  if (response.status === 409) throw new Error('Artifact, signed policy or Flow revision changed. Refresh and review again.');
  throw new Error(`Artifact review failed (HTTP ${response.status}).`);
}

function requestOptions(method: 'GET' | 'POST'): RequestInit {
  const identity = currentOperator();
  if (identity?.role !== 'senior_operator') {
    throw new Error('Only a currently verified senior operator may review artifacts.');
  }
  return {
    method,
    headers: authHeaders({ Accept: 'application/json', ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  };
}

export const flowArtifactReviewsApi = {
  async candidates(boundary: ReviewScope, offset = 0): Promise<ReviewCandidatePage> {
    const query = sourceQuery(boundary);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 64) {
      throw new Error('Review inventory offset exceeds the bounded search window.');
    }
    query.set('limit', '10');
    query.set('offset', String(offset));
    const response = await fetch(
      `${API_BASE}/flows/${encodeURIComponent(boundary.flowId)}/artifact-reviews/candidates?${query}`,
      requestOptions('GET'),
    );
    if (!response.ok) return failure(response);
    const data: unknown = await response.json();
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Independent review inventory is invalid.');
    }
    const page = data as ReviewCandidatePage;
    if (page.flow_id !== boundary.flowId || page.engagement_id !== boundary.engagementId
      || page.limit !== 10 || page.offset !== offset || !Array.isArray(page.items)
      || page.items.length > 10 || (page.next_offset !== null && (
        !Number.isSafeInteger(page.next_offset) || page.next_offset <= offset
        || page.next_offset > 64))) {
      throw new Error('Review inventory scope or pagination is unverified.');
    }
    const seen = new Set<string>();
    for (const candidate of page.items) {
      if (!candidate || typeof candidate !== 'object'
        || !artifactIdentifier.test(candidate.artifact_id) || seen.has(candidate.artifact_id)
        || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(candidate.name)
        || !Number.isSafeInteger(candidate.size_bytes) || candidate.size_bytes <= 0
        || candidate.size_bytes > 2 * 1024 * 1024 || !digest.test(candidate.sha256)
        || candidate.flow_revision !== boundary.revision
        || candidate.authorization_version !== boundary.authorizationVersion
        || !['UNKNOWN', 'approve', 'reject'].includes(candidate.review_decision)
        || candidate.verified_bytes !== true || candidate.approved !== false) {
        throw new Error('Review candidate metadata or immutable digest is invalid.');
      }
      seen.add(candidate.artifact_id);
    }
    return page;
  },
  async source(boundary: ReviewBoundary, expectedBytes: number): Promise<Blob> {
    checkedBoundary(boundary);
    if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > 2 * 1024 * 1024) {
      throw new Error('Bounded independent artifact source size required.');
    }
    const query = sourceQuery(boundary);
    query.set('expected_sha256', boundary.artifactSha256);
    const response = await fetch(
      `${API_BASE}/flows/${encodeURIComponent(boundary.flowId)}/artifact-reviews/${encodeURIComponent(boundary.artifactId)}/content?${query}`,
      requestOptions('GET'),
    );
    if (!response.ok) return failure(response);
    if (response.headers.get('X-Artifact-SHA256') !== boundary.artifactSha256
      || !globalThis.crypto?.subtle || !response.body) {
      throw new Error('Immutable review source hash or bounded secure stream is unavailable.');
    }
    const advertised = response.headers.get('Content-Length');
    if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) !== expectedBytes)) {
      throw new Error('Reviewer source length conflicts with signed inventory.');
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let count = 0;
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) break;
        count += result.value.byteLength;
        if (count > expectedBytes) throw new Error('Reviewer source exceeded the immutable size bound.');
        chunks.push(result.value);
      }
    } catch (error) {
      await reader.cancel().catch(() => undefined);
      throw error;
    } finally {
      reader.releaseLock();
    }
    if (count !== expectedBytes) throw new Error('Reviewer source was truncated.');
    const bytes = new Uint8Array(count);
    let cursor = 0;
    for (const chunk of chunks) { bytes.set(chunk, cursor); cursor += chunk.byteLength; }
    const actual = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
      (byte) => byte.toString(16).padStart(2, '0')).join('');
    if (actual !== boundary.artifactSha256) {
      throw new Error('Independent reviewer source failed exact SHA-256 integrity.');
    }
    return new Blob([bytes], { type: 'application/octet-stream' });
  },
  async inspect(boundary: ReviewBoundary): Promise<FlowArtifactReviewReceipt | null> {
    const pathname = reviewLocation(boundary);
    const params = new URLSearchParams({
      expected_revision: String(boundary.revision),
      expected_authorization_version: String(boundary.authorizationVersion),
      expected_sha256: boundary.artifactSha256,
      expected_authorization_id: boundary.authorizationId,
      expected_authorization_sha256: boundary.authorizationSha256,
    });
    const response = await fetch(`${pathname}?${params}`, requestOptions('GET'));
    if (!response.ok) return failure(response);
    const value: unknown = await response.json();
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const unresolved = value as { status?: unknown; verified_review?: unknown; approved?: unknown; decision?: unknown; artifact_id?: unknown };
      if (unresolved.status === 'unknown' || (unresolved.verified_review === false
        && unresolved.approved === false && unresolved.decision === 'UNKNOWN'
        && unresolved.artifact_id === boundary.artifactId)) return null;
    }
    return verifyReceipt(value, boundary);
  },
  async decide(boundary: ReviewBoundary, decision: 'approve' | 'reject', reason: string): Promise<FlowArtifactReviewReceipt> {
    const pathname = reviewLocation(boundary);
    const cleanReason = reason.trim();
    if (!['approve', 'reject'].includes(decision)
      || cleanReason.length < 10 || cleanReason.length > 512) {
      throw new Error('Provide an explicit review decision and meaningful 10–512 character reason.');
    }
    const response = await fetch(pathname, {
      ...requestOptions('POST'),
      body: JSON.stringify({
        decision,
        reason: cleanReason,
        expected_sha256: boundary.artifactSha256,
        expected_revision: boundary.revision,
        expected_authorization_version: boundary.authorizationVersion,
        expected_authorization_id: boundary.authorizationId,
        expected_authorization_sha256: boundary.authorizationSha256,
      }),
    });
    if (!response.ok) return failure(response);
    if (response.status !== 201) {
      throw new Error('Artifact review must be durably created; no acknowledgement was confirmed.');
    }
    const receipt = verifyReceipt(await response.json(), boundary);
    if (receipt.decision !== decision) {
      throw new Error('Stored review decision differs from the explicit operator decision.');
    }
    return receipt;
  },
};
