/** Explicitly human-released signed report snapshots (not unsigned summaries). */
import { API_BASE, authHeaders, currentOperator, isSecureApiBase, isSecureBrowserOrigin } from './api';

const digestPattern = /^[0-9a-f]{64}$/;
const reportPattern = /^report-[A-Za-z0-9_.-]{1,128}$/;
export type SignedReportArtifactKind = 'md' | 'json' | 'html' | 'graph.html';
const artifactKinds: SignedReportArtifactKind[] = ['md', 'json', 'html', 'graph.html'];

export type SignedReportPreview = {
  report_id: string;
  attestation_sha256: string;
  authorization_version: number;
  release_status: 'signed_report_task_snapshot_verified';
  operator_approval_verified: false;
  artifact_sha256: Record<SignedReportArtifactKind, string>;
  flow_binding: { flow_id: string; flow_revision: number } | null;
};

export type HumanReleaseReceipt = {
  status: 'human_release_approved' | 'awaiting_human_release';
  report_id: string;
  attestation_sha256: string;
  authorization_version: number;
  release_event_id: string | null;
  operator_approval_recorded: boolean;
  external_effect_verified: boolean;
  report_completeness_certified: false;
};

/** Inert confirmation of locally hashed, nonempty bytes; never raw witness content. */
export type SignedReportReview = {
  report_id: string;
  attestation_sha256: string;
  authorization_version: number;
  artifact_kind: 'md';
  artifact_sha256: string;
  byte_length: number;
  reviewer_sub: string;
};

export function sameSignedSnapshot(
  preview: SignedReportPreview, current: HumanReleaseReceipt,
): boolean {
  return current.report_id === preview.report_id
    && current.attestation_sha256 === preview.attestation_sha256
    && current.authorization_version === preview.authorization_version;
}

const releaseFields = [
  'status', 'report_id', 'attestation_sha256', 'authorization_version',
  'release_event_id', 'operator_approval_recorded', 'external_effect_verified',
  'report_completeness_certified',
];

function uri(engagementId: string, reportId: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$/.test(engagementId)
      || !reportPattern.test(reportId)
      || !reportId.startsWith('report-' + engagementId + '-')) {
    throw new Error('Signed report identity is invalid or belongs to another engagement.');
  }
  return API_BASE + '/engagements/' + encodeURIComponent(engagementId)
    + '/attestations/' + encodeURIComponent(reportId);
}

async function request(
  url: string, method: 'GET' | 'POST', body?: object,
): Promise<unknown> {
  if (!isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
    throw new Error('Signed report authorization requires HTTPS or local loopback.');
  }
  const headers = authHeaders({ Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) });
  if (!/^Bearer \S+$/.test(headers.Authorization ?? '')) {
    throw new Error('A currently verified operator bearer is required.');
  }
  const response = await fetch(url, {
    method,
    headers,
    ...(body ? { body: JSON.stringify(body) } : {}),
    credentials: 'omit', cache: 'no-store', redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error('Verified report service rejected or could not verify the request.');
  return response.json();
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Report verification did not return a valid object.');
  }
  return value as Record<string, unknown>;
}

function receipt(value: unknown, reportId: string): HumanReleaseReceipt {
  const row = object(value);
  if (
    Object.keys(row).sort().join(',') !== [...releaseFields].sort().join(',')
    ||
    !['human_release_approved', 'awaiting_human_release'].includes(String(row.status))
    || row.report_id !== reportId
    || typeof row.attestation_sha256 !== 'string'
    || !digestPattern.test(row.attestation_sha256)
    || !Number.isSafeInteger(row.authorization_version)
    || Number(row.authorization_version) < 1
    || typeof row.operator_approval_recorded !== 'boolean'
    || typeof row.external_effect_verified !== 'boolean'
    || row.report_completeness_certified !== false
    || (row.release_event_id !== null && (typeof row.release_event_id !== 'string'
      || !/^evt-[A-Za-z0-9._-]{1,60}$/.test(row.release_event_id)))
    || (row.status === 'human_release_approved') !== row.operator_approval_recorded
    || (row.status === 'human_release_approved' && !row.release_event_id)
    || (row.status === 'awaiting_human_release' && row.release_event_id !== null)
  ) {
    throw new Error('Human release status cannot be verified.');
  }
  return row as HumanReleaseReceipt;
}

export const signedReportsApi = {
  async inspect(engagementId: string, reportId: string): Promise<SignedReportPreview> {
    const data = object(await request(uri(engagementId, reportId), 'GET'));
    const manifest = object(data.manifest);
    const attestation = object(object(data.signed_attestation).attestation);
    const binding = object(attestation.generation_binding);
    const sha = manifest.attestation_sha256;
    const version = binding.authorization_version;
    const artifactHashes = object(attestation.artifacts);
    const manifestHashes = object(manifest.artifacts);
    const schema = attestation.schema;
    const isFlowV3 = schema === 'ai-osop-report-attestation-v3';
    const isStandaloneV2 = schema === 'ai-osop-report-attestation-v2';
    const flowBinding = isFlowV3 ? {
      flow_id: binding.flow_id,
      flow_revision: binding.flow_revision,
    } : null;
    const flowBindingValid = isFlowV3
      ? (typeof binding.flow_id === 'string'
        && /^flow-[A-Za-z0-9_.-]{1,123}$/.test(binding.flow_id)
        && Number.isSafeInteger(binding.flow_revision)
        && Number(binding.flow_revision) >= 0
        && typeof binding.task_id === 'string'
        && /^task-[A-Za-z0-9_.-]{1,123}$/.test(binding.task_id)
        && typeof binding.authorization_sha256 === 'string'
        && digestPattern.test(binding.authorization_sha256)
        && typeof binding.task_payload_sha256 === 'string'
        && digestPattern.test(binding.task_payload_sha256)
        && Object.keys(binding).sort().join(',') === [
          'task_id', 'authorization_version', 'authorization_sha256',
          'task_payload_sha256', 'flow_id', 'flow_revision',
        ].sort().join(','))
      : (isStandaloneV2 && !('flow_id' in binding) && !('flow_revision' in binding));
    if (
      !flowBindingValid
      || data.release_status !== 'signed_report_task_snapshot_verified'
      || data.operator_approval_verified !== false
      || data.independent_target_authority_verified === true
      || data.finding_release_eligible === true
      || typeof sha !== 'string' || !digestPattern.test(sha)
      || !Number.isSafeInteger(version) || Number(version) < 1
      || attestation.report_id !== reportId
      || manifest.report_id !== reportId
      || Object.keys(artifactHashes).length !== artifactKinds.length
      || Object.keys(manifestHashes).length !== artifactKinds.length
      || artifactKinds.some((kind) =>
        typeof artifactHashes[kind] !== 'string'
        || !digestPattern.test(artifactHashes[kind] as string)
        || manifestHashes[kind] !== artifactHashes[kind])
    ) throw new Error('Report snapshot is not independently generation-verified.');
    return {
      report_id: reportId, attestation_sha256: sha,
      authorization_version: Number(version),
      release_status: 'signed_report_task_snapshot_verified',
      operator_approval_verified: false,
      artifact_sha256: Object.fromEntries(
        artifactKinds.map((kind) => [kind, artifactHashes[kind]]),
      ) as Record<SignedReportArtifactKind, string>,
      flow_binding: flowBindingValid && isFlowV3
        ? flowBinding as { flow_id: string; flow_revision: number }
        : null,
    };
  },
  async downloadVerifiedArtifact(
    engagementId: string, preview: SignedReportPreview,
    kind: SignedReportArtifactKind,
  ): Promise<ArrayBuffer> {
    if (!artifactKinds.includes(kind) || !digestPattern.test(preview.artifact_sha256?.[kind] ?? '')) {
      throw new Error('Trusted signed report artifact digest is unavailable.');
    }
    if (!isSecureApiBase(API_BASE) || !isSecureBrowserOrigin()) {
      throw new Error('Verified artifact download requires HTTPS or local loopback.');
    }
    const headers = authHeaders({ Accept: 'application/octet-stream' });
    if (!/^Bearer \S+$/.test(headers.Authorization ?? '')) {
      throw new Error('A currently verified operator bearer is required.');
    }
    const response = await fetch(
      uri(engagementId, preview.report_id) + '/artifacts/' + encodeURIComponent(kind),
      {
        method: 'GET',
        headers,
        credentials: 'omit', cache: 'no-store', redirect: 'error',
        referrerPolicy: 'no-referrer',
      },
    );
    if (!response.ok || !response.body) {
      throw new Error('Original signed artifact download is unavailable.');
    }
    const returnedDigest = response.headers.get('X-Signed-Artifact-Sha256');
    if (returnedDigest !== null && returnedDigest !== preview.artifact_sha256[kind]) {
      throw new Error('Server artifact digest differs from signed manifest.');
    }
    // Bound each streamed report without trusting a Content-Length header.
    const reader = response.body.getReader();
    const pieces: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        if (!(item.value instanceof Uint8Array) ||
            length + item.value.byteLength > 4 * 1024 * 1024) {
          throw new Error('Signed report artifact is oversized or invalid.');
        }
        length += item.value.byteLength;
        pieces.push(item.value);
      }
    } finally {
      reader.releaseLock();
    }
    if (length === 0 || !globalThis.crypto?.subtle) {
      throw new Error('Cryptographic signed artifact verification unavailable.');
    }
    const bytes = new Uint8Array(length);
    let cursor = 0;
    for (const piece of pieces) {
      bytes.set(piece, cursor);
      cursor += piece.byteLength;
    }
    const digest = Array.from(
      new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)),
      (number) => number.toString(16).padStart(2, '0'),
    ).join('');
    if (digest !== preview.artifact_sha256[kind]) {
      throw new Error('Downloaded bytes fail independent signed-manifest SHA-256 verification.');
    }
    return bytes.buffer as ArrayBuffer;
  },
  async reviewExactSnapshot(
    engagementId: string, preview: SignedReportPreview,
  ): Promise<{ bytes: ArrayBuffer; review: SignedReportReview }> {
    const identity = currentOperator();
    if (!identity || identity.role !== 'senior_operator' || !identity.sub.trim()) {
      throw new Error('Authenticated senior operator required to review signed report.');
    }
    if (preview.release_status !== 'signed_report_task_snapshot_verified'
      || preview.operator_approval_verified !== false
      || !digestPattern.test(preview.attestation_sha256)
      || !Number.isSafeInteger(preview.authorization_version)
      || preview.authorization_version < 1) {
      throw new Error('Exact verified report snapshot is unavailable.');
    }
    const bytes = await this.downloadVerifiedArtifact(engagementId, preview, 'md');
    if (bytes.byteLength === 0 || bytes.byteLength > 4 * 1024 * 1024) {
      throw new Error('The original signed report snapshot is empty or oversized.');
    }
    if (currentOperator()?.sub !== identity.sub || currentOperator()?.role !== 'senior_operator') {
      throw new Error('Operator changed during exact signed report review.');
    }
    // Do not decode, render, cache or log raw report/private witness bodies.
    // The caller supplies these exact verified bytes as a private download.
    return { bytes, review: {
      report_id: preview.report_id,
      attestation_sha256: preview.attestation_sha256,
      authorization_version: preview.authorization_version,
      artifact_kind: 'md',
      artifact_sha256: preview.artifact_sha256.md,
      byte_length: bytes.byteLength,
      reviewer_sub: identity.sub,
    } };
  },
  async approve(
    engagementId: string, preview: SignedReportPreview, reason: string,
    review?: SignedReportReview,
  ): Promise<HumanReleaseReceipt> {
    const identity = currentOperator();
    if (!identity || identity.role !== 'senior_operator' || !identity.sub.trim()
      || !review || review.reviewer_sub !== identity.sub
      || review.report_id !== preview.report_id
      || review.attestation_sha256 !== preview.attestation_sha256
      || review.authorization_version !== preview.authorization_version
      || review.artifact_kind !== 'md'
      || review.artifact_sha256 !== preview.artifact_sha256?.md
      || !Number.isSafeInteger(review.byte_length)
      || review.byte_length < 1 || review.byte_length > 4 * 1024 * 1024
      || preview.release_status !== 'signed_report_task_snapshot_verified'
      || preview.operator_approval_verified !== false) {
      throw new Error('Human must review the exact nonempty signed report bytes before approval.');
    }
    if (reason.trim().length < 20 || reason.trim().length > 256) {
      throw new Error('A meaningful human final-release reason (20–256 characters) is required.');
    }
    const data = await request(uri(engagementId, preview.report_id) + '/release', 'POST', {
      expected_authorization_version: preview.authorization_version,
      expected_attestation_sha256: preview.attestation_sha256,
      reason: reason.trim(),
      approval_statement: 'I approve releasing this exact signed report snapshot',
    });
    const result = receipt(data, preview.report_id);
    if (
      result.status !== 'human_release_approved'
      || !sameSignedSnapshot(preview, result)
      || !result.release_event_id
      || currentOperator()?.sub !== identity.sub
      || currentOperator()?.role !== 'senior_operator'
    ) throw new Error('Current signed report release acknowledgment is unverified.');
    return result;
  },
  async status(engagementId: string, reportId: string): Promise<HumanReleaseReceipt> {
    return receipt(await request(uri(engagementId, reportId) + '/release', 'GET'), reportId);
  },
};
