import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const oldFetch = globalThis.fetch;
let vite, api, reports;

const engagement = 'eng-report-owner';
const reportId = 'report-' + engagement + '-v1';
const sha = 'a'.repeat(64);

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  reports = await vite.ssrLoadModule('/src/services/signedReports.ts');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = oldFetch;
  await vite?.close();
});

const jwtProof = {
  sub: 'owner', role: 'senior_operator',
  exp: Math.floor(Date.now() / 1000) + 300,
};

function snapshot() {
  // Verification now requires all four original report artifact digests from
  // both the report manifest and the signed attestation, not just the report ID.
  const artifacts = {
    md: 'b'.repeat(64), json: 'c'.repeat(64),
    html: 'd'.repeat(64), 'graph.html': 'e'.repeat(64),
  };
  return {
    release_status: 'signed_report_task_snapshot_verified',
    operator_approval_verified: false,
    manifest: {
      report_id: reportId, attestation_sha256: sha, artifacts,
    },
    signed_attestation: {
      attestation: {
        schema: 'ai-osop-report-attestation-v2',
        report_id: reportId,
        generation_binding: {
          task_id: 'task-report-fixture', authorization_version: 5,
          authorization_sha256: 'f'.repeat(64),
          task_payload_sha256: '9'.repeat(64),
        },
        artifacts,
      },
    },
  };
}

function release(approved = true) {
  return {
    status: approved ? 'human_release_approved' : 'awaiting_human_release',
    report_id: reportId, attestation_sha256: sha,
    authorization_version: 5,
    release_event_id: approved ? 'evt-report-signoff' : null,
    operator_approval_recorded: approved,
    external_effect_verified: false,
    report_completeness_certified: false,
  };
}

test('signed report snapshot, separate human approval and independent status recheck use bearer-only REST', async () => {
  const seen = [];
  globalThis.fetch = async (url, options) => {
    seen.push({ url, options });
    if (url.endsWith('/auth/me')) return { ok: true, json: async () => jwtProof };
    if (url.endsWith('/release')) return {
      ok: true, json: async () => release(),
    };
    return { ok: true, json: async () => snapshot() };
  };
  await api.signIn('signed-human-credential');
  const prior = await reports.signedReportsApi.inspect(engagement, reportId);
  assert.equal(prior.attestation_sha256, sha);
  assert.equal(prior.flow_binding, null);
  const result = await reports.signedReportsApi.approve(
    engagement, prior, 'Verified signed bytes and evidence before release.',
    { report_id: reportId, attestation_sha256: sha, authorization_version: 5,
      artifact_kind: 'md', artifact_sha256: 'b'.repeat(64), byte_length: 42,
      reviewer_sub: 'owner' },
  );
  assert.equal(result.operator_approval_recorded, true);
  assert.equal(result.report_completeness_certified, false);
  assert.equal(result.external_effect_verified, false);
  const recovered = await reports.signedReportsApi.status(engagement, reportId);
  assert.equal(recovered.release_event_id, 'evt-report-signoff');
  const approved = seen[2];
  assert.equal(approved.url,
    api.API_BASE + '/engagements/' + engagement
    + '/attestations/' + reportId + '/release');
  assert.equal(approved.options.headers.Authorization, 'Bearer signed-human-credential');
  assert.equal(approved.options.method, 'POST');
  assert.equal(approved.options.cache, 'no-store');
  assert.equal(approved.options.credentials, 'omit');
  assert.equal(approved.options.redirect, 'error');
  assert.deepEqual(JSON.parse(approved.options.body), {
    expected_authorization_version: 5,
    expected_attestation_sha256: sha,
    reason: 'Verified signed bytes and evidence before release.',
    approval_statement: 'I approve releasing this exact signed report snapshot',
  });
  assert.equal(approved.url.includes('signed-human-credential'), false);
});

test('independent verified effect flag does not itself authorize senior release', async () => {
  globalThis.fetch = async (url) => ({
    ok: true,
    json: async () => url.endsWith('/auth/me') ? jwtProof : {
      ...release(false), external_effect_verified: true,
    },
  });
  await api.signIn('signed-human-credential');
  const pending = await reports.signedReportsApi.status(engagement, reportId);
  assert.equal(pending.status, 'awaiting_human_release');
  assert.equal(pending.external_effect_verified, true);
  assert.equal(pending.operator_approval_recorded, false);
  globalThis.fetch = async (url) => ({
    ok: true,
    json: async () => url.endsWith('/auth/me') ? jwtProof : {
      ...release(true), external_effect_verified: true,
    },
  });
  const approved = await reports.signedReportsApi.status(engagement, reportId);
  assert.equal(approved.external_effect_verified, true);
  assert.equal(approved.operator_approval_recorded, true);
});

test('v3 report inspection carries signed Flow revision and rejects malformed Flow downgrade', async () => {
  const original = snapshot();
  original.signed_attestation.attestation.schema = 'ai-osop-report-attestation-v3';
  original.signed_attestation.attestation.generation_binding = {
    ...original.signed_attestation.attestation.generation_binding,
    flow_id: 'flow-safe-owned', flow_revision: 7,
  };
  globalThis.fetch = async (url) => ({
    ok: true,
    json: async () => url.endsWith('/auth/me')
      ? jwtProof : structuredClone(original),
  });
  const inspected = await reports.signedReportsApi.inspect(engagement, reportId);
  assert.deepEqual(inspected.flow_binding, { flow_id: 'flow-safe-owned', flow_revision: 7 });

  for (const invalid of [
    { flow_revision: true }, { flow_revision: -1 },
    { flow_id: 'flow-../foreign' }, { flow_id: 'eng-foreign' },
    { unauthorized_field: 'fake proof' },
  ]) {
    Object.assign(original.signed_attestation.attestation.generation_binding, invalid);
    await assert.rejects(
      reports.signedReportsApi.inspect(engagement, reportId), /generation-verified/,
    );
    original.signed_attestation.attestation.generation_binding = {
      task_id: 'task-report-fixture', authorization_version: 5,
      authorization_sha256: 'f'.repeat(64), task_payload_sha256: '9'.repeat(64),
      flow_id: 'flow-safe-owned', flow_revision: 7,
    };
  }
  original.signed_attestation.attestation.schema = 'ai-osop-report-attestation-v2';
  await assert.rejects(reports.signedReportsApi.inspect(engagement, reportId), /generation-verified/);
});

test('unsafe report identity or reason cannot contact signing service', async () => {
  let called = 0;
  globalThis.fetch = async () => {
    called++;
    throw Error('must not contact server');
  };
  for (const invalid of [
    'summary-' + 'a'.repeat(64),
    'report-eng-other-v1',
    '../report-' + engagement + '-v1',
  ]) {
    await assert.rejects(reports.signedReportsApi.inspect(engagement, invalid));
  }
  await assert.rejects(reports.signedReportsApi.approve(
    engagement, {
      report_id: reportId, attestation_sha256: sha,
      authorization_version: 5,
      release_status: 'signed_report_task_snapshot_verified',
      operator_approval_verified: false,
    }, 'not enough',
  ));
  assert.equal(called, 0);
});

test('stale digest and fake provider success can never confirm human signoff', async () => {
  globalThis.fetch = async (url) => ({
    ok: true,
    json: async () => url.endsWith('/release')
      ? { ...release(), attestation_sha256: 'b'.repeat(64) }
      : snapshot(),
  });
  await assert.rejects(reports.signedReportsApi.approve(
    engagement, {
      report_id: reportId, attestation_sha256: sha,
      authorization_version: 5,
      release_status: 'signed_report_task_snapshot_verified',
      operator_approval_verified: false,
      artifact_sha256: { md: 'b'.repeat(64) },
    }, 'Independent original source records checked.',
    { report_id: reportId, attestation_sha256: sha, authorization_version: 5,
      artifact_kind: 'md', artifact_sha256: 'b'.repeat(64), byte_length: 42,
      reviewer_sub: 'owner' },
  ), /unverified/);
});

test('FlowOperations contains an actual senior-only human signoff workflow, never printable summary approval', () => {
  const operations = readFileSync(
    fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)),
    'utf8',
  );
  assert.match(operations, /<SignedReportOperatorPanel key=/);
  assert.match(operations, /identity\?\.role === 'senior_operator'/);
  assert.match(operations, /window\.confirm/);
  assert.match(operations, /signedReportsApi\.inspect/);
  assert.match(operations, /signedReportsApi\.status/);
  assert.match(operations, /signedReportsApi\.approve/);
  assert.match(operations, /signedReportsApi\.reviewExactSnapshot/);
  assert.match(operations, /typedDigest !== preview\.attestation_sha256/);
  assert.match(operations, /does NOT certify finding authenticity/);
  assert.doesNotMatch(operations, /dangerouslySetInnerHTML/);
});
