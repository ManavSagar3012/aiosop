import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const oldFetch = globalThis.fetch;
const engagement = 'eng-review';
const reportId = `report-${engagement}-v1`;
const sha = 'a'.repeat(64);
const reportBytes = new TextEncoder().encode('# Independently signed report\nNo live witness body shown in dashboard.');
const mdSha = createHash('sha256').update(reportBytes).digest('hex');
const hashes = { md: mdSha, json: 'b'.repeat(64), html: 'c'.repeat(64), 'graph.html': 'd'.repeat(64) };
let vite, api, signed, page;
let calls = [];
let snapshot, release, content;

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  signed = await vite.ssrLoadModule('/src/services/signedReports.ts');
  page = await vite.ssrLoadModule('/src/pages/FlowOperations.tsx');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = oldFetch;
  await vite?.close();
});

function originalSnapshot() {
  return {
    release_status: 'signed_report_task_snapshot_verified',
    operator_approval_verified: false,
    independent_target_authority_verified: false,
    finding_release_eligible: false,
    manifest: { report_id: reportId, attestation_sha256: sha, artifacts: { ...hashes } },
    signed_attestation: { attestation: {
      schema: 'ai-osop-report-attestation-v3', report_id: reportId,
      generation_binding: {
        task_id: 'task-review', authorization_version: 5,
        authorization_sha256: 'e'.repeat(64), task_payload_sha256: 'f'.repeat(64),
        flow_id: 'flow-review', flow_revision: 3,
      }, artifacts: { ...hashes },
    } },
  };
}

function originalStatus(approved = false) {
  return {
    status: approved ? 'human_release_approved' : 'awaiting_human_release',
    report_id: reportId, attestation_sha256: sha, authorization_version: 5,
    release_event_id: approved ? 'evt-review-approved' : null,
    operator_approval_recorded: approved,
    external_effect_verified: false,
    report_completeness_certified: false,
  };
}

function json(body, code = 200) {
  return { ok: code === 200, status: code, json: async () => structuredClone(body) };
}

async function signIn(role = 'senior_operator') {
  api.signOut();
  calls = [];
  snapshot = originalSnapshot();
  release = originalStatus();
  content = reportBytes;
  globalThis.fetch = async (url, options = {}) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, url: String(url), options });
    if (pathname === '/auth/me') return json({ sub: 'senior-owner', role, exp: null });
    if (pathname.endsWith('/artifacts/md')) return {
      ok: true, status: 200,
      headers: { get: name => name === 'X-Signed-Artifact-Sha256' ? mdSha : null },
      body: new ReadableStream({ start(controller) { controller.enqueue(content); controller.close(); } }),
    };
    if (pathname.endsWith('/release')) {
      if (options.method === 'POST') {
        release = originalStatus(true);
        return json(release);
      }
      return json(release);
    }
    if (pathname.endsWith(`/attestations/${reportId}`)) return json(snapshot);
    throw new Error('Unexpected signing endpoint: ' + pathname);
  };
  await api.signIn('review-bearer-secret');
}

test('mounted FlowOperations has one private report review gate and independent release readback', () => {
  const html = renderToStaticMarkup(createElement(page.SignedReportOperatorPanel, { engagementId: engagement }));
  assert.match(html, /SIGNED REPORT — PRIVATE HUMAN REVIEW/);
  assert.match(html, /SIGNED REPORT ID/);
  assert.match(html, /VERIFY SNAPSHOT \+ SEPARATE SIGNED RELEASE GET/);
  assert.doesNotMatch(html, /private witness body\s*:/i);
  const operations = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');
  assert.match(operations, /<SignedReportOperatorPanel key=/);
  assert.doesNotMatch(operations, /<SignedReportReleasePanel/);
  assert.match(operations, /signedReportsApi\.reviewExactSnapshot\(engagementId, preview\)/);
  assert.match(operations, /download\.click\(\)/);
  assert.match(operations, /setReview\(verified\.review\)/);
  assert.match(operations, /!acknowledged/);
  assert.match(operations, /typedDigest !== preview\.attestation_sha256/);
  assert.match(operations, /const fresh = await signedReportsApi\.inspect/);
  assert.match(operations, /const before = await signedReportsApi\.status/);
  assert.match(operations, /const readback = await signedReportsApi\.status/);
  assert.match(operations, /setRelease\(null\); \/\/ A POST success/);
  assert.match(operations, /subscribeOperator\(/);
  assert.doesNotMatch(operations, /dangerouslySetInnerHTML|document\.write/);
});

test('original nonempty signed artifact GET hashes bytes before review; POST requires explicit review', async () => {
  await signIn();
  const inspected = await signed.signedReportsApi.inspect(engagement, reportId);
  assert.deepEqual(inspected.flow_binding, { flow_id: 'flow-review', flow_revision: 3 });
  const pending = await signed.signedReportsApi.status(engagement, reportId);
  assert.ok(signed.sameSignedSnapshot(inspected, pending));
  assert.equal(pending.operator_approval_recorded, false);
  const priorCount = calls.length;
  await assert.rejects(
    signed.signedReportsApi.approve(engagement, inspected, 'I inspected the complete signed report file.'),
    /Human must review/,
  );
  assert.equal(calls.length, priorCount);
  const downloaded = await signed.signedReportsApi.reviewExactSnapshot(engagement, inspected);
  assert.deepEqual(new Uint8Array(downloaded.bytes), reportBytes);
  assert.equal(downloaded.review.byte_length, reportBytes.byteLength);
  assert.equal(downloaded.review.artifact_sha256, mdSha);
  assert.equal(downloaded.review.reviewer_sub, 'senior-owner');
  const response = await signed.signedReportsApi.approve(
    engagement, inspected, 'I inspected the complete signed report file.', downloaded.review,
  );
  assert.equal(response.status, 'human_release_approved');
  const status = await signed.signedReportsApi.status(engagement, reportId);
  assert.equal(status.release_event_id, response.release_event_id);
  assert.ok(signed.sameSignedSnapshot(inspected, status));
  const sent = calls.filter(call => call.pathname.endsWith('/release'));
  assert.deepEqual(sent.map(call => call.options.method), ['GET', 'POST', 'GET']);
  assert.equal(sent[1].options.headers.Authorization, 'Bearer review-bearer-secret');
  assert.equal(sent[1].options.cache, 'no-store');
  assert.equal(sent[1].options.redirect, 'error');
  assert.equal(sent[1].options.credentials, 'omit');
  assert.deepEqual(JSON.parse(sent[1].options.body), {
    expected_authorization_version: 5,
    expected_attestation_sha256: sha,
    reason: 'I inspected the complete signed report file.',
    approval_statement: 'I approve releasing this exact signed report snapshot',
  });
  assert.ok(calls.every(call => !call.url.includes('bearer-secret')));
});

test('empty, altered, or body-only forged artifact never permits review or release', async () => {
  await signIn();
  const inspected = await signed.signedReportsApi.inspect(engagement, reportId);
  for (const broken of [new Uint8Array(), new TextEncoder().encode('Private witness changed!')]) {
    content = broken;
    await assert.rejects(
      signed.signedReportsApi.reviewExactSnapshot(engagement, inspected),
      /artifact|Cryptographic|digest|verification/i,
    );
  }
  assert.equal(calls.filter(call => call.options.method === 'POST').length, 0);
});

test('strict readback refuses forged verification, stale version, false approval and private witness fields', async () => {
  await signIn();
  snapshot.independent_target_authority_verified = true;
  await assert.rejects(signed.signedReportsApi.inspect(engagement, reportId), /generation-verified/);
  snapshot = originalSnapshot();
  snapshot.operator_approval_verified = true;
  await assert.rejects(signed.signedReportsApi.inspect(engagement, reportId), /generation-verified/);
  snapshot = originalSnapshot();
  const inspected = await signed.signedReportsApi.inspect(engagement, reportId);
  release = { ...originalStatus(), authorization_version: 6 };
  const stale = await signed.signedReportsApi.status(engagement, reportId);
  assert.equal(signed.sameSignedSnapshot(inspected, stale), false);
  release = { ...originalStatus(), status: 'human_release_approved', release_event_id: null, operator_approval_recorded: true };
  await assert.rejects(signed.signedReportsApi.status(engagement, reportId), /cannot be verified/);
  release = { ...originalStatus(), private_witness_body: { cookie: 'secret-not-for-ui' } };
  await assert.rejects(signed.signedReportsApi.status(engagement, reportId), /cannot be verified/);
  release = { ...originalStatus(), release_event_id: 'evt-false-release' };
  await assert.rejects(signed.signedReportsApi.status(engagement, reportId), /cannot be verified/);
});

test('non-senior, swapped identity and a forged report snapshot cannot release', async () => {
  await signIn('operator');
  const inspected = await signed.signedReportsApi.inspect(engagement, reportId);
  await assert.rejects(signed.signedReportsApi.reviewExactSnapshot(engagement, inspected), /senior operator/);
  await signIn();
  const verified = await signed.signedReportsApi.inspect(engagement, reportId);
  const reviewed = await signed.signedReportsApi.reviewExactSnapshot(engagement, verified);
  await signIn('operator');
  const count = calls.length;
  await assert.rejects(signed.signedReportsApi.approve(
    engagement, verified, 'I personally reviewed these original signed bytes.', reviewed.review,
  ), /Human must review/);
  assert.equal(calls.length, count);
  await signIn();
  const rewritten = { ...verified, attestation_sha256: 'f'.repeat(64) };
  await assert.rejects(signed.signedReportsApi.approve(
    engagement, rewritten, 'I personally reviewed these original signed bytes.', reviewed.review,
  ), /Human must review/);
});
