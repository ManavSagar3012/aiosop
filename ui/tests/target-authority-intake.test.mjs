import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'vite';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let api;
let target;
let panel;

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  target = await vite.ssrLoadModule('/src/services/targetAuthority.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/TargetAuthorityReviewPanel.tsx');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

function respond(data, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => data, headers: { get: () => 'application/json' } };
}

function request() {
  return {
    engagementId: 'eng-test', flowId: 'flow-test', originalTaskId: 'task-original',
    sourceTaskId: 'task-source', targetTaskId: 'task-target',
    canonicalClaims: '{}', signature: 'A'.repeat(86),
  };
}

test('target-owned intake uses bearer-only and leaves external effects unverified', async () => {
  api.signOut();
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).endsWith('/auth/me')) return respond({ sub: 'owner', role: 'senior_operator', exp: null });
    return respond({
      status: 'target_assertion_admitted_candidate_only',
      engagement_id: 'eng-test', flow_id: 'flow-test',
      source_task_id: 'task-source', target_task_id: 'task-target',
      key_id: 'independent', proof_sha256: 'a'.repeat(64),
      target_controlled_signature_verified: true,
      independent_target_authority_verified: true,
      finding_verified: false, authorization_violation_verified: false,
      report_release_approved: false,
    });
  };
  await api.signIn('test-owner-bearer');
  const result = await target.submitTargetAssertion(request());
  assert.equal(result.finding_verified, false);
  assert.equal(result.report_release_approved, false);
  const post = calls.find(call => call.options.method === 'POST');
  assert.match(post.url, /\/engagements\/eng-test\/flows\/flow-test\/target-authority\/attestations$/);
  assert.doesNotMatch(post.url, /token|bearer|signature/i);
  assert.equal(post.options.headers.Authorization, 'Bearer test-owner-bearer');
  assert.equal(post.options.credentials, 'omit');
  assert.equal(post.options.redirect, 'error');
  assert.deepEqual(Object.keys(JSON.parse(post.options.body)).sort(), [
    'claims_json', 'original_source_task_id', 'signature_b64url', 'source_task_id', 'target_task_id',
  ]);
});

test('forged provider response cannot assert verified finding or released report', async () => {
  globalThis.fetch = async (url, options = {}) => {
    if (String(url).endsWith('/auth/me')) return respond({ sub: 'owner', role: 'senior_operator', exp: null });
    return respond({
      status: 'target_assertion_admitted_candidate_only', engagement_id: 'eng-test', flow_id: 'flow-test',
      source_task_id: 'task-source', target_task_id: 'task-target',
      proof_sha256: 'a'.repeat(64), target_controlled_signature_verified: true,
      independent_target_authority_verified: true, finding_verified: true,
      authorization_violation_verified: true, report_release_approved: true,
    });
  };
  await assert.rejects(() => target.submitTargetAssertion(request()), /not independently acknowledged/);
});

test('incomplete independently signed audit pair never reaches target intake', async () => {
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; throw new Error('unexpected request'); };
  await assert.rejects(() => target.submitTargetAssertion({
    ...request(), ownershipAuditJson: '{}',
  }), /All independent ownership and access audit fields/);
  assert.equal(calls, 0);
});

test('complete corroboration requires explicit independent acknowledgement', async () => {
  let submitted;
  globalThis.fetch = async (url, options = {}) => {
    submitted = options.body && JSON.parse(options.body);
    return respond({
      status: 'target_assertion_admitted_candidate_only',
      engagement_id: 'eng-test', flow_id: 'flow-test',
      source_task_id: 'task-source', target_task_id: 'task-target',
      proof_sha256: 'a'.repeat(64), target_controlled_signature_verified: true,
      independent_target_authority_verified: true, finding_verified: false,
      authorization_violation_verified: false, report_release_approved: false,
      independent_audit_records_correlated: false,
    });
  };
  await assert.rejects(() => target.submitTargetAssertion({
    ...request(), ownershipAuditJson: '{}', ownershipAuditSignature: 'A'.repeat(86),
    accessAuditJson: '{}', accessAuditSignature: 'B'.repeat(86),
  }), /corroboration was not acknowledged/);
  assert.equal(submitted.ownership_audit_json, '{}');
  assert.equal(submitted.access_audit_signature, 'B'.repeat(86));
  assert.equal(submitted.finding_verified, undefined);
});

test('read-only historical verification binds exact stored proof and candidate-only receipt', async () => {
  let post;
  const sha = 'b'.repeat(64);
  globalThis.fetch = async (url, options = {}) => {
    post = { url: String(url), options };
    return respond({
      status: 'target_assertion_reverified_candidate_only',
      engagement_id: 'eng-test', flow_id: 'flow-test',
      source_task_id: 'task-source', target_task_id: 'task-target',
      proof_sha256: sha, target_controlled_signature_verified: true,
      independent_target_authority_verified: true,
      finding_verified: false, authorization_violation_verified: false,
      report_release_approved: false, independent_audit_records_correlated: false,
    });
  };
  const response = await target.submitTargetAssertion(request(), sha);
  assert.equal(response.finding_verified, false);
  assert.match(post.url, new RegExp(`/target-authority/attestations/${sha}/reverify$`));
  assert.equal(post.options.headers.Authorization, 'Bearer test-owner-bearer');
  assert.doesNotMatch(post.url, /token|bearer|signature/i);
  await assert.rejects(() => target.submitTargetAssertion(request(), 'wrong'), /Exact immutable original proof/);
});

test('historical verification rejects wrong returned proof hash', async () => {
  globalThis.fetch = async () => respond({
    status: 'target_assertion_reverified_candidate_only',
    engagement_id: 'eng-test', flow_id: 'flow-test',
    source_task_id: 'task-source', target_task_id: 'task-target',
    proof_sha256: 'c'.repeat(64), target_controlled_signature_verified: true,
    independent_target_authority_verified: true,
    finding_verified: false, authorization_violation_verified: false,
    report_release_approved: false,
  });
  await assert.rejects(() => target.submitTargetAssertion(request(), 'b'.repeat(64)), /Historical target authority source digest/);
});

test('unverified operator and malformed task tuple never POST', async () => {
  api.signOut();
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('should not contact'); };
  await assert.rejects(() => target.submitTargetAssertion(request()), /Verified senior bearer/);
  assert.equal(called, false);
});

test('mounted review component never promises finding verification', () => {
  const markup = renderToStaticMarkup(createElement(panel.TargetAuthorityReviewPanel, {
    engagement: { session_id: 'eng-test', phase: 'reconnaissance' },
    flow: { id: 'flow-test', engagement_id: 'eng-test', status: 'running', revision: 1 },
  }));
  assert.match(markup, /target-authority-review/);
  assert.match(markup, /candidate only/i);
  assert.doesNotMatch(markup, /finding verified: yes/i);
});
