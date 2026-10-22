import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const ENG = 'eng-candidate-write';
const FLOW = 'flow-signed-approved';
const FINDING = 'finding-provenance';
const HASH = 'a'.repeat(64);
let vite, api, service, panel;
let calls = [];
let responseBody;
let failStatus;
let responseHook;

const receipt = () => ({
  status: 'candidate_evidence_recorded_unverified',
  artifact_id: 'ev-from-nav-1', merkle_leaf_sha256: HASH,
  finding_verified: false, independent_target_effect_verified: false,
  safe_to_automatically_retry: false,
});
function readback(taskId) {
  return {
    engagement_id: ENG, finding_id: FINDING, flow_id: FLOW,
    flow_revision: 7, authorization_version: 3,
    verification_state: 'candidate_unverified',
    finding_verified: false, independent_target_effect_verified: false,
    artifacts: [{ artifact_id: 'ev-from-nav-1', source_task_id: taskId,
      merkle_leaf_sha256: HASH, verification_state: 'candidate_unverified',
      independent_target_effect_verified: false }],
  };
}
const input = (taskId, overrides = {}) => ({
  engagementId: ENG, findingId: FINDING, flowId: FLOW,
  sourceTaskId: taskId, expectedFlowRevision: 7,
  expectedAuthorizationVersion: 3, explicitHumanConfirmation: true,
  ...overrides,
});

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/candidateEvidenceArtifacts.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/CandidateEvidenceArtifactPanel.tsx');
});
after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

async function signIn(role = 'senior_operator') {
  api.signOut();
  calls = [];
  responseBody = receipt();
  failStatus = 200;
  responseHook = null;
  globalThis.fetch = async (url, options = {}) => {
    const target = new URL(String(url));
    calls.push({ url: String(url), pathname: target.pathname, method: options.method ?? 'GET', options });
    if (target.pathname === '/auth/me') {
      return { ok: true, status: 200, json: async () => ({ sub: 'reviewer-1', role, exp: null }) };
    }
    if (target.pathname.endsWith('/from-signed-navigation')) {
      if (responseHook) await responseHook();
      return { ok: failStatus === 200, status: failStatus,
        json: async () => structuredClone(responseBody) };
    }
    if (target.pathname.endsWith('/candidate-evidence-artifacts')) {
      const task = target.searchParams.get('unused') || 'task-approved-1';
      return { ok: true, status: 200, json: async () => readback(task) };
    }
    throw new Error('Unexpected network path: ' + target.pathname);
  };
  await api.signIn('test-signed-candidate-bearer');
}

function posts() { return calls.filter(call => call.method === 'POST'); }

test('signed-navigation association POST sends exactly four signed references and never a browser request', async () => {
  await signIn();
  const sent = await service.associateCompletedSignedNavigationCandidate(input('task-approved-1'));
  assert.deepEqual(sent, receipt());
  assert.equal(sent.safe_to_automatically_retry, false);
  assert.equal(sent.finding_verified, false);
  assert.equal(sent.independent_target_effect_verified, false);
  assert.equal(posts().length, 1);
  const call = posts()[0];
  assert.equal(call.pathname,
    `/engagements/${ENG}/findings/${FINDING}/candidate-evidence-artifacts/from-signed-navigation`);
  assert.deepEqual(JSON.parse(call.options.body), {
    flow_id: FLOW, source_task_id: 'task-approved-1',
    expected_flow_revision: 7, expected_authorization_version: 3,
  });
  assert.deepEqual(Object.keys(JSON.parse(call.options.body)).sort(), [
    'expected_authorization_version', 'expected_flow_revision', 'flow_id', 'source_task_id',
  ]);
  assert.equal(call.options.headers.Authorization, 'Bearer test-signed-candidate-bearer');
  assert.equal(call.options.headers['Content-Type'], 'application/json');
  assert.equal(call.options.cache, 'no-store');
  assert.equal(call.options.credentials, 'omit');
  assert.equal(call.options.redirect, 'error');
  assert.equal(call.options.referrerPolicy, 'no-referrer');
  assert.doesNotMatch(call.url + call.options.body, /Bearer test-signed-candidate-bearer|raw_body|request_headers|target_url|replay_recipe|witness/);
  assert.equal(calls.filter(call => /browser|execute|navigate|release/.test(call.pathname)).length, 0);
  // Separate server GET is authoritative about whether this recorded receipt exists.
  const independent = await service.readCandidateEvidenceArtifacts(ENG, FINDING, FLOW, 7, 3);
  assert.deepEqual(independent.artifacts[0], {
    artifact_id: sent.artifact_id, merkle_leaf_sha256: sent.merkle_leaf_sha256,
    source_task_id: 'task-approved-1', verification_state: 'candidate_unverified',
    independent_target_effect_verified: false,
  });
  assert.equal(calls.filter(call => call.pathname.endsWith('/candidate-evidence-artifacts')).length, 1);
});

test('UI separates explicit human POST checkbox/confirm from GET and forces exact successful GET readback', async () => {
  await signIn();
  const markup = renderToStaticMarkup(createElement(panel.CandidateEvidenceArtifactPanel,
    { engagementId: ENG, flowId: FLOW, revision: 7, flowStatus: 'running' }));
  assert.match(markup, /READ CANDIDATE EVIDENCE \(GET ONLY\)/);
  assert.match(markup, /ASSOCIATE EXISTING SIGNED NAVIGATION/);
  assert.match(markup, /ALREADY COMPLETED, human-approved signed navigation/);
  assert.match(markup, /Existing signed navigation source Task ID/);
  assert.match(markup, /type="checkbox"/);
  assert.match(markup, /ASSOCIATE EXISTING SIGNED NAVIGATION — HUMAN CONFIRMATION REQUIRED/);
  assert.doesNotMatch(markup, /https:\/\/|private-bearer-value/);

  const ui = readFileSync(new URL('../src/components/flows/CandidateEvidenceArtifactPanel.tsx', import.meta.url), 'utf8');
  assert.match(ui, /window\.confirm\(/);
  assert.match(ui, /!associateConfirmed/);
  assert.match(ui, /sourceTaskId/);
  assert.match(ui, /attemptedAssociations\.current\.add\(tuple\)/);
  assert.match(ui, /const recorded = await associateCompletedSignedNavigationCandidate\(/);
  assert.match(ui, /const result = await readCandidateEvidenceArtifacts\(/);
  assert.match(ui, /artifact\.artifact_id === recorded\.artifact_id/);
  assert.match(ui, /artifact\.merkle_leaf_sha256 === recorded\.merkle_leaf_sha256/);
  assert.match(ui, /artifact\.source_task_id === currentSource/);
  assert.match(ui, /checked\.status !== 'active' \|\| checked\.version !== policy\.version/);
  assert.match(ui, /UNKNOWN: POST may have committed/);
  assert.match(ui, /Manually select READ CANDIDATE EVIDENCE/);
  assert.match(ui, /setReadback\(null\)/);
  assert.doesNotMatch(ui, /dangerouslySetInnerHTML|document\.write|signedReportsApi|fetch\(.+browser/);
  const flow = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');
  assert.match(flow, /<CandidateEvidenceArtifactPanel/);
  assert.match(flow, /<SignedReportOperatorPanel/);
});

test('stale/invalid source, signed versions, missing confirmation and junior user deny before POST', async () => {
  await signIn('operator');
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(input('task-junior-1')), /Explicit senior/);
  assert.equal(posts().length, 0);
  await signIn();
  const variants = [
    { explicitHumanConfirmation: false }, { expectedFlowRevision: -1 },
    { expectedFlowRevision: 2.25 }, { expectedAuthorizationVersion: 0 },
    { expectedAuthorizationVersion: Number.MAX_SAFE_INTEGER + 1 },
    { sourceTaskId: 'invalid' }, { sourceTaskId: 'task-../outside' },
    { findingId: 'finding/foreign' }, { engagementId: 'eng-../foreign' },
    { flowId: 'flow-../other' },
  ];
  for (const variant of variants) {
    await assert.rejects(
      service.associateCompletedSignedNavigationCandidate(input('task-rejected-1', variant)),
      /Explicit senior/,
    );
  }
  assert.equal(posts().length, 0);
});

test('forged verified success/private fields are refused, and ambiguous receipt is permanently fenced', async () => {
  await signIn();
  const adversarial = [
    { finding_verified: true }, { independent_target_effect_verified: true },
    { safe_to_automatically_retry: true },
    { status: 'verified_finding' }, { merkle_leaf_sha256: 'bad' },
    { artifact_id: 'ev-../foreign' },
    { private_target_url: 'https://example.test/private?token=do-not-display' },
    { private_headers: { Authorization: 'Bearer secret' } },
    { raw_witness_body: 'secret' },
  ];
  for (let i = 0; i < adversarial.length; i++) {
    responseBody = { ...receipt(), ...adversarial[i] };
    const request = input(`task-forged-${i}`);
    await assert.rejects(service.associateCompletedSignedNavigationCandidate(request));
    assert.equal(service.signedNavigationAssociationAlreadyAttempted(
      ENG, FINDING, FLOW, request.sourceTaskId), true);
    const before = posts().length;
    await assert.rejects(
      service.associateCompletedSignedNavigationCandidate(request), /already attempted/,
    );
    assert.equal(posts().length, before);
  }
});

test('repeated HTTP 503 never auto-retries, manual GET remains available and private errors stay hidden', async () => {
  await signIn();
  failStatus = 503;
  responseBody = { private_request: 'Bearer top-secret' };
  const association = input('task-503-uncertain');
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(association), error => {
    assert.match(error.message, /outcome UNKNOWN; manual GET readback required/);
    assert.doesNotMatch(error.message, /top-secret/);
    return true;
  });
  assert.equal(posts().length, 1);
  for (let i = 0; i < 4; i++) {
    await assert.rejects(service.associateCompletedSignedNavigationCandidate(association), /already attempted/);
    assert.equal(posts().length, 1);
  }
  const recovered = await service.readCandidateEvidenceArtifacts(ENG, FINDING, FLOW, 7, 3);
  assert.equal(recovered.verification_state, 'candidate_unverified');
  assert.equal(recovered.finding_verified, false);
  assert.equal(posts().length, 1);
});

test('network timeout, missing success body, and changed operator leave UNKNOWN without replay', async () => {
  await signIn();
  responseHook = async () => { throw new Error('Authorization: Bearer private'); };
  const timeoutInput = input('task-timeout-unknown');
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(timeoutInput), error => {
    assert.match(error.message, /outcome UNKNOWN; manual GET readback/);
    assert.doesNotMatch(error.message, /private|Authorization/);
    return true;
  });
  assert.equal(posts().length, 1);
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(timeoutInput), /already attempted/);
  assert.equal(posts().length, 1);

  responseHook = null;
  responseBody = { status: 'candidate_evidence_recorded_unverified' };
  const partialInput = input('task-partial-unknown');
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(partialInput), /public schema|private fields/);
  assert.equal(posts().length, 2);
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(partialInput), /already attempted/);

  responseBody = receipt();
  responseHook = async () => { api.signOut(); };
  const signedOut = input('task-logout-after-dispatch');
  await assert.rejects(service.associateCompletedSignedNavigationCandidate(signedOut), /operator changed/);
  assert.equal(posts().length, 3);
  assert.equal(service.signedNavigationAssociationAlreadyAttempted(ENG, FINDING, FLOW, signedOut.sourceTaskId), true);
});
