import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const engagementId = 'eng-candidate-evidence';
const flowId = 'flow-candidate-evidence';
const findingId = 'finding-candidate-1';
let vite, api, service, panel;
let calls = [];
let reply;
let policy;

function candidate() {
  return {
    engagement_id: engagementId,
    finding_id: findingId,
    flow_id: flowId,
    flow_revision: 7,
    authorization_version: 3,
    verification_state: 'candidate_unverified',
    finding_verified: false,
    independent_target_effect_verified: false,
    artifacts: [{
      artifact_id: 'ev-candidate-1',
      source_task_id: 'task-signed-candidate-1',
      merkle_leaf_sha256: 'a'.repeat(64),
      verification_state: 'candidate_unverified',
      independent_target_effect_verified: false,
    }],
  };
}

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
  reply = candidate();
  policy = { status: 'active', version: 3, key_id: 'key-test', expires_at: null,
    policy_sha256: 'b'.repeat(64), remote_execution_outcome: 'unknown' };
  calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ url: String(url), pathname, options });
    if (pathname === '/auth/me') return { ok: true, status: 200,
      json: async () => ({ sub: 'senior-owner', role, exp: null }) };
    if (pathname.endsWith('/authorization/status')) return { ok: true, status: 200,
      json: async () => structuredClone(policy) };
    if (pathname.endsWith('/candidate-evidence-artifacts')) return { ok: true, status: 200,
      json: async () => structuredClone(reply) };
    throw new Error('Unexpected endpoint');
  };
  await api.signIn('test-candidate-token');
}

test('actual FlowOperations selected Flow mounts only inert candidate read panel and preserves report review', async () => {
  await signIn();
  const html = renderToStaticMarkup(createElement(panel.CandidateEvidenceArtifactPanel,
    { engagementId, flowId, revision: 7, flowStatus: 'running' }));
  assert.match(html, /Signed candidate evidence — digest-only operator readback/);
  assert.match(html, /Candidate finding ID/);
  assert.match(html, /READ CANDIDATE EVIDENCE \(GET ONLY\)/);
  assert.match(html, /do NOT verify a vulnerability/);
  assert.doesNotMatch(html, /PRIVATE-WITNESS|access_token|Bearer test-candidate-token/);

  const mounted = readFileSync(fileURLToPath(new URL('../src/pages/FlowOperations.tsx', import.meta.url)), 'utf8');
  assert.match(mounted, /import \{ CandidateEvidenceArtifactPanel \}/);
  assert.match(mounted, /<CandidateEvidenceArtifactPanel/);
  assert.match(mounted, /engagementId=\{selectedFlow\.engagement_id\}/);
  assert.match(mounted, /flowId=\{selectedFlow\.id\}/);
  assert.match(mounted, /revision=\{selectedFlow\.revision\}/);
  assert.match(mounted, /flowStatus=\{selectedFlow\.status\}/);
  assert.match(mounted, /<SignedReportOperatorPanel/);
  assert.match(mounted, /signedReportsApi\.reviewExactSnapshot/);

  const panelSource = readFileSync(new URL('../src/components/flows/CandidateEvidenceArtifactPanel.tsx', import.meta.url), 'utf8');
  assert.match(panelSource, /supervisionApi\.authorizationStatus\(engagementId\)/);
  assert.match(panelSource, /const checked = await supervisionApi\.authorizationStatus/);
  assert.match(panelSource, /checked\.status !== 'active'/);
  assert.match(panelSource, /requestId !== epoch\.current/);
  assert.match(panelSource, /subscribeOperator/);
  assert.doesNotMatch(panelSource, /dangerouslySetInnerHTML|document\.write|<iframe|approveFinding|verifyFinding/);
});

test('senior service issues precisely bounded signed-Flow GET and copies only candidate-only public fields', async () => {
  await signIn();
  const result = await service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3);
  assert.deepEqual(result, candidate());
  assert.equal(result.verification_state, 'candidate_unverified');
  assert.equal(result.finding_verified, false);
  assert.equal(result.independent_target_effect_verified, false);
  const network = calls.filter(call => call.pathname.endsWith('/candidate-evidence-artifacts'));
  assert.equal(network.length, 1);
  const sent = network[0];
  assert.equal(sent.pathname,
    `/engagements/${engagementId}/findings/${findingId}/candidate-evidence-artifacts`);
  const destination = new URL(sent.url);
  assert.deepEqual([...destination.searchParams.entries()], [
    ['flow_id', flowId], ['expected_flow_revision', '7'],
    ['expected_authorization_version', '3'],
  ]);
  assert.equal(sent.options.method, 'GET');
  assert.equal(sent.options.cache, 'no-store');
  assert.equal(sent.options.credentials, 'omit');
  assert.equal(sent.options.redirect, 'error');
  assert.equal(sent.options.referrerPolicy, 'no-referrer');
  assert.equal(sent.options.headers.Authorization, 'Bearer test-candidate-token');
  assert.equal(sent.options.body, undefined);
  assert.doesNotMatch(sent.url, /token|secret|body|header|witness|replay_recipe/);
});

test('non-senior or malformed identifiers and signer versions fail locally without network', async () => {
  await signIn('operator');
  await assert.rejects(service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3), /senior/);
  assert.equal(calls.length, 1);
  await signIn();
  const wrong = [
    ['eng-../foreign', findingId, flowId, 7, 3],
    [engagementId, 'finding?access_token=x', flowId, 7, 3],
    [engagementId, '', flowId, 7, 3],
    [engagementId, 'x'.repeat(129), flowId, 7, 3],
    [engagementId, findingId, 'flow-../foreign', 7, 3],
    [engagementId, findingId, flowId, -1, 3],
    [engagementId, findingId, flowId, 1.5, 3],
    [engagementId, findingId, flowId, 7, 0],
    [engagementId, findingId, flowId, 7, Number.MAX_SAFE_INTEGER + 1],
  ];
  for (const args of wrong) {
    await assert.rejects(service.readCandidateEvidenceArtifacts(...args), /bounded candidate identifiers/);
  }
  assert.equal(calls.length, 1);
});

test('strict exact schema rejects extra raw URL/headers/body/private provenance fields', async () => {
  await signIn();
  const extras = [
    { raw_target_url: 'https://example.test/private?token=secret' },
    { replay_recipe: { private_request_body: 'secret' } },
    { provider_receipt: { authorization: 'Bearer private' } },
    { human_report_release_approved: true },
    { witness_body: 'private' },
    { findings: ['verified'] },
  ];
  for (const extra of extras) {
    reply = { ...candidate(), ...extra };
    await assert.rejects(
      service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3), /private fields/,
    );
  }
  for (const extra of [
    { response_body: 'secret' }, { request_headers: { Authorization: 'Bearer private' } },
    { target_url: 'https://private.test/' }, { verified: true },
  ]) {
    reply = candidate();
    reply.artifacts[0] = { ...reply.artifacts[0], ...extra };
    await assert.rejects(
      service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3), /private fields/,
    );
  }
});

test('fake verified claims, swapped tenant/Flow/source and malformed Merkle digests never surface', async () => {
  await signIn();
  const corruptions = [
    { engagement_id: 'eng-other' }, { finding_id: 'finding-other' },
    { flow_id: 'flow-other' }, { flow_revision: 6 },
    { authorization_version: 4 },
    { verification_state: 'VERIFIED' }, { finding_verified: true },
    { independent_target_effect_verified: true },
    { artifacts: 'private' }, { artifacts: Array.from({ length: 101 }, () => candidate().artifacts[0]) },
  ];
  for (const fields of corruptions) {
    reply = { ...candidate(), ...fields };
    await assert.rejects(
      service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3), /Stale or falsely verified/,
    );
  }
  const badArtifactFields = [
    { artifact_id: 'ev-../escape' }, { source_task_id: 'task-foreign/private' },
    { merkle_leaf_sha256: 'A'.repeat(64) }, { merkle_leaf_sha256: 'short' },
    { verification_state: 'VERIFIED' }, { independent_target_effect_verified: true },
  ];
  for (const field of badArtifactFields) {
    reply = candidate();
    reply.artifacts[0] = { ...reply.artifacts[0], ...field };
    await assert.rejects(
      service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3), /unverified source artifact/,
    );
  }
  reply = candidate();
  reply.artifacts = [reply.artifacts[0], { ...reply.artifacts[0] }];
  await assert.rejects(
    service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3), /duplicate/,
  );
});

test('authorization rotation and operator logout during GET invalidate the received response', async () => {
  await signIn();
  const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const response = await original(url, options);
    if (new URL(String(url)).pathname.endsWith('/candidate-evidence-artifacts')) api.signOut();
    return response;
  };
  await assert.rejects(
    service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3),
    /Senior operator changed/,
  );
  await signIn();
  reply = candidate();
  reply.authorization_version = 99;
  await assert.rejects(
    service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3),
    /Stale or falsely verified/,
  );
});

test('unavailable/revoked candidate endpoint cannot be displayed as candidate success', async () => {
  await signIn();
  const normal = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (new URL(String(url)).pathname.endsWith('/candidate-evidence-artifacts')) {
      return { ok: false, status: 409, json: async () => ({ private_body: 'secret' }) };
    }
    return normal(url, options);
  };
  await assert.rejects(
    service.readCandidateEvidenceArtifacts(engagementId, findingId, flowId, 7, 3),
    /unavailable \(HTTP 409\)/,
  );
  assert.ok(calls.every(call => !call.url.includes('test-candidate-token')));
});
