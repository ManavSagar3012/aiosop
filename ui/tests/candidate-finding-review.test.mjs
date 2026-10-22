import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const service = readFileSync(new URL('../src/services/candidateFindingReviews.ts', import.meta.url), 'utf8');
const component = readFileSync(new URL('../src/components/flows/CandidateFindingReviewPanel.tsx', import.meta.url), 'utf8');
const flow = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');

test('manual signed candidate reviews bind the exact server-owned source tuple', () => {
  for (const name of ['original_source_task_id', 'source_task_id', 'target_task_id',
    'proof_sha256', 'audit_sha256', 'report_source_evidence_sha256',
    'expected_authorization_version', 'expected_flow_revision', 'expected_review_revision']) {
    assert.ok(service.includes(name), `missing ${name}`);
  }
  assert.match(service, /Set\(\[body\.original_source_task_id, body\.source_task_id, body\.target_task_id\]\)\.size === 3/);
  assert.match(service, /currentOperator\(\)\?\.role !== 'senior_operator'/);
  assert.match(service, /credentials: 'omit'/);
  assert.match(service, /redirect: 'error'/);
  assert.match(service, /cache: 'no-store'/);
});

test('candidate UI mounts on real Flow and never claims verified or released', () => {
  assert.match(flow, /<CandidateFindingReviewPanel/);
  assert.match(component, /I understand this is only a signed-source candidate review/);
  assert.match(component, /Vulnerability verified: NO\. Senior report release approved: NO\./);
  assert.match(component, /Reverify existing candidate \(GET\)/);
  assert.match(component, /Record explicitly reviewed candidate \(POST\)/);
  assert.match(service, /result\.finding_verified !== false \|\| result\.report_release_approved !== false/);
  assert.doesNotMatch(service, /dev-token|[?&]token=/);
});

test('senior qualification records UNKNOWN-only effect with exact reviewed identity', () => {
  for (const name of [
    'review_decision_id', 'review_decision_sha256', 'expected_qualification_revision',
    'qualifyUnknown', 'readEffectUnknown',
  ]) assert.ok(service.includes(name), `missing signed UNKNOWN qualifier ${name}`);
  assert.match(service, /result\.finding_verified !== false \|\| result\.report_release_approved !== false/);
  assert.match(service, /reply\.status !== 'UNKNOWN' \|\| reply\.independent_target_effect_verified !== false/);
  assert.match(service, /reviewDecision\.test\(body\.review_decision_id\)/);
  assert.match(component, /reviewSource\?\.source !== JSON\.stringify\(request\)/);
  assert.match(component, /Explicit UNKNOWN-only evidence qualification acknowledgement/);
  assert.match(component, /Record unresolved target-effect qualification \(POST\)/);
  assert.match(component, /Reverify target-effect UNKNOWN \(GET\)/);
  assert.match(component, /independently deployed owner-of-record verifier is still required/i);
  assert.doesNotMatch(service, /dev-token|[?&]token=/);
});
