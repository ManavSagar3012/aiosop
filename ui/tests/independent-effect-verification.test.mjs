import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const service = readFileSync(new URL('../src/services/candidateFindingReviews.ts', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/components/flows/CandidateFindingReviewPanel.tsx', import.meta.url), 'utf8');
const router = readFileSync(new URL('../../src/ai_osop/api/routers/verified_finding_reviews.py', import.meta.url), 'utf8');

test('independent observer action is distinct from old UNKNOWN-only qualification', () => {
  assert.match(service, /verifyIndependent\(/);
  assert.match(service, /finding-effect-verifications/);
  assert.match(service, /qualificationId\.test\(body\.qualification_id\)/);
  assert.match(service, /sha\.test\(body\.qualification_sha256\)/);
  assert.match(service, /expected_qualification_revision < 1/);
  assert.match(service, /verdict\.report_release_approved !== false/);
  assert.match(service, /verdict\.finding_release_eligible !== false/);
  assert.match(router, /fetch_independent_target_effect_signed_receipt/);
  assert.match(router, /issue_independent_target_effect_challenge/);
  assert.match(router, /admit_independent_target_effect_verification/);
});

test('signed observation and nonce never originate in browser request', () => {
  const action = service.slice(service.indexOf('async verifyIndependent('));
  assert.doesNotMatch(action, /observer_claims_json\s*:/);
  assert.doesNotMatch(action, /observer_signature_b64url\s*:/);
  assert.doesNotMatch(action, /expected_nonce\s*:/);
  assert.doesNotMatch(action, /finding_verified\s*:\s*true/);
  assert.match(action, /credentials: 'omit'/);
  assert.match(action, /redirect: 'error'/);
  assert.match(action, /cache: 'no-store'/);
  assert.match(panel, /liveAcknowledged/);
  assert.match(panel, /effectSource\.source !== JSON\.stringify\(request\)/);
  assert.match(panel, /report release: NOT APPROVED/i);
});
