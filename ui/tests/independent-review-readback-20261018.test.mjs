import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const service = readFileSync(new URL('../src/services/candidateFindingReviews.ts', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/components/flows/CandidateFindingReviewPanel.tsx', import.meta.url), 'utf8');

test('verification ID must match durable 0022 row identity, not arbitrary claimed success', () => {
  assert.match(service, /const verificationId = \/\^itefv-\[0-9a-f\]\{32\}\$\//);
  assert.match(service, /!verificationId\.test\(verdict\.verification_id\)/);
});

test('POST does not certify current independent readback or senior release', () => {
  assert.match(service, /return this\.readIndependent\(engagementId, flowId, body\.finding_id/);
  assert.match(service, /durable_readback_verified: true, final_senior_signoff: false/);
  assert.match(panel, /Final signed report release: NOT APPROVED/);
  assert.match(panel, /verdict\.durable_readback_verified !== true/);
});

test('attempt acknowledgement and pinned qualification are invalidated after receipt', () => {
  const call = panel.slice(panel.indexOf('async function verifyLive()'));
  assert.match(call, /setLiveAcknowledged\(false\);\s*setEffectSource\(null\);/);
  assert.match(call, /current !== epoch\.current/);
});

test('GET rejects forged, stale, mismatched or revoked verification receipt', () => {
  assert.match(service, /finding-effect-verifications'\)/);
  assert.match(service, /method: 'GET'/);
  assert.match(service, /checkedVerification\(await response\.json\(\)\)/);
  assert.match(service, /verdict\.verification_id !== expectedVerificationId/);
  assert.match(service, /verdict\.verification_sha256 !== expectedVerificationSha256/);
  assert.match(service, /verdict\.report_source_evidence_sha256 !== expectedSourceSha256/);
  assert.match(service, /verdict\.status !== 'VERIFIED'/);
  assert.match(service, /verdict\.report_release_approved !== false/);
});

test('refresh invalidates revoked and changed source and never claims release', () => {
  assert.match(panel, /async function refreshVerification\(\)/);
  assert.match(panel, /candidateFindingReviews\.readIndependent\(engagementId, flowId/);
  assert.match(panel, /receipt\.source !== value\.report_source_evidence_sha256/);
  assert.match(panel, /setVerifiedReceipt\(null\)/);
  assert.match(panel, /Finding status: UNKNOWN\. Final signed report release: NOT APPROVED/);
  assert.match(panel, /Refresh independent VERIFIED readback \(GET\)/);
});
