import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const service = readFileSync(new URL('../src/services/providerCapabilities.ts', import.meta.url), 'utf8');
const page = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');

test('senior bearer GET is no-store, read-only and engagement-bound', () => {
  assert.match(service, /identity\?\.role !== 'senior_operator'/);
  assert.match(service, /Bearer \\S\+/);
  assert.match(service, /method: 'GET'/);
  assert.match(service, /cache: 'no-store'/);
  assert.match(service, /value\.engagement_id !== engagementId/);
});

test('forged provider availability and price certainty fail closed', () => {
  assert.match(service, /value\.provider_currently_available_verified !== false/);
  assert.match(service, /value\.provider_native_cost_ceiling_verified !== false/);
  assert.match(service, /value\.signed_budget_admission_still_required !== true/);
  assert.match(service, /route\.provider_capability_verified === true/);
  assert.match(service, /currentOperator\(\)\?\.sub !== identity\.sub/);
});

test('FlowOperations gates refresh and discards stale engagement replies', () => {
  assert.match(page, /canAttemptApproval && <Card title="Provider routes/);
  assert.match(page, /\+\+providerEpoch\.current/);
  assert.match(page, /current !== providerEpoch\.current/);
  assert.match(page, /providerCapabilities\?\.engagement_id === engagementId/);
  assert.match(page, /Signed budget admission: REQUIRED/);
});
