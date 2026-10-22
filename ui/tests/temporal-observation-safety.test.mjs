import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const service = readFileSync(
  new URL('../src/services/supervision.ts', import.meta.url), 'utf8',
);
const panel = readFileSync(
  new URL('../src/components/flows/SupervisionPanel.tsx', import.meta.url), 'utf8',
);

test('operator observes existing Temporal workflow through authenticated POST, no restart', () => {
  assert.match(service, /observeTemporal:\s*\(engagementId: string, taskId: string\)/);
  assert.match(service, /\/temporal\/observe/);
  assert.match(service, /authHeaders/);
  assert.doesNotMatch(service, /temporal\/start/);
});

test('Temporal observation can never be displayed as verified remote termination', () => {
  assert.match(panel, /external_effect_status !== 'unknown'/);
  assert.match(panel, /safe_to_retry !== false/);
  assert.match(panel, /durable_status_changed !== false/);
  assert.match(panel, /Automatic retry prohibited/);
  assert.match(panel, /CHECK EXISTING WORKFLOW \(NO REPLAY\)/);
  assert.match(panel, /\['dispatching', 'dispatch_unknown'\]/);
});
