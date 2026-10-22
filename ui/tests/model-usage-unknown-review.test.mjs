import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const api = readFileSync(
  new URL('../src/services/supervision.ts', import.meta.url), 'utf8',
);
const panel = readFileSync(
  new URL('../src/components/flows/SupervisionPanel.tsx', import.meta.url), 'utf8',
);

test('unreconciled provider calls are read-only and authenticated', () => {
  assert.match(api, /unresolvedModelCalls:/);
  assert.match(api, /model-usage\/unreconciled/);
  assert.match(api, /authHeaders/);
  assert.match(api, /invoice_reconciled: false/);
  assert.match(api, /safe_to_retry: false/);
});

test('operator panel cannot present unknown paid calls as free or invoice reconciled', () => {
  assert.match(panel, /UNRESOLVED PROVIDER CALLS — NO AUTOMATIC RETRY/);
  assert.match(panel, /billed cost UNKNOWN/);
  assert.match(panel, /Invoice reconciliation remains unverified/);
  assert.match(panel, /unresolvedCallsResult\.value\.safe_to_retry === false/);
});
