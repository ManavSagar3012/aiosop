import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
let vite;
let authAudit;

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true },
  });
  authAudit = await vite.ssrLoadModule('/src/pages/AuthAudit.tsx');
});

after(async () => {
  await vite?.close();
});

test('graph validated flag, model confidence and severity cannot manufacture enforcement', () => {
  const lead = authAudit.graphFindingAsUnverifiedControl({
    title: 'Possible IDOR', endpoint_id: '/api/objects/123',
    validated: true, status: 'verified', confidence: 0.99,
    severity: 'critical', role_required: 'Admin',
  });
  assert.deepEqual(lead, {
    endpoint: '/api/objects/123', workflow: 'Possible IDOR',
    roleRequired: 'Admin', observedEnforcement: 'UNKNOWN', confidence: 0.99,
  });
  assert.equal(authAudit.graphFindingAsUnverifiedControl(null).observedEnforcement, 'UNKNOWN');
  assert.equal(authAudit.graphFindingAsUnverifiedControl({ confidence: Infinity }).confidence, 0);
  assert.equal(authAudit.graphFindingAsUnverifiedControl({ severity: 'high' }).roleRequired, 'Unverified');
});

test('mounted authorization audit has no synthetic access percentages or fabricated bypass', () => {
  const page = readFileSync(fileURLToPath(new URL('../src/pages/AuthAudit.tsx', import.meta.url)), 'utf8');
  assert.doesNotMatch(page, /'98%'|'12%'|'BFLA Detected'/);
  assert.match(page, /authorization_violation_verified|Authorization roles, effective access percentages/);
  assert.doesNotMatch(page, /f\.status === 'verified'\s*\?\s*'ENFORCED'/);
});
