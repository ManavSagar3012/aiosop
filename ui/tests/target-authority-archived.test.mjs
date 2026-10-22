import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const service = readFileSync(new URL('../src/services/targetAuthority.ts', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/components/flows/TargetAuthorityReviewPanel.tsx', import.meta.url), 'utf8');

test('archived target authority read uses an exact GET without client-replayed evidence', () => {
  const body = service.slice(service.indexOf('export async function reverifyStoredTargetAssertion'));
  assert.match(body, /method: 'GET'/);
  assert.match(body, /authHeaders\(\{ Accept: 'application\/json' \}\)/);
  assert.match(body, /credentials: 'omit'/);
  assert.match(body, /redirect: 'error'/);
  assert.doesNotMatch(body, /method: 'POST'|body: JSON\.stringify/);
  assert.match(body, /row\.proof_sha256 !== proofSha256/);
});

test('archived authority remains candidate-only even with separately verified signed records', () => {
  assert.match(service, /row\.finding_verified !== false/);
  assert.match(service, /row\.authorization_violation_verified !== false/);
  assert.match(service, /row\.report_release_approved !== false/);
  assert.match(service, /\['UNKNOWN', 'candidate_only'\]/);
  assert.match(panel, /RECHECK ARCHIVED SIGNED SOURCE \(NO REUPLOAD\)/);
  assert.match(panel, /no finding or senior report release authorized/);
});
