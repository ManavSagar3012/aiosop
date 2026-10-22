import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const service = readFileSync(new URL('../src/services/operatorKnowledge.ts', import.meta.url), 'utf8');
const panel = readFileSync(new URL('../src/components/flows/OperatorKnowledgePanel.tsx', import.meta.url), 'utf8');
const page = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');

test('knowledge CRUD requires signed Flow authority and bearer-only API access', () => {
  assert.match(service, /expected_authorization_version/);
  assert.match(service, /expected_revision/);
  assert.match(service, /authHeaders\(/);
  assert.match(service, /credentials: 'omit'/);
  assert.match(service, /redirect: 'error'/);
  assert.doesNotMatch(service, /Bearer dev-token|[?&]token=/);
});

test('knowledge is explicit operator-owned content, not trusted agent instructions', () => {
  assert.match(panel, /inert, not agent-approved/);
  assert.match(panel, /does not make content trusted agent instructions/);
  assert.match(panel, /expected_document_revision|Save exact revision/);
  assert.match(page, /<OperatorKnowledgePanel/);
});

test('stale knowledge revision denial is not interpreted as success', () => {
  assert.match(service, /if \(!result\.ok\) throw new Error/);
  assert.match(service, /Number\.isSafeInteger\(doc\.revision\)/);
  assert.match(panel, /setError\(cause instanceof Error/);
});
