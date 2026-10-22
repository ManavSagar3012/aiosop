import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/pages/Administration.tsx', import.meta.url), 'utf8');

test('administration does not invent connected servers, credentials or signed verification', () => {
  assert.match(source, /useState<MCPServerInfo\[\]>\(\[\]\)/);
  assert.match(source, /Registered Model Context Protocol Servers \(not target-verified\)/);
  assert.match(source, /presence and serving status UNKNOWN/i);
  assert.doesNotMatch(source, /success_count: 42|success_count: 28|simulated: 9ms|Server managed — verified|STRICT \(100% LIVE\)/);
  assert.match(source, /NOT ESTABLISHED/);
  assert.match(source, /Cross-engagement pattern sharing is NOT established/);
  assert.doesNotMatch(source, /REQUEUE ALL PENDING/);
});

test('global administration health has authenticated read-only transport, redaction and no blind success', () => {
  assert.match(source, /\$\{API_BASE\}\/system\/mcp\/health/);
  assert.match(source, /headers, cache: 'no-store', credentials: 'omit', redirect: 'error'/);
  assert.match(source, /host: 'redacted', port: 0/);
  assert.match(source, /Hidden \(server managed\)/);
  assert.match(source, /setServers\(\[\]\)/);
  assert.match(source, /currentOperator\(\)\?\.sub !== principal\.sub/);
  assert.doesNotMatch(source, /'\/api\/v1\/system\/mcp\/health'|Keep illustrative defaults/);
});

test('MCP control operations are authenticated and never fabricate ping/reset ACK', () => {
  assert.match(source, /\$\{API_BASE\}\/system\/mcp\/\$\{encodeURIComponent\(serverId\)\}\/ping/);
  assert.match(source, /\$\{API_BASE\}\/system\/mcp\/\$\{encodeURIComponent\(serverId\)\}\/reset-circuit/);
  assert.match(source, /identity\?\.role !== 'senior_operator'/);
  assert.match(source, /window\.confirm\(`/);
  assert.match(source, /outcome UNKNOWN/);
  assert.doesNotMatch(source, /Circuit breaker reset \(simulated\)|Ping.*completed \(simulated/);
});
