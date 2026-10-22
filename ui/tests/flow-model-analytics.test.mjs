import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let api;
let flows;
let analytics;

const payload = {
  engagement_id: 'eng-bounded', flow_id: 'flow-bounded',
  source: 'postgresql_task_attributed_model_ledger',
  attribution: 'same_tenant_task_flow_join_only',
  unattributed_model_calls_included: false,
  groups: [], group_count: 0, calls: 0, unknown_outcome_calls: 0,
  unpriced_calls: 0, complete_for_attributed_calls: true,
  provider_native_cost_verified: false, provider_native_hard_cap_verified: false,
  external_execution_outcome_verified: false,
};

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  flows = await vite.ssrLoadModule('/src/services/flows.ts');
  analytics = await vite.ssrLoadModule('/src/components/flows/FlowModelAnalyticsPanel.tsx');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

function reply(data, status = 200) {
  return {
    ok: status === 200, status,
    headers: { get: () => 'application/json' },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

test('real Flow service sends bearer-only read and never triggers model execution', async () => {
  api.signOut();
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ url: String(url), init, pathname });
    if (pathname === '/auth/me') {
      return reply({ sub: 'review-operator', role: 'operator', exp: null });
    }
    if (pathname === '/flows/flow-bounded/model-analytics') return reply(payload);
    throw new Error('Unexpected destination ' + pathname);
  };
  await api.signIn('local-model-analytics-fixture-bearer');
  const result = await flows.flowApi.getModelAnalytics('flow-bounded');
  assert.deepEqual(result, payload);
  const analyticCall = calls.find(call => call.pathname.includes('/model-analytics'));
  assert.ok(analyticCall);
  assert.equal(analyticCall.init.method, 'GET');
  assert.equal(analyticCall.init.cache, 'no-store');
  assert.equal(analyticCall.init.credentials, 'omit');
  assert.equal(analyticCall.init.redirect, 'error');
  assert.ok(analyticCall.init.headers.Authorization.includes('local-model-analytics-fixture-bearer'));
  assert.ok(!analyticCall.url.includes('bearer') && !analyticCall.init.body);
  assert.equal(calls.filter(call => call.pathname.includes('/model-analytics')).length, 1);
});

test('operator Flow usage panel is mounted and explicitly non-certifying', () => {
  const html = renderToStaticMarkup(createElement(
    analytics.FlowModelAnalyticsPanel,
    { engagementId: 'eng-bounded', flowId: 'flow-bounded', revision: 1 },
  ));
  assert.match(html, /Flow model usage/);
  assert.match(html, /not provider-certified invoices/);
  assert.match(html, /REFRESH FLOW MODEL USAGE/);
  assert.doesNotMatch(html, /model inference started|provider-verified cost: YES/);

  const page = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');
  assert.match(page, /<FlowModelAnalyticsPanel/);
  assert.match(page, /engagementId=\{selectedFlow\.engagement_id\}/);
  assert.match(page, /flowId=\{selectedFlow\.id\}/);
});
