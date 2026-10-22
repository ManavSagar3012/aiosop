import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let auth;
let supervision;

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  supervision = await vite.ssrLoadModule('/src/services/supervision.ts');
});

after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

test('independent admin-provider observation is explicit read-only and never a model-call invoice', async () => {
  const calls = [];
  const verified = {
    source: 'openai_organization_costs_api',
    source_authenticated: true,
    source_scope: 'configured_openai_project',
    provider_cost_usd: '12.34', provider_cost_data_present: true,
    source_checked_at_utc: Math.floor(Date.now() / 1000), currency: 'USD',
    project_sha256: 'd'.repeat(64), pages: 1, buckets: 7, cost_lines: 1,
    provider_project_comparable_to_engagement: false,
    provider_project_exclusivity_verified: false,
    project_access_binding: 'server_configured_engagement',
    individual_call_cost_verified: false,
    provider_hard_cost_cap_verified: false,
    ledger_mutated: false, observation_recorded: true, safe_to_retry: false,
    execution_outcome: 'unknown',
  };
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/auth/me')) return {
      ok: true, json: async () => ({
        sub: 'independent-senior', role: 'senior_operator',
        exp: Math.floor(Date.now() / 1000) + 300,
      }),
    };
    return { ok: true, json: async () => verified };
  };
  await auth.signIn('operator-signed-bearer');
  const day = 86400;
  const end = Math.floor(Date.now() / 1000 / day) * day;
  const result = await supervision.supervisionApi.observeOpenAIProjectCosts(
    'eng-test-billing', end - 7 * day, end,
  );
  assert.equal(result.source_authenticated, true);
  assert.equal(result.individual_call_cost_verified, false);
  assert.equal(result.ledger_mutated, false);
  assert.equal(result.provider_project_exclusivity_verified, false);
  assert.equal(result.project_access_binding, 'server_configured_engagement');
  assert.equal(calls[1].url, auth.API_BASE
    + '/supervision/engagements/eng-test-billing/model-usage/provider-costs/openai/observe');
  assert.equal(calls[1].options.method, 'POST');
  assert.equal(calls[1].options.headers.Authorization, 'Bearer operator-signed-bearer');
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    start_time: end - 7 * day, end_time: end,
  });
  assert.equal(calls[1].url.includes('operator-signed-bearer'), false);
  assert.equal(calls[1].options.body.includes('OPENAI_ADMIN_KEY'), false);
});

test('out-of-range, partial UTC day and future windows deny without network', async () => {
  const day = 86400;
  const end = Math.floor(Date.now() / 1000 / day) * day;
  const cases = [
    [end - 32 * day, end],
    [end - 7 * day + 1, end],
    [end - 7 * day, end + day],
    [end, end],
    [0, Infinity],
  ];
  let called = 0;
  globalThis.fetch = async () => { called += 1; throw Error('unexpected network'); };
  for (const [start, finish] of cases) {
    assert.throws(() => supervision.supervisionApi.observeOpenAIProjectCosts(
      'eng-test-billing', start, finish,
    ), /completed UTC days/);
  }
  assert.equal(called, 0);
});

test('supervisor UI displays independently observed aggregate only with no false hard cap', () => {
  const component = readFileSync(
    fileURLToPath(new URL('../src/components/flows/SupervisionPanel.tsx', import.meta.url)), 'utf8',
  );
  assert.match(component, /seniorRoleHint.*?<div className="mt-2 pt-2 border-t border-outline-variant">/s);
  assert.match(component, /observeOpenAICosts\(\)/);
  assert.match(component, /Individual call charge verification: NO/);
  assert.match(component, /External spending ceiling verification: NO/);
  assert.match(component, /providerCostsEpoch.current \+= 1/);
  assert.match(component, /provider_project_comparable_to_engagement !== false/);
  assert.match(component, /provider_project_exclusivity_verified !== false/);
  assert.match(component, /Project exclusivity verification: NO/);
  assert.match(component, /UNKNOWN \(no provider cost lines returned\)/);
  assert.doesNotMatch(component, /setModelUsage\(observed\)/);
});
