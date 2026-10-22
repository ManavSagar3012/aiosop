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
let service;
let panel;
let calls = [];
let payload;

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  service = await vite.ssrLoadModule('/src/services/providerCapabilityAdmission.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/FlowModelAnalyticsPanel.tsx');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

const valid = () => ({
  engagement_id: 'eng-owned', scope: 'engagement_not_individual_flow',
  status: 'blocked', reasons: ['unreconciled_provider_outcome'],
  signed_roe_current_at_read: true, admission_attempted: false, execution_admitted: false,
  provider_called: false, reservation_created: false, provider_native_cost_ceiling_verified: false,
  routes: [{ provider: 'openai', model: 'safe-model', operations: ['completion'],
    configured_capabilities: ['text_completion'], allowed_roles: ['workflow'],
    deployment: 'locally_configured', provider_served_model_verified: false, provider_capability_verified: false }],
  budget: { signed_call_limit: 5, recorded_calls: 2, unresolved_calls: 1, unpriced_calls: 1,
    signed_cost_limit_usd: '8.0', signed_max_precharge_usd: '2.0',
    known_adjusted_cost_usd: null, outstanding_precharge_usd: '2.00000000',
    provider_native_cost_ceiling_verified: false },
});

const reply = (body, status = 200) => ({ ok: status === 200, status,
  json: async () => body, text: async () => JSON.stringify(body),
});

async function signIn(role = 'senior_operator') {
  api.signOut();
  calls = [];
  payload = valid();
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    calls.push({ pathname, url: String(url), init });
    if (pathname === '/auth/me') return reply({ sub: 'owner', role, exp: null });
    if (pathname.endsWith('/provider-admission-explanation')) return reply(payload);
    throw new Error('Unexpected provider endpoint: ' + pathname);
  };
  await api.signIn('fixture-bearer-read-only');
}

test('mounted Flow model panel explains senior-only signed admission and unknown price', async () => {
  await signIn();
  const markup = renderToStaticMarkup(createElement(
    panel.FlowModelAnalyticsPanel,
    { engagementId: 'eng-owned', flowId: 'flow-owned', revision: 1 },
  ));
  assert.match(markup, /Provider admission · signed engagement budget/);
  assert.match(markup, /REFRESH PROVIDER ADMISSION EXPLANATION/);
  assert.match(markup, /atomic PostgreSQL reservation checks/);
  const mounted = readFileSync(new URL('../src/pages/FlowOperations.tsx', import.meta.url), 'utf8');
  assert.match(mounted, /<FlowModelAnalyticsPanel/);
  assert.match(mounted, /engagementId=\{selectedFlow.engagement_id\}/);
});

test('senior real service verifies tenant and server denial with no paid provider request', async () => {
  await signIn();
  const result = await service.readOperatorAdmissionExplanation('eng-owned');
  assert.equal(result.status, 'blocked');
  assert.deepEqual(result.reasons, ['unreconciled_provider_outcome']);
  assert.equal(result.execution_admitted, false);
  assert.equal(result.reservation_created, false);
  assert.equal(result.provider_called, false);
  assert.equal(result.budget.known_adjusted_cost_usd, null);
  const requests = calls.filter(call => call.pathname.endsWith('/provider-admission-explanation'));
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request.init.method, 'GET');
  assert.equal(request.init.cache, 'no-store');
  assert.equal(request.init.credentials, 'omit');
  assert.equal(request.init.redirect, 'error');
  assert.equal(request.init.referrerPolicy, 'no-referrer');
  assert.match(request.init.headers.Authorization, /Bearer fixture-bearer-read-only/);
  assert.doesNotMatch(request.url, /bearer|token|secret/);
  assert.equal(request.init.body, undefined);
});

test('operator and foreign engagement cannot request senior budget or provider data', async () => {
  await signIn('operator');
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /senior operator/);
  assert.equal(calls.length, 1);
  await signIn();
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-INVALID?'), /engagement required/);
  assert.equal(calls.length, 1);
  payload.engagement_id = 'eng-foreign';
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /Unsafe or malformed/);
});

test('a forged provider-verified model, successful admission or cost cap fails closed', async () => {
  await signIn();
  payload.routes[0].provider_capability_verified = true;
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /unsupported verification/);
  payload = valid();
  payload.execution_admitted = true;
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /Unsafe or malformed/);
  payload = valid();
  payload.budget.provider_native_cost_ceiling_verified = true;
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /falsely verified/);
});

test('revoked signed authorization hides budget and rejects contradictory success status', async () => {
  await signIn();
  payload = {
    engagement_id: 'eng-owned', scope: 'engagement_not_individual_flow',
    status: 'unavailable', reasons: ['signed_authorization_unavailable'], routes: [], budget: null,
    signed_roe_current_at_read: false, admission_attempted: false, execution_admitted: false,
    provider_called: false, reservation_created: false, provider_native_cost_ceiling_verified: false,
  };
  assert.equal((await service.readOperatorAdmissionExplanation('eng-owned')).status, 'unavailable');
  payload.status = 'requires_atomic_admission';
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /Incomplete signed|Unverified provider/);
});

test('changed operator during read never receives the previous engagement snapshot', async () => {
  await signIn();
  const delegated = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const data = await delegated(url, init);
    if (new URL(String(url)).pathname.endsWith('/provider-admission-explanation')) api.signOut();
    return data;
  };
  await assert.rejects(service.readOperatorAdmissionExplanation('eng-owned'), /Operator changed/);
});
