import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
let vite;
let modal;

const envelope = () => ({
  version: 7,
  policy: {
    engagement_id: 'eng-stable-session-42',
    created_by: 'operator@example.com',
    domains: ['example.test', 'api.example.test'],
    ips: ['10.7.0.0/24'],
    exclusions: ['internal.example.test'],
    allowed_techniques: ['recon', 'vuln_scan'],
    restrictions: ['no-write'],
    approval_required_for: ['sqli', 'rce'],
    testing_window_start: '2026-10-14T07:00:00Z',
    testing_window_end: '2026-10-14T16:00:00Z',
    roe: {
      llm_call_budget_total: 12,
      llm_cost_budget_usd: 0.125,
      max_depth: 3,
      scan_intensity: 'limited',
      allow_automated_exploitation: false,
    },
    issued_at: '2026-10-13T12:00:00Z',
    not_before: '2026-10-14T06:00:00Z',
    expires_at: '2026-10-14T17:00:00Z',
    version: 7,
    authorization_id: 'auth-approved-42',
    key_id: 'roe-kid-2026',
  },
  // Shape only: intentionally NOT a real signature. The browser must NOT
  // mistake this for cryptographic verification; backend must reject it.
  signature: 'A'.repeat(86),
});

const json = (value) => JSON.stringify(value);

before(async () => {
  vite = await createServer({
    root,
    logLevel: 'silent',
    appType: 'custom',
    server: { middlewareMode: true },
  });
  modal = await vite.ssrLoadModule('/src/components/shared/NewMissionModal.tsx');
});

after(async () => {
  await vite?.close();
});

test('parses externally signed envelope and derives immutable-looking operator preview without signing', () => {
  const raw = json(envelope());
  const preview = modal.parseNewMissionInput(raw);
  assert.deepEqual(preview, {
    rawEnvelopeJson: raw,
    engagementId: 'eng-stable-session-42',
    createdBy: 'operator@example.com',
    authorizationId: 'auth-approved-42',
    keyId: 'roe-kid-2026',
    version: 7,
    domains: ['example.test', 'api.example.test'],
    ips: ['10.7.0.0/24'],
    testingWindowStart: '2026-10-14T07:00:00Z',
    testingWindowEnd: '2026-10-14T16:00:00Z',
    llmCallBudgetTotal: 12,
    llmCostBudgetUsd: 0.125,
  });
  preview.domains.push('evil.example.test');
  assert.deepEqual(modal.parseNewMissionInput(raw).domains, ['example.test', 'api.example.test']);
});

test('POST body equals all signed scope, UTC testing dates, ROE quotas and authorization ID with stable session', () => {
  const signed = envelope();
  const sent = modal.buildSignedEngagementRequest(json(signed));
  assert.deepEqual(sent, {
    engagement_id: signed.policy.engagement_id,
    domains: signed.policy.domains,
    ips: signed.policy.ips,
    exclusions: signed.policy.exclusions,
    allowed_techniques: signed.policy.allowed_techniques,
    restrictions: signed.policy.restrictions,
    approval_required_for: signed.policy.approval_required_for,
    testing_window_start: signed.policy.testing_window_start,
    testing_window_end: signed.policy.testing_window_end,
    authorization_ref: signed.policy.authorization_id,
    roe: signed.policy.roe,
    signed_roe: signed,
  });
  assert.notEqual(sent.domains, signed.policy.domains);
  sent.domains.push('added.example.test');
  sent.roe.llm_call_budget_total = 9999;
  assert.deepEqual(signed.policy.domains, ['example.test', 'api.example.test']);
  assert.equal(signed.policy.roe.llm_call_budget_total, 12);
});

test('requires explicitly signed finite model calls and never invents an optional dollar cap', () => {
  const signed = envelope();
  signed.policy.roe = { max_depth: 2, allow_automated_exploitation: false };
  assert.throws(() => modal.parseNewMissionInput(json(signed)), /explicitly authorize/);
  const countOnly = envelope();
  delete countOnly.policy.roe.llm_cost_budget_usd;
  assert.equal(modal.buildSignedEngagementRequest(json(countOnly)).roe.llm_cost_budget_usd, undefined);
  assert.equal(modal.buildSignedEngagementRequest(json(countOnly)).roe.llm_call_budget_total, 12);
});

test('rejects plain refs, missing signed envelope fields, unknown additions and version mismatch', () => {
  const parse = modal.parseNewMissionInput;
  for (const raw of ['', '{}', '{bad-json', 'signed-roe-only', '[]', 'null', 'false']) {
    assert.throws(() => parse(raw), /ROE|signed|valid JSON|JSON/);
  }
  const base = envelope();
  for (const change of [
    (value) => { value.extra = 'dangerous'; },
    (value) => { delete value.signature; },
    (value) => { value.version = 8; },
    (value) => { value.version = true; },
    (value) => { value.policy.version = 0; },
    (value) => { value.policy.unexpected = ['extra']; },
    (value) => { delete value.policy.authorization_id; },
    (value) => { value.signature = 'padded=='; },
    (value) => { value.signature = 'x'.repeat(85); },
    (value) => { value.signature = 'x'.repeat(86) + '='; },
  ]) {
    const value = structuredClone(base);
    change(value);
    assert.throws(() => parse(json(value)));
  }
});

test('rejects unsigned/malformed scope fields, artificial IDs, wildcard targets and duplicates', () => {
  const parse = modal.parseNewMissionInput;
  for (const change of [
    (p) => { p.engagement_id = 'dash-mission-random'; },
    (p) => { p.engagement_id = '../unsafe'; },
    (p) => { p.created_by = ''; },
    (p) => { p.authorization_id = ''; },
    (p) => { p.key_id = ''; },
    (p) => { p.domains = ['https://example.test']; },
    (p) => { p.domains = ['*.example.test']; },
    (p) => { p.domains = ['EXAMPLE.TEST']; },
    (p) => { p.domains = ['example.test', 'example.test']; },
    (p) => { p.domains = 'example.test'; },
    (p) => { p.domains = []; p.ips = []; },
    (p) => { p.exclusions = null; },
    (p) => { p.allowed_techniques = ['recon', 'recon']; },
    (p) => { p.approval_required_for = undefined; },
  ]) {
    const value = envelope();
    change(value.policy);
    assert.throws(() => parse(json(value)));
  }
});

test('rejects inconsistent UTC dates and invalid signed budgets rather than changing them', () => {
  const parse = modal.parseNewMissionInput;
  for (const change of [
    (p) => { p.testing_window_start = '2026-10-14T17:00:00Z'; },
    (p) => { p.testing_window_end = '2026-10-14T06:00:00Z'; },
    (p) => { p.issued_at = '2026-10-14T07:00:00Z'; },
    (p) => { p.issued_at = '2026-02-30T09:00:00Z'; },
    (p) => { p.not_before = '2026-10-14T16:00:00+00:00'; },
    (p) => { p.expires_at = '2026-10-14'; },
    (p) => { p.roe.llm_call_budget_total = 0; },
    (p) => { p.roe.llm_call_budget_total = -5; },
    (p) => { p.roe.llm_call_budget_total = 1.5; },
    (p) => { p.roe.llm_call_budget_total = true; },
    (p) => { p.roe.llm_call_budget_total = Number.MAX_SAFE_INTEGER + 1; },
    (p) => { p.roe.llm_cost_budget_usd = 0; },
    (p) => { p.roe.llm_cost_budget_usd = -1; },
  ]) {
    const value = envelope();
    change(value.policy);
    assert.throws(() => parse(json(value)));
  }
});

test('rendered modal collects ONLY externally signed JSON and shows no editable scope/budget defaults', () => {
  const markup = renderToStaticMarkup(createElement(modal.NewMissionModal, {
    isOpen: true,
    onClose: () => {},
    onLaunch: async () => {},
  }));
  assert.match(markup, /id="mission-signed-roe"/);
  assert.match(markup, /EXTERNALLY SIGNED ED25519 ROE ENVELOPE/);
  assert.match(markup, /does not sign or verify Ed25519 signatures/);
  assert.match(markup, /provider-reported costs/);
  assert.doesNotMatch(markup, /id="mission-domain"|id="mission-llm-calls"|id="mission-cost-cap"|id="mission-authorization"/);
  assert.doesNotMatch(markup, /BEGIN PRIVATE KEY|sk-|dev-token/);
  assert.equal(renderToStaticMarkup(createElement(modal.NewMissionModal, {
    isOpen: false,
    onClose: () => {},
    onLaunch: async () => {},
  })), '');
});

test('Header uses canonical API authentication and dispatch builder, not random IDs or bearer query', () => {
  const source = readFileSync(new URL('../src/components/layout/Header.tsx', import.meta.url), 'utf8');
  assert.match(source, /API_BASE/);
  assert.match(source, /authHeaders/);
  assert.match(source, /buildSignedEngagementRequest\(mission\.rawEnvelopeJson\)/);
  assert.match(source, /JSON\.stringify\(requestBody\)/);
  assert.match(source, /created\.session_id !== requestBody\.engagement_id/);
  assert.doesNotMatch(source, /dev-token|127\.0\.0\.1|[?&]token=|dash-mission|Math\.random\(|Date\.now\(/);
  assert.match(source, /headers:\s*authHeaders\(\{\s*Accept:/);
  assert.match(source, /headers:\s*authHeaders\(\)/);
});
