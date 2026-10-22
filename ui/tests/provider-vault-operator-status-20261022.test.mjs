/** Senior-only pending status; no paid dispatch, secret state or write actions. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const initialFetch = globalThis.fetch;
const initialWindow = globalThis.window;
const expiry = Math.floor(Date.now() / 1000) + 3600;
const action = {
  PENDING_HOST_ENROLLMENT: 'Enroll an independently signed host guard and all eleven authority roots.',
  PENDING_DURABLE_CALL_FENCE: 'Enroll a host-signed independent atomic one-use PostgreSQL call fence.',
  PENDING_CURRENT_HOST_AUTHORITY: 'Renew the signed host enrollment and durable call-fence lease.',
};
const expectedFields = [
  'code', 'next_action', 'host_enrollment_verified',
  'shared_call_fence_enrolled', 'provider_dispatch_authorized',
  'provider_contacted', 'credential_exported',
];
const status = (code = 'PENDING_HOST_ENROLLMENT') => ({
  code, next_action: action[code],
  host_enrollment_verified: false,
  shared_call_fence_enrolled: false,
  provider_dispatch_authorized: false,
  provider_contacted: false,
  credential_exported: false,
});
const reply = (data, http = 200, headers = {}) => new Response(JSON.stringify(data), {
  status: http, headers: { 'content-type': 'application/json', ...headers },
});

let vite, auth, svc, panel, sent = [], answers = [];
before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  svc = await vite.ssrLoadModule('/src/services/providerVaultOperatorStatus.ts');
  panel = await vite.ssrLoadModule('/src/components/ProviderVaultOperatorStatusPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = initialFetch;
  if (initialWindow === undefined) delete globalThis.window;
  else globalThis.window = initialWindow;
  await vite?.close();
});

async function login(role = 'senior_operator') {
  auth.signOut();
  sent = [];
  answers = [];
  globalThis.fetch = async (target, options = {}) => {
    const req = { url: new URL(String(target)), options };
    if (req.url.pathname === '/auth/me')
      return reply({ sub: 'current-verified-actor', role, exp: expiry });
    sent.push(req);
    if (!answers.length) throw new Error('Unexpected provider vault request');
    const answer = answers.shift();
    return typeof answer === 'function' ? await answer(req) : answer;
  };
  await auth.signIn('memory-only-provider-vault-bearer');
  sent = [];
}
const queue = (...responses) => answers.push(...responses);

test('mounted backend matches strictly bounded seven-field pending status contract', () => {
  const source = readFileSync(
    new URL('../../src/ai_osop/api/routers/system.py', import.meta.url), 'utf8',
  );
  const runtime = readFileSync(
    new URL('../../src/ai_osop/core/provider_vault_runtime_join.py', import.meta.url), 'utf8',
  );
  assert.match(source, /@router\.get\("\/provider\/vault-join-status"\)/);
  assert.match(source, /Depends\(require_role\("senior_operator"\)\)/);
  assert.match(source, /return asdict\(ProviderVaultRuntimeJoin\(\)\.health\(\)\)/);
  for (const flag of expectedFields.slice(2)) {
    assert.match(runtime, new RegExp(`\\b${flag}\\b`));
  }
  assert.deepEqual(Object.keys(status()).sort(), [...expectedFields].sort());
});

test('Administration mounts exactly one read-only vault status panel without duplicate requests or elevated actions', async () => {
  await login();
  const html = renderToStaticMarkup(createElement(panel.ProviderVaultOperatorStatusPanel));
  assert.match(html, /Provider vault trust status/);
  assert.match(html, /NOT READY — PENDING HOST TRUST/);
  assert.match(html, /Host enrollment independently verified/);
  assert.match(html, /Shared one-use call fence enrolled/);
  assert.match(html, /Provider dispatch authorized/);
  assert.match(html, /Provider contacted/);
  assert.match(html, /Credential exported/);
  assert.equal((html.match(/Unknown — not verified/g) ?? []).length, 5);
  assert.match(html, /Refresh status/);
  assert.doesNotMatch(html, /memory-only-provider-vault-bearer|api_key|secret material|private_host|127\.0\.0\.1:8200/i);
  assert.doesNotMatch(html, /<button[^>]*>\s*(?:approve|execute|send|rotate|revoke|enable|grant)/i);
  const admin = readFileSync(new URL('../src/pages/Administration.tsx', import.meta.url), 'utf8');
  assert.match(admin, /<ProviderCredentialAdministrationPanel \/>/);
  const ast = ts.createSourceFile('Administration.tsx', admin, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const imports = ast.statements.filter(node =>
    ts.isImportDeclaration(node)
    && node.moduleSpecifier.text === '../components/ProviderVaultOperatorStatusPanel'
    && node.importClause?.namedBindings
    && ts.isNamedImports(node.importClause.namedBindings)
    && node.importClause.namedBindings.elements.some(item => item.name.text === 'ProviderVaultOperatorStatusPanel')
  );
  assert.equal(imports.length, 1, 'the panel must be imported exactly once');
  const mounts = [];
  function walk(node) {
    if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node))
      && node.tagName.getText(ast) === 'ProviderVaultOperatorStatusPanel') mounts.push(node);
    ts.forEachChild(node, walk);
  }
  walk(ast);
  assert.equal(mounts.length, 1, 'mount exactly one panel in Administration');
  assert.equal(mounts[0].attributes.properties.length, 0, 'no injected token, permission or action props');
  assert.doesNotMatch(admin, /readProviderVaultOperatorStatus|vault-join-status/,
    'Administration must not issue a second vault status request');

  const panelSource = readFileSync(
    new URL('../src/components/ProviderVaultOperatorStatusPanel.tsx', import.meta.url), 'utf8',
  );
  const calls = panelSource.match(/await readProviderVaultOperatorStatus\(abort\.signal\)/g) ?? [];
  assert.equal(calls.length, 1, 'a single component refresh calls the guarded read exactly once');
  assert.equal((panelSource.match(/<button\b/g) ?? []).length, 1, 'only the manual Refresh button is present');
  assert.match(panelSource, /onClick=\{\(\) => \{ void refresh\(\); \}\}/);
  assert.doesNotMatch(panelSource, /\bfetch\s*\(|grantProvider|sendToProvider|executeProvider|rotateCredential|revokeCredential/,
    'the panel must not add direct requests or elevated actions');
});

test('senior GET reads exact PENDING status once without cookies, redirects, URL tokens or POST', async () => {
  await login();
  queue(reply(status()));
  const result = await svc.readProviderVaultOperatorStatus();
  assert.deepEqual(result, status());
  assert.equal(sent.length, 1);
  const [{ url, options }] = sent;
  assert.equal(url.pathname, '/system/provider/vault-join-status');
  assert.equal(url.search, '');
  assert.equal(options.method, 'GET');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.redirect, 'error');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.headers.Authorization, 'Bearer memory-only-provider-vault-bearer');
  assert.equal(options.headers.Accept, 'application/json');
  assert.equal(options.body, undefined);
  assert.doesNotMatch(url.toString(), /Bearer|memory-only|password|api_key|credential|access_token=/);
  for (const code of svc.PROVIDER_VAULT_PENDING_CODES.slice(1)) {
    queue(reply(status(code)));
    assert.deepEqual(await svc.readProviderVaultOperatorStatus(), status(code));
  }
});

test('no overclaimed authority, secret field or unrecognized status passes validation', async () => {
  await login();
  const mutants = [
    x => { x.host_enrollment_verified = true; },
    x => { x.shared_call_fence_enrolled = true; },
    x => { x.provider_dispatch_authorized = true; },
    x => { x.provider_contacted = true; },
    x => { x.credential_exported = true; },
    x => { x.host_enrollment_verified = 'false'; },
    x => { x.provider_dispatch_authorized = null; },
    x => { x.code = 'HOST_ENROLLED_DISPATCH_UNPROVEN'; },
    x => { x.code = 'READY'; },
    x => { x.code = 'PENDING_DEPLOYMENT_KEYS'; },
    x => { x.next_action = 'POST to https://attacker.example/get-keys'; },
    x => { x.next_action = 'Signer: Bearer PRIVATE'; },
    x => { x.next_action = true; },
    x => { x.provider_api_key = 'PRIVATE-SECRET'; },
    x => { x.vault_revision = 50; },
    x => { x.runtime_key_service_url = 'https://vault.internal'; },
    x => { delete x.credential_exported; },
  ];
  for (const mutate of mutants) {
    const changed = status();
    mutate(changed);
    queue(reply(changed));
    await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /vault|PENDING/i);
  }
  assert.equal(sent.length, mutants.length);
  assert.ok(sent.every(req => req.options.method === 'GET'));
});

test('duplicate JSON keys, malformed payload, size and MIME violations fail closed', async () => {
  await login();
  const duplicate = JSON.stringify(status()).replace(
    '"provider_dispatch_authorized":false',
    '"provider_dispatch_authorized":true,"provider_dispatch_authorized":false',
  );
  queue(new Response(duplicate, {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /Duplicate/);
  queue(new Response('x'.repeat(2_049), {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /limit/i);
  queue(new Response('{ "code":', {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus());
  queue(new Response(JSON.stringify(status()), {
    status: 200, headers: { 'content-type': 'text/html' },
  }));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /JSON/i);
  queue(reply(status(), 200, { 'content-length': '999999' }));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /limit/i);
  queue(reply({ detail: 'SECRET server exception' }, 503));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /unavailable/i);
  queue(new Error('private provider transport detail'));
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /unavailable/i);
  assert.equal(sent.length, 7);
});

test('only current verified unexpired senior secure-origin identity can read', async () => {
  auth.signOut();
  sent = [];
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /senior operator/i);
  assert.equal(sent.length, 0);
  await login('operator');
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /senior operator/i);
  assert.equal(sent.length, 0);
  await login();
  globalThis.window = { location: { protocol: 'http:', hostname: 'untrusted.example' } };
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /secure origin/i);
  if (initialWindow === undefined) delete globalThis.window;
  else globalThis.window = initialWindow;
  assert.equal(sent.length, 0);
  const signal = new AbortController();
  signal.abort();
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(signal.signal), /cancelled/i);
  assert.equal(sent.length, 0);
});

test('sign-out or identity mutation during network / response read rejects current results', async () => {
  await login();
  queue(() => { auth.signOut(); return reply(status()); });
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /senior operator|changed/i);
  await login();
  queue(() => {
    const response = reply(status());
    response.text = async () => {
      auth.signOut();
      return JSON.stringify(status());
    };
    return response;
  });
  await assert.rejects(() => svc.readProviderVaultOperatorStatus(), /senior operator|changed/i);
  assert.equal(sent.length, 1);
});

test('service and panel have no credential stores, provider dispatches or arbitrary URL actions', () => {
  const service = readFileSync(
    new URL('../src/services/providerVaultOperatorStatus.ts', import.meta.url), 'utf8',
  );
  const component = readFileSync(
    new URL('../src/components/ProviderVaultOperatorStatusPanel.tsx', import.meta.url), 'utf8',
  );
  assert.match(service, /\/system\/provider\/vault-join-status/);
  assert.match(service, /method: 'GET'/);
  assert.doesNotMatch(service + component, /localStorage\.|sessionStorage\.|document\.cookie|dangerouslySetInnerHTML|\.innerHTML\s*=/);
  assert.doesNotMatch(service, /method: 'POST'|method: 'PUT'|method: 'DELETE'|credentials: 'include'/);
  assert.doesNotMatch(component, /grantProvider|sendToProvider|executeProvider|rotateCredential|POST/);
});
