import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const reportId = 'summary-' + 'a'.repeat(64);
const validPayload = {
  report_id: reportId,
  availability: 'limited_verified_summary',
  markdown: 'AI-OSOP EVIDENCE SUMMARY\nCritical: 1',
  verified_record_count: 1,
};
let vite;
let page;
let api;

before(async () => {
  vite = await createServer({
    root,
    logLevel: 'silent',
    appType: 'custom',
    server: { middlewareMode: true },
  });
  page = await vite.ssrLoadModule('/src/pages/MissionReport.tsx');
  api = await vite.ssrLoadModule('/src/services/api.ts');
});

after(async () => {
  await vite?.close();
});

test('accepts only bounded, explicit summary availability; never accepts HTML-only drafts', () => {
  assert.deepEqual(page.parsePrintableMissionReport(validPayload), validPayload);
  assert.equal(
    page.parsePrintableMissionReport({
      ...validPayload, markdown: 'NO VERIFIED REPORT DATA',
      availability: 'no_verified_evidence', verified_record_count: 0,
    }).verified_record_count,
    0,
  );
  for (const bad of [
    null,
    '<h1>untrusted report</h1>',
    { ...validPayload, markdown: '' },
    { ...validPayload, markdown: 'X'.repeat(32001) },
    { ...validPayload, markdown: undefined, body_html: '<script>alert(1)</script>' },
    { ...validPayload, report_id: 'signed-report-1234' },
    { ...validPayload, availability: 'verified_and_signed' },
    { ...validPayload, availability: 'no_verified_evidence' },
    { ...validPayload, verified_record_count: 0 },
    { ...validPayload, verified_record_count: 201 },
    { ...validPayload, verified_record_count: Number.NaN },
  ]) {
    assert.throws(
      () => page.parsePrintableMissionReport(bad),
      /invalid summary/,
    );
  }
});

test('fetch uses canonical bearer headers and never includes a token in the URL', async () => {
  const originalFetch = globalThis.fetch;
  let called;
  globalThis.fetch = async (url, options) => {
    called = { url, options };
    return { ok: true, json: async () => validPayload };
  };
  try {
    const abort = new AbortController();
    assert.deepEqual(await page.fetchMissionReport('eng-authorized', abort.signal), validPayload);
    assert.equal(called.url, `${api.API_BASE}/engagements/eng-authorized/report`);
    assert.deepEqual(called.options.headers, api.authHeaders({ Accept: 'application/json' }));
    assert.equal(called.options.signal, abort.signal);
    assert.equal(called.options.cache, 'no-store');
    assert.equal(called.url.includes('?'), false);
    assert.equal(called.options.credentials, undefined);
    await assert.rejects(
      () => page.fetchMissionReport('eng?token=leaked'),
      /valid engagement/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetch distinguishes authorization, unavailability, malformed JSON and does not leak response body', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const [status, pattern] of [
      [401, /access denied/],
      [403, /access denied/],
      [404, /not available/],
      [503, /temporarily unavailable/],
      [502, /Could not load/],
    ]) {
      globalThis.fetch = async () => ({
        ok: false,
        status,
        text: async () => 'SECRET ACCESS TOKEN NOT FOR USER',
      });
      await assert.rejects(
        () => page.fetchMissionReport('eng-authorized'),
        (err) => pattern.test(err.message) && !err.message.includes('SECRET'),
      );
    }
    globalThis.fetch = async () => ({
      ok: true, json: async () => ({ html: '<script>pwn()</script>' }),
    });
    await assert.rejects(() => page.fetchMissionReport('eng-authorized'), /invalid summary/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('displayed errors never reflect untrusted JSON parser snippets or server exceptions', () => {
  assert.equal(
    page.reportFetchErrorMessage(new SyntaxError('Unexpected token: SECRET_TOKEN_VALUE')),
    'Could not load the engagement summary. Try again.',
  );
  assert.equal(
    page.reportFetchErrorMessage(new Error('Report access denied. Check your operator authorization.')),
    'Report access denied. Check your operator authorization.',
  );
  assert.equal(
    page.reportFetchErrorMessage({ detail: '<script>steal()</script>' }),
    'Could not load the engagement summary. Try again.',
  );
});

test('printable React markup escapes all report content and never evaluates HTML', () => {
  const malicious = {
    ...validPayload,
    markdown: '<img src=x onerror="alert(1)"> <script>window.pwned = true</script>',
    html: '<svg onload="alert(1)"></svg>',
    body_html: '<script>stealCookies()</script>',
  };
  const safe = page.parsePrintableMissionReport(malicious);
  const markup = renderToStaticMarkup(
    createElement(page.MissionReportDocument, {
      report: safe,
      sessionId: '<img src=x onerror=alert(3)>',
    }),
  );
  assert.match(markup, /&lt;img src=x onerror=/);
  assert.match(markup, /&lt;script&gt;window\.pwned/);
  assert.doesNotMatch(markup, /<img src=x|<script>|<svg|stealCookies\(\)/);
  assert.match(markup, /not a signature/);
  assert.match(markup, /not an approved or signed final/);
  assert.doesNotMatch(markup, /V6\.5|Elite Kernel|PAGE 1 \/ 1|SIGNATURE: SHA256/);
});

test('no_verified_evidence displays absence truthfully, not a successful scan', () => {
  const noFindings = page.parsePrintableMissionReport({
    ...validPayload,
    availability: 'no_verified_evidence',
    verified_record_count: 0,
    markdown: 'NO VERIFIED REPORT DATA',
  });
  const markup = renderToStaticMarkup(
    createElement(page.MissionReportDocument, { report: noFindings, sessionId: 'eng-empty' }),
  );
  assert.match(markup, /No verified evidence available/);
  assert.match(markup, /does not mean the engagement is secure/);
  assert.match(markup, /NO VERIFIED REPORT DATA/);
  assert.doesNotMatch(markup, /Limited evidence summary available/);
});

test('save PDF and print use the browser print dialog instead of inert export', () => {
  const originalWindow = globalThis.window;
  let calls = 0;
  globalThis.window = { print: () => { calls += 1; } };
  try {
    page.openMissionReportPrintDialog();
    page.openMissionReportPrintDialog();
    assert.equal(calls, 2);
  } finally {
    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  }
});

test('page wires both export and print, guards session changes, and contains no unsafe HTML path', () => {
  const source = readFileSync(new URL('../src/pages/MissionReport.tsx', import.meta.url), 'utf8');
  assert.equal((source.match(/onClick=\{openMissionReportPrintDialog\}/g) ?? []).length, 2);
  assert.match(source, /reportSessionId !== sessionId/);
  assert.match(source, /controller\.abort\(\)/);
  assert.doesNotMatch(source, /dangerouslySetInnerHTML|\.innerHTML\s*=|Bearer dev-token|V6\.5|SIGNATURE: SHA256|PAGE 1 \/ 1/);
});
