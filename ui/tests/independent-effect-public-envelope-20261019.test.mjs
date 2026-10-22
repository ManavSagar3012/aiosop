import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const oldFetch = globalThis.fetch;
let vite, api, reviews;
const eng = 'eng-checked-effect';
const flow = 'flow-checked-effect';
const report = 'report-' + eng + '-v1';
const finding = 'finding-owned';
const id = 'itefv-' + 'a'.repeat(32);
const digest = 'b'.repeat(64);
const source = 'c'.repeat(64);

const claims = {
  sub: 'review-owner', role: 'senior_operator',
  exp: Math.floor(Date.now() / 1000) + 300,
};
const verdict = {
  status: 'VERIFIED', finding_verified: true,
  independent_effect_verified: true, authorization_violation_verified: true,
  report_release_approved: false, finding_release_eligible: false,
  verification_id: id, verification_sha256: digest,
  report_source_evidence_sha256: source,
};

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  reviews = await vite.ssrLoadModule('/src/services/candidateFindingReviews.ts');
});
after(async () => {
  api?.signOut();
  globalThis.fetch = oldFetch;
  await vite?.close();
});

async function readWith(reply) {
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/me')) return { ok: true, json: async () => claims };
    assert.equal(options.method, 'GET');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    assert.match(options.headers.Authorization, /^Bearer /);
    return { ok: true, json: async () => reply };
  };
  await api.signIn('local-senior-credential');
  return reviews.candidateFindingReviews.readIndependent(
    eng, flow, finding, report, 2, id, digest, source,
  );
}

test('exact public independently verified receipt is still never a senior final release', async () => {
  const result = await readWith({ ...verdict });
  assert.equal(result.durable_readback_verified, true);
  assert.equal(result.authorization_violation_verified, true);
  assert.equal(result.final_senior_signoff, false);
  assert.equal(result.report_release_approved, false);
});

test('missing authorization-violation proof cannot be promoted by other true flags', async () => {
  await assert.rejects(
    readWith({ ...verdict, authorization_violation_verified: false }),
    /unavailable or revoked/,
  );
});

test('private or extra signed witness fields cannot enter the UI public state', async () => {
  await assert.rejects(
    readWith({ ...verdict, private_response_body: 'secret-owned-record' }),
    /unavailable or revoked/,
  );
  const { authorization_violation_verified, ...missing } = verdict;
  assert.equal(authorization_violation_verified, true);
  await assert.rejects(readWith(missing), /unavailable or revoked/);
});
