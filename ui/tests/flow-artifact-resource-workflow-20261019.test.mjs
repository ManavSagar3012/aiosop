import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { webcrypto, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const oldFetch = globalThis.fetch;
const flow = 'flow-resource-review';
const engagement = 'eng-resource-review';
const revision = 4;
const roe = 7;
let vite, auth, resources, panel, requests;
let manifest, archive, contents, archiveChecksum;
let currentSigner, statusCode, afterNetwork;

const hash = (value) => createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}
function makeManifest(files = [{ name: 'safety.txt', bytes: 'no target action\n' }, { name: 'notes.py', bytes: 'flag = False\n' }]) {
  const entries = files.map(({ name, bytes }, i) => ({
    artifact_id: 'artifact-' + String(i + 1).repeat(32), name,
    resource_path: `resources/${name}`,
    size_bytes: new TextEncoder().encode(bytes).length,
    sha256: hash(bytes),
    classification: name.endsWith('.py') ? 'utf8_inert_source' : 'utf8_inert_text',
  })).sort((a, b) => a.resource_path.localeCompare(b.resource_path, 'en-US'));
  const data = {
    format: 'ai-osop-inert-flow-resources-v1', flow_id: flow,
    flow_revision: revision, authorization_version: roe,
    count: entries.length, total_size_bytes: entries.reduce((total, item) => total + item.size_bytes, 0),
    items: entries, read_only: true, content_executed: false,
    host_files_created: false, archive_compression: 'stored', artifact_bytes_untrusted: true,
  };
  return { ...data, manifest_sha256: hash(canonical(data)) };
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function zipStored(entries) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const [name, raw] of entries) {
    const file = Buffer.from(raw);
    const title = Buffer.from(name, 'ascii');
    const crc = crc32(file);
    const local = Buffer.alloc(30 + title.length + file.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(file.length, 18);
    local.writeUInt32LE(file.length, 22);
    local.writeUInt16LE(title.length, 26);
    title.copy(local, 30);
    file.copy(local, 30 + title.length);
    locals.push(local);
    const central = Buffer.alloc(46 + title.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(788, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(file.length, 20);
    central.writeUInt32LE(file.length, 24);
    central.writeUInt16LE(title.length, 28);
    central.writeUInt32LE(offset, 42);
    title.copy(central, 46);
    centrals.push(central);
    offset += local.length;
  }
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
}
function resetArchive() {
  manifest = makeManifest();
  contents = { 'safety.txt': 'no target action\n', 'notes.py': 'flag = False\n' };
  archive = zipStored([
    ...manifest.items.map(item => [item.resource_path, Buffer.from(contents[item.name])]),
    ['resource-manifest.json', Buffer.from(canonical(manifest))],
  ]);
  archiveChecksum = hash(archive);
}
function streamResponse(bytes, headers = {}) {
  return new Response(bytes, { status: statusCode, headers: {
    'Content-Type': 'application/zip', 'X-Resource-Archive-SHA256': archiveChecksum,
    'X-Resource-Manifest-SHA256': manifest.manifest_sha256, ...headers,
  } });
}

before(async () => {
  vite = await createServer({ root, appType: 'custom', logLevel: 'silent', server: { middlewareMode: true } });
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  resources = await vite.ssrLoadModule('/src/services/flowArtifacts.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/FlowArtifactsPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = oldFetch;
  await vite?.close();
});

async function login(role = 'operator') {
  auth.signOut();
  resetArchive();
  requests = [];
  currentSigner = { id: flow, engagement_id: engagement, revision, status: 'running' };
  statusCode = 200;
  afterNetwork = null;
  globalThis.fetch = async (url, options = {}) => {
    const request = { url: String(url), method: options.method ?? 'GET', options };
    requests.push(request);
    if (new URL(request.url).pathname === '/auth/me') {
      return { ok: true, status: 200,
        json: async () => ({ sub: 'owner-' + role, role, exp: null }) };
    }
    if (new URL(request.url).pathname === `/flows/${flow}`) {
      const returned = { ok: true, status: 200, json: async () => ({ flow: structuredClone(currentSigner) }) };
      if (afterNetwork) await afterNetwork('flow');
      return returned;
    }
    if (request.url.includes('/resource-manifest')) {
      const returned = { ok: statusCode === 200, status: statusCode,
        headers: { get: key => key === 'X-Resource-Manifest-SHA256' ? manifest.manifest_sha256 : null },
        json: async () => structuredClone(manifest) };
      if (afterNetwork) await afterNetwork('manifest');
      return returned;
    }
    if (request.url.includes('/resource-bundle')) {
      const returned = streamResponse(archive);
      if (afterNetwork) await afterNetwork('bundle');
      return returned;
    }
    throw new Error('Unexpected API request');
  };
  await auth.signIn('resource-operator-test-bearer');
}
const manifestRequests = () => requests.filter(r => r.url.includes('/resource-manifest'));
const bundleRequests = () => requests.filter(r => r.url.includes('/resource-bundle'));

test('real mounted manifest GET and ZIP GET are bounded bearer-only, no browser or host effects', async () => {
  await login();
  await resources.flowArtifactsApi.currentResourceFlow(flow, engagement, revision);
  const inspected = await resources.flowArtifactsApi.resourceManifest(flow, revision, roe);
  assert.deepEqual(inspected, manifest);
  const packed = await resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, inspected);
  assert.equal(packed.blob.size, archive.length);
  assert.equal(packed.archive_sha256, archiveChecksum);
  assert.equal(packed.manifest_sha256, manifest.manifest_sha256);
  assert.equal(packed.flow_revision, revision);
  assert.equal(packed.authorization_version, roe);
  assert.equal(packed.resource_count, 2);
  assert.equal(packed.total_resource_bytes, manifest.total_size_bytes);
  assert.equal((await resources.flowArtifactsApi.resourceBundle(flow, revision, roe, inspected)).size, archive.length);
  assert.equal(manifestRequests().length, 1);
  assert.equal(bundleRequests().length, 2);
  for (const sent of [...manifestRequests(), ...bundleRequests()]) {
    assert.equal(sent.method, 'GET');
    assert.match(sent.url, /expected_revision=4&expected_authorization_version=7$/);
    assert.equal(sent.options.headers.Authorization, 'Bearer resource-operator-test-bearer');
    assert.equal(sent.options.credentials, 'omit');
    assert.equal(sent.options.cache, 'no-store');
    assert.equal(sent.options.redirect, 'error');
    assert.equal(sent.options.referrerPolicy, 'no-referrer');
    assert.equal(sent.options.body, undefined);
    assert.doesNotMatch(sent.url, /Bearer|token|secret|private-body/);
  }
  assert.equal(requests.filter(r => r.method !== 'GET').length, 0);
  assert.equal(requests.some(r => /browser|container|terminal|execute|sync|report\/release/.test(r.url)), false);
});

test('Flow currentness denies wrong tenant, revision, status, and stale operator reply', async () => {
  await login();
  for (const variant of [
    { engagement_id: 'eng-other' }, { revision: 5 },
    { status: 'invented_verified_worker_sync' }, { id: 'flow-other' },
  ]) {
    currentSigner = { id: flow, engagement_id: engagement, revision, status: 'running', ...variant };
    await assert.rejects(resources.flowArtifactsApi.currentResourceFlow(flow, engagement, revision), /revision or status changed/);
  }
  currentSigner = { id: flow, engagement_id: engagement, revision, status: 'completed' };
  await resources.flowArtifactsApi.currentResourceFlow(flow, engagement, revision);
  await assert.rejects(resources.flowArtifactsApi.currentResourceFlow('flow-../evil', engagement, revision), /Exact current/);
  await assert.rejects(resources.flowArtifactsApi.currentResourceFlow(flow, engagement, -1), /Exact current/);
  const count = requests.length;
  assert.equal(count > 0, true);
  afterNetwork = async type => { if (type === 'flow') auth.signOut(); };
  await assert.rejects(resources.flowArtifactsApi.currentResourceFlow(flow, engagement, revision), /Verified current|Operator identity/);
});

test('manifest verification denies forged fields, paths, classifications and independent hash mismatch', async () => {
  await login();
  const forged = [
    value => { value.content_executed = true; },
    value => { value.host_files_created = true; },
    value => { value.worker_resource_synced = true; },
    value => { value.flow_revision = revision + 1; },
    value => { value.authorization_version = roe + 1; },
    value => { value.flow_id = 'flow-foreign'; },
    value => { value.items[0].resource_path = 'resources/../private.txt'; },
    value => { value.items[0].name = '../private.txt'; },
    value => { value.items[0].raw_body = 'secret'; },
    value => { value.items[0].classification = 'source_verified_executed'; },
    value => { value.items[0].classification = 'utf8_inert_text'; },
    value => { value.items[0].name = 'task.exe'; value.items[0].resource_path = 'resources/task.exe'; },
    value => { value.items = [value.items[0], value.items[0]]; },
  ];
  for (const mutate of forged) {
    resetArchive();
    mutate(manifest);
    await assert.rejects(resources.flowArtifactsApi.resourceManifest(flow, revision, roe), /integrity|scope|SHA-256/);
  }
  resetArchive();
  manifest.items[0].sha256 = 'f'.repeat(64);
  await assert.rejects(resources.flowArtifactsApi.resourceManifest(flow, revision, roe), /SHA-256/);
});

test('ZIP rejects centrally rewritten CRC even with forged valid whole-archive SHA', async () => {
  await login();
  const source = await resources.flowArtifactsApi.resourceManifest(flow, revision, roe);
  const original = Buffer.from(archive);
  const index = original.readUInt32LE(original.length - 22 + 16);
  const local = Buffer.from(original);
  local.writeUInt32LE(0, 14);
  archive = local;
  archiveChecksum = hash(archive);
  await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, source), /member integrity/);
  const central = Buffer.from(original);
  central.writeUInt32LE(0, index + 16);
  archive = central;
  archiveChecksum = hash(archive);
  await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, source), /member integrity/);
});

test('ZIP rejects corrupt member, hidden paths, central file spoofing, and modified manifest', async () => {
  await login();
  const source = await resources.flowArtifactsApi.resourceManifest(flow, revision, roe);
  const original = Buffer.from(archive);
  const variants = [];
  const corrupted = Buffer.from(original);
  corrupted[30 + 'resources/notes.py'.length] ^= 1;
  variants.push(corrupted);
  const renamed = Buffer.from(original);
  renamed[30] = 46;
  variants.push(renamed);
  const badCentralPath = Buffer.from(original);
  const centralOffset = original.readUInt32LE(original.length - 22 + 16);
  badCentralPath[centralOffset + 46] = 46;
  variants.push(badCentralPath);
  const symlink = Buffer.from(original);
  symlink.writeUInt32LE(0xa0000000, centralOffset + 38);
  variants.push(symlink);
  const embedded = Buffer.from(original);
  embedded[embedded.indexOf(Buffer.from('"manifest_sha256"')) + 1] = 77;
  variants.push(embedded);
  for (const mutated of variants) {
    archive = mutated;
    archiveChecksum = hash(mutated);
    await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, source), /member integrity/);
  }
});

test('stale bearer on manifest or ZIP download cannot yield a trusted resource', async () => {
  await login();
  afterNetwork = async type => { if (type === 'manifest') auth.signOut(); };
  await assert.rejects(resources.flowArtifactsApi.resourceManifest(flow, revision, roe), /Verified current|Operator identity/);
  await login();
  const verified = await resources.flowArtifactsApi.resourceManifest(flow, revision, roe);
  afterNetwork = async type => { if (type === 'bundle') auth.signOut(); };
  await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, verified), /Verified current|Operator identity/);
});

test('ambiguous download/denial/malformed stream fails closed, without retries', async () => {
  await login();
  const snapshot = await resources.flowArtifactsApi.resourceManifest(flow, revision, roe);
  statusCode = 403;
  await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, snapshot), /authorization/);
  assert.equal(bundleRequests().length, 1);
  statusCode = 200;
  const old = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes('/resource-bundle')) {
      requests.push({ url: String(url), options: init, method: 'GET' });
      throw new Error('Private backend token leaked?');
    }
    return old(url, init);
  };
  await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, snapshot));
  assert.equal(bundleRequests().length, 2);
  const invalid = structuredClone(snapshot);
  invalid.items[0].resource_path = 'resources/../../host.conf';
  await assert.rejects(resources.flowArtifactsApi.verifiedResourceBundle(flow, revision, roe, invalid), /integrity|scope/);
  assert.equal(bundleRequests().length, 2);
});

test('real mounted operator panel demands full manifest review, digest and explicit ZIP confirmation; no sync claim', async () => {
  await login();
  const markup = renderToStaticMarkup(createElement(panel.FlowArtifactsPanel, {
    flowId: flow, engagementId: engagement, revision,
  }));
  assert.match(markup, /VERIFY RESOURCE MANIFEST/);
  assert.match(markup, /VERIFY &amp; EXPORT INERT ZIP/);
  assert.match(markup, /no archive is unpacked, interpreted or synchronized/);
  assert.doesNotMatch(markup, /automatic sync successful|remote executed successfully/);
  const ui = readFileSync(new URL('../src/components/flows/FlowArtifactsPanel.tsx', import.meta.url), 'utf8');
  assert.match(ui, /resourceManifest\.items\.map/);
  assert.match(ui, /item\.resource_path/);
  assert.match(ui, /item\.sha256/);
  assert.match(ui, /item\.size_bytes/);
  assert.match(ui, /setResourceReviewed\(event\.target\.checked\)/);
  assert.match(ui, /confirmedManifestSha !== resourceManifest\.manifest_sha256/);
  assert.match(ui, /window\.confirm\(/);
  assert.match(ui, /await flowArtifactsApi\.resourceManifest\(/);
  assert.match(ui, /flowArtifactsApi\.verifiedResourceBundle\(/);
  assert.match(ui, /await checkSnapshot\(version, reviewer\)/);
  assert.match(ui, /resourceInFlight\.current/);
  assert.match(ui, /subscribeOperator/);
  assert.match(ui, /no worker\/container sync or file execution occurred/);
  assert.doesNotMatch(ui, /dangerouslySetInnerHTML|document\.write|docker\.exec|\bsyncToContainer\(/);
});
