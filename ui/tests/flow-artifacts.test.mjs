import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { webcrypto } from 'node:crypto';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
let vite;
let api;
let artifacts;
let component;

before(async () => {
  vite = await createServer({
    root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true },
  });
  api = await vite.ssrLoadModule('/src/services/api.ts');
  artifacts = await vite.ssrLoadModule('/src/services/flowArtifacts.ts');
  component = await vite.ssrLoadModule('/src/components/flows/FlowArtifactsPanel.tsx');
  globalThis.fetch = async () => ({
    ok: true, status: 200,
    json: async () => ({
      sub: 'test-operator', role: 'operator',
      exp: Math.floor(Date.now() / 1000) + 600,
    }),
  });
  await api.signIn('test-only-signed-placeholder');
});

after(async () => {
  api?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});

function fakeJson(value, status = 200) {
  return { ok: status < 300, status, json: async () => value };
}

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

async function sha(value) {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return Buffer.from(await webcrypto.subtle.digest('SHA-256', bytes)).toString('hex');
}

async function resourceFixture() {
  const source = new TextEncoder().encode('inert = true\n');
  const item = {
    artifact_id: 'artifact-' + 'a'.repeat(32), name: 'test.py',
    resource_path: 'resources/test.py', size_bytes: source.byteLength,
    sha256: await sha(source), classification: 'utf8_inert_source',
  };
  const fields = {
    format: 'ai-osop-inert-flow-resources-v1', flow_id: 'flow-one',
    flow_revision: 7, authorization_version: 3, count: 1,
    total_size_bytes: source.byteLength, items: [item], read_only: true,
    content_executed: false, host_files_created: false,
    archive_compression: 'stored', artifact_bytes_untrusted: true,
  };
  const manifest = { ...fields, manifest_sha256: await sha(canonical(fields)) };
  return { manifest, source };
}

// Construct a standards-compatible ZIP_STORED archive with local and central
// headers independently; the browser verifier may not trust its header SHA alone.
function zipStored(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBytes = Buffer.from(name, 'ascii');
    const blob = Buffer.from(data);
    let crc = 0xffffffff;
    for (const byte of blob) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    const part = Buffer.alloc(30 + nameBytes.length + blob.length);
    part.writeUInt32LE(0x04034b50, 0);
    part.writeUInt16LE(20, 4);
    part.writeUInt32LE(crc, 14);
    part.writeUInt32LE(blob.length, 18);
    part.writeUInt32LE(blob.length, 22);
    part.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(part, 30);
    blob.copy(part, 30 + nameBytes.length);
    local.push(part);

    const directory = Buffer.alloc(46 + nameBytes.length);
    directory.writeUInt32LE(0x02014b50, 0);
    directory.writeUInt16LE(788, 4);
    directory.writeUInt16LE(20, 6);
    directory.writeUInt32LE(crc, 16);
    directory.writeUInt32LE(blob.length, 20);
    directory.writeUInt32LE(blob.length, 24);
    directory.writeUInt16LE(nameBytes.length, 28);
    directory.writeUInt32LE(offset, 42);
    nameBytes.copy(directory, 46);
    central.push(directory);
    offset += part.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

function fakeBinary(bytes, headers = {}) {
  return new Response(bytes, {
    status: 200, headers: { 'Content-Type': 'application/zip', ...headers },
  });
}

test('artifact service binds signed versions and carries bearer only in header', async () => {
  const sent = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ url, init });
    return fakeJson({ items: [], total: 0 });
  };
  assert.deepEqual(await artifacts.flowArtifactsApi.list('flow-one', 7, 3), []);
  assert.equal(sent.length, 1);
  assert.match(sent[0].url, /\/flows\/flow-one\/artifacts\?expected_revision=7&expected_authorization_version=3$/);
  assert.equal(sent[0].init.method, 'GET');
  assert.match(sent[0].init.headers.Authorization, /^Bearer /);
  assert.doesNotMatch(sent[0].url, /Bearer|token|signature/);
  await assert.rejects(artifacts.flowArtifactsApi.list('flow/foreign', 7, 3), /identity/);
  assert.equal(sent.length, 1);
});

test('artifact upload refuses unsafe filename or size before provider I/O', async () => {
  let requests = 0;
  globalThis.fetch = async () => {
    requests += 1;
    return fakeJson({});
  };
  for (const name of ['../evil', '..', 'sub\\evil', 'a:token', '']) {
    assert.throws(() => artifacts.artifactName(name), /filename/);
  }
  const fake = { name: 'valid.txt', size: 2 * 1024 * 1024 + 1 };
  await assert.rejects(artifacts.flowArtifactsApi.upload('flow-one', 7, 3, fake), /2 MiB/);
  assert.equal(requests, 0);
});

test('artifact download is checked by SHA-256 before browser receives bytes', async () => {
  const bytes = new TextEncoder().encode('synthetic-only');
  const hash = Array.from(new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes)),
    (byte) => byte.toString(16).padStart(2, '0')).join('');
  const entry = {
    id: 'artifact-' + 'a'.repeat(32), flow_id: 'flow-one', name: 'synthetic.txt',
    size_bytes: bytes.length, sha256: hash, flow_revision: 7,
    authorization_version: 3,
  };
  let corrupt = false;
  globalThis.fetch = async () => ({
    ok: true, status: 200,
    arrayBuffer: async () => corrupt ? new Uint8Array([0, 1]).buffer : bytes.buffer,
    headers: { get: () => hash },
  });
  const blob = await artifacts.flowArtifactsApi.download('flow-one', 7, 3, entry);
  assert.equal(blob.size, bytes.length);
  corrupt = true;
  await assert.rejects(artifacts.flowArtifactsApi.download('flow-one', 7, 3, entry),
    /size no longer matches/);
});

test('stale backend revision never becomes a successful stored artifact', async () => {
  globalThis.fetch = async () => fakeJson({ detail: 'stale revision' }, 409);
  await assert.rejects(artifacts.flowArtifactsApi.list('flow-one', 7, 3), /revision changed/);
});

test('React panel shows inert evidence semantics, no implied target execution', () => {
  const markup = renderToStaticMarkup(createElement(component.FlowArtifactsPanel, {
    flowId: 'flow-one', engagementId: 'eng-test', revision: 7,
  }));
  assert.match(markup, /Flow evidence artifacts/);
  assert.match(markup, /Authorization unverified/);
  assert.match(markup, /inert bytes/);
  assert.match(markup, /UPLOAD ARTIFACT/);
  assert.match(markup, /VERIFY RESOURCE MANIFEST/);
  assert.match(markup, /VERIFY &amp; EXPORT INERT ZIP/);
});

test('manifest is independently digested and rejects changed ownership or malformed fields', async () => {
  const { manifest } = await resourceFixture();
  let requests = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url, init });
    return {
      ...fakeJson(manifest),
      headers: { get: (name) => name === 'X-Resource-Manifest-SHA256'
        ? manifest.manifest_sha256 : null },
    };
  };
  assert.deepEqual(await artifacts.flowArtifactsApi.resourceManifest('flow-one', 7, 3), manifest);
  assert.match(requests[0].url, /resource-manifest\?expected_revision=7&expected_authorization_version=3$/);
  assert.match(requests[0].init.headers.Authorization, /^Bearer /);
  assert.doesNotMatch(requests[0].url, /token|Bearer|signature/);
  await assert.rejects(artifacts.flowArtifactsApi.resourceManifest('flow-one', 8, 3), /scope|integrity/);
  await assert.rejects(artifacts.flowArtifactsApi.resourceManifest('flow-one', 7, 4), /scope|integrity/);

  manifest.items[0].sha256 = '0'.repeat(64);
  await assert.rejects(artifacts.flowArtifactsApi.resourceManifest('flow-one', 7, 3), /SHA-256/);
  manifest.items[0].sha256 = '1'.repeat(64);
  manifest.unexpected = 'hidden';
  await assert.rejects(artifacts.flowArtifactsApi.resourceManifest('flow-one', 7, 3), /scope|integrity/);
});

test('resource bundles verify every ZIP member hash, directory and embedded manifest', async () => {
  const { manifest, source } = await resourceFixture();
  const packed = zipStored([
    ['resources/test.py', source],
    ['resource-manifest.json', new TextEncoder().encode(canonical(manifest))],
  ]);
  let reply = fakeBinary(packed, {
    'X-Resource-Manifest-SHA256': manifest.manifest_sha256,
    'X-Resource-Archive-SHA256': await sha(packed),
  });
  globalThis.fetch = async () => reply;
  const valid = await artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, manifest);
  assert.equal(valid.size, packed.length);
  const modified = Buffer.from(packed);
  modified[30 + 'resources/test.py'.length] ^= 1;
  reply = fakeBinary(modified, {
    'X-Resource-Manifest-SHA256': manifest.manifest_sha256,
    'X-Resource-Archive-SHA256': await sha(modified),
  });
  await assert.rejects(artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, manifest),
    /archive member integrity/);
  const renamed = Buffer.from(packed);
  renamed[30] = 46; // traversal/synthetic member name, with a newly supplied archive digest
  reply = fakeBinary(renamed, {
    'X-Resource-Manifest-SHA256': manifest.manifest_sha256,
    'X-Resource-Archive-SHA256': await sha(renamed),
  });
  await assert.rejects(artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, manifest),
    /archive member integrity/);
  // Forging central directory POSIX mode as a symlink is unsafe even if a
  // compromised server recomputes an archive checksum.
  const symlink = Buffer.from(packed);
  const centralOffset = symlink.readUInt32LE(symlink.length - 22 + 16);
  symlink.writeUInt32LE(0xa0000000, centralOffset + 38);
  reply = fakeBinary(symlink, {
    'X-Resource-Manifest-SHA256': manifest.manifest_sha256,
    'X-Resource-Archive-SHA256': await sha(symlink),
  });
  await assert.rejects(artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, manifest),
    /archive member integrity/);
});

test('resource download denies stale or oversized responses and does not materialize unverified bytes', async () => {
  const { manifest } = await resourceFixture();
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    return fakeJson({}, 403);
  };
  await assert.rejects(artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, manifest),
    /authorization/);
  assert.equal(calls, 1);
  const tampered = structuredClone(manifest);
  tampered.total_size_bytes++;
  await assert.rejects(artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, tampered),
    /manifest|scope|integrity/);
  assert.equal(calls, 1);
  globalThis.fetch = async () => fakeBinary(new Uint8Array(0), {
    'Content-Length': String(5 * 1024 * 1024),
    'X-Resource-Manifest-SHA256': manifest.manifest_sha256,
    'X-Resource-Archive-SHA256': '0'.repeat(64),
  });
  await assert.rejects(artifacts.flowArtifactsApi.resourceBundle('flow-one', 7, 3, manifest),
    /safe transfer size/);
});
