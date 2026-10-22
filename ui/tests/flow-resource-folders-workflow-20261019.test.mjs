import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const originalFetch = globalThis.fetch;
const SHA = 'a'.repeat(64);
const AUTH_SHA = 'b'.repeat(64);
const MANIFEST_SHA = 'c'.repeat(64);
const A_ID = `artifact-${'e'.repeat(32)}`;
const F_ID = `folder-${'f'.repeat(32)}`;
const F_NEW = `folder-${'d'.repeat(32)}`;
const engagementId = 'eng-virtual-folders';
const flowId = 'flow-virtual-folders';
const signed = {
  flowId, engagementId, flowRevision: 3, authorizationVersion: 2,
  authorizationId:'auth-signed-review', authorizationSha256:AUTH_SHA,
  manifestSha256:MANIFEST_SHA,
};
const resource = {
  artifact_id:A_ID, artifact_sha256:SHA, original_name:'notes.txt',
  classification:'utf8_inert_text',size_bytes:125,
};
const source = {
  format:'ai-osop-flow-resource-folders-v1',
  flow_id:flowId,engagement_id:engagementId,flow_revision:3,
  authorization_version:2,authorization_id:signed.authorizationId,
  authorization_sha256:AUTH_SHA,source_manifest_sha256:MANIFEST_SHA,
  catalog_revision:1,
  folders:[{folder_id:F_ID,name:'research_notes',items:[]}],
  unassigned:[resource],
  metadata_only:true,host_files_created:false,worker_sync_performed:false,
};
const body = value => JSON.stringify(value);
const reply = (value,status=200) => new Response(body(value),{
  status, headers:{'Content-Type':'application/json'},
});
const deep = value => structuredClone(value);
let vite, auth, folders, panel, calls, responses, exp, actorRole, actorName;

before(async () => {
  vite = await createServer({root, appType:'custom',logLevel:'silent',server:{middlewareMode:true}});
  auth = await vite.ssrLoadModule('/src/services/api.ts');
  folders = await vite.ssrLoadModule('/src/services/flowResourceFolders.ts');
  panel = await vite.ssrLoadModule('/src/components/flows/FlowResourceFoldersPanel.tsx');
});
after(async () => {
  auth?.signOut();
  globalThis.fetch = originalFetch;
  await vite?.close();
});
async function signIn({role='operator', sub='signed-owner'}={}) {
  auth.signOut();
  calls = []; responses = []; actorRole = role; actorName = sub;
  exp = Math.floor(Date.now()/1000)+3600;
  globalThis.fetch = async (url,options={}) => {
    const target = new URL(String(url));
    calls.push({url:String(url),path:target.pathname,query:target.searchParams,options});
    if (target.pathname === '/auth/me') return reply({sub:actorName,role:actorRole,exp});
    if (!responses.length) throw Error('Explicit response was not queued.');
    const answer = responses.shift();
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer() : answer;
  };
  await auth.signIn('only-signed-in-tab-operator-bearer');
  calls=[];
}
function queue(...answers) {responses.push(...answers);}
function posted(catalog,operation,status=200) {
  return reply({...catalog,operation,event_id:'evt-resource-folder-change'},status);
}
function assertPrivate(call, method) {
  assert.equal(call.options.method,method);
  assert.equal(call.options.headers.Authorization,'Bearer only-signed-in-tab-operator-bearer');
  assert.equal(call.options.credentials,'omit');
  assert.equal(call.options.redirect,'error');
  assert.equal(call.options.referrerPolicy,'no-referrer');
  assert.equal(call.options.cache,'no-store');
  assert.equal(call.options.headers.Accept,'application/json');
  assert.equal(call.query.get('expected_engagement_id'),engagementId);
  assert.equal(call.query.get('expected_revision'),'3');
  assert.equal(call.query.get('expected_authorization_version'),'2');
  assert.equal(call.query.get('expected_authorization_id'),signed.authorizationId);
  assert.equal(call.query.get('expected_authorization_sha256'),AUTH_SHA);
  assert.equal(call.query.get('expected_manifest_sha256'),MANIFEST_SHA);
  assert.equal(call.path,`/flows/${flowId}/resource-folders`);
  assert.doesNotMatch(call.url,/Bearer|only-signed-in-tab|private-token/);
}
function withFolder(name='research_notes', id=F_ID) {
  return {...deep(source),folders:[{folder_id:id,name,items:[]}]};
}

test('selected Flow panel export and mount contract have no execution/sync claims', async () => {
  await signIn();
  const markup = renderToStaticMarkup(createElement(panel.FlowResourceFoldersPanel,{
    flowId,engagementId,revision:3,flowStatus:'pending',authorizationId:signed.authorizationId,
  }));
  assert.match(markup,/Signed Flow resource folders — persisted VIRTUAL metadata only/);
  assert.match(markup,/independently approved senior Flow artifact review/);
  assert.match(markup,/never moves bytes/i);
  assert.match(markup,/READ CURRENT SIGNED FOLDER CATALOG/);
  const page = readFileSync(new URL('../src/pages/FlowOperations.tsx',import.meta.url),'utf8');
  assert.match(page,/<FlowResourceFoldersPanel/);
});

test('GET checks signed bearer, all six ROE/Flow/manifest query fences, nested catalog', async () => {
  await signIn();
  queue(reply(source));
  const actual = await folders.flowResourceFoldersApi.read(signed);
  assert.deepEqual(actual,source);
  assert.equal(calls.length,1);
  assertPrivate(calls[0],'GET');
});

test('create POST is one-shot CAS human-confirmed; only exact independent GET establishes success', async () => {
  await signIn();
  const after = {...deep(source),catalog_revision:2,folders:[
    ...source.folders,{folder_id:F_NEW,name:'audit_notes',items:[]},
  ]};
  queue(posted(after,'create',201),reply(after));
  const changed = await folders.flowResourceFoldersApi.mutate(
    signed,source,{operation:'create',name:'audit_notes'},true,
  );
  assert.deepEqual(changed,after);
  assert.equal(calls.length,2);
  assertPrivate(calls[0],'POST');
  assertPrivate(calls[1],'GET');
  assert.deepEqual(JSON.parse(calls[0].options.body),{
    operation:'create',name:'audit_notes',expected_catalog_revision:1,
    explicit_human_confirmation:true,
  });
  assert.doesNotMatch(calls[0].options.body,/api_key|response_body|target_url|container/);
  await assert.rejects(
    folders.flowResourceFoldersApi.mutate(signed,source,{operation:'create',name:'audit_notes'},true),
    /already attempted/,
  );
  assert.equal(calls.length,2);
});

test('renames, deletes, assigns and unassigns only with matching catalog CAS transition', async () => {
  await signIn();
  const ren = {...withFolder('change_notes'),catalog_revision:2};
  queue(posted(ren,'rename'),reply(ren));
  await folders.flowResourceFoldersApi.mutate(signed,source,{
    operation:'rename',folder_id:F_ID,name:'change_notes',
  },true);
  const erased = {...deep(source),catalog_revision:2,folders:[]};
  queue(posted(erased,'delete'),reply(erased));
  await folders.flowResourceFoldersApi.mutate(signed,source,{
    operation:'delete',folder_id:F_ID,
  },true);
  const allocated = {...deep(source),catalog_revision:2,
    folders:[{folder_id:F_ID,name:'research_notes',items:[resource]}],unassigned:[]};
  queue(posted(allocated,'assign'),reply(allocated));
  await folders.flowResourceFoldersApi.mutate(signed,source,{
    operation:'assign',folder_id:F_ID,artifact_id:A_ID,artifact_sha256:SHA,
  },true);
  const unallocated = {...deep(source),catalog_revision:3};
  queue(posted(unallocated,'unassign'),reply(unallocated));
  await folders.flowResourceFoldersApi.mutate(signed,allocated,{
    operation:'unassign',artifact_id:A_ID,artifact_sha256:SHA,
  },true);
  assert.deepEqual(JSON.parse(calls.at(-2).options.body),{
    operation:'unassign',artifact_id:A_ID,artifact_sha256:SHA,
    expected_catalog_revision:2,explicit_human_confirmation:true,
  });
  assert.equal(calls.length,8);
});

test('denies path traversal, slash names, forged raw bytes and unreviewed mutations BEFORE any HTTP', async () => {
  await signIn();
  const attacks = [
    {operation:'create',name:'../etc'},
    {operation:'create',name:'WrongCase'},
    {operation:'create',name:'../evil'},
    {operation:'create',name:'folder/name'},
    {operation:'create',name:'a'.repeat(49)},
    {operation:'assign',folder_id:F_ID,artifact_id:A_ID,artifact_sha256:'bad'},
    {operation:'assign',folder_id:'folder-../etc',artifact_id:A_ID,artifact_sha256:SHA},
    {operation:'assign',folder_id:F_ID,artifact_id:A_ID,artifact_sha256:SHA,headers:'Bearer danger'},
  ];
  for (const item of attacks) {
    await assert.rejects(folders.flowResourceFoldersApi.mutate(signed,source,item,true));
  }
  await assert.rejects(folders.flowResourceFoldersApi.mutate(
    signed,source,{operation:'create',name:'valid_name'},false,
  ),/confirmation/);
  assert.equal(calls.length,0);
});

test('foreign tenant, wrong SHA, unexpected bytes, false sync and duplicate nested artifact fail closed', async () => {
  await signIn();
  const forgeries = [
    {...source,engagement_id:'eng-foreign'},
    {...source,source_manifest_sha256:'b'.repeat(64)},
    {...source,worker_sync_performed:true},
    {...source,host_files_created:true},
    {...source,response_body:'Bearer private-token'},
    {...source,folders:[{folder_id:F_ID,name:'../secret',items:[]}]},
    {...source,folders:[{folder_id:F_ID,name:'research_notes',items:[resource]}]},
    {...source,unassigned:[{...resource,private_cookie:'secret'}]},
    {...source,unassigned:[{...resource,artifact_sha256:'not-sha'}]},
    {...source,catalog_revision:-1},
    {...source,folders:[{folder_id:F_ID,name:'research_notes',items:[]},
      {folder_id:F_ID,name:'copy',items:[]}]},
  ];
  for (const forged of forgeries) {
    queue(reply(forged));
    await assert.rejects(folders.flowResourceFoldersApi.read(signed));
  }
  assert.equal(calls.length,forgeries.length);
});

test('unknown POST network ACK cannot be replayed; signed GET can be inspected separately', async () => {
  await signIn();
  queue(new Error('lost acknowledgement'));
  const request = {operation:'create',name:'lost_reply'};
  await assert.rejects(folders.flowResourceFoldersApi.mutate(signed,source,request,true),/UNKNOWN/);
  assert.equal(calls.length,1);
  await assert.rejects(folders.flowResourceFoldersApi.mutate(signed,source,request,true),/already attempted/);
  assert.equal(calls.length,1);
  queue(reply(source));
  assert.equal((await folders.flowResourceFoldersApi.read(signed)).catalog_revision,1);
  assert.equal(calls.length,2);
});

test('post CAS anomaly, forged operation/event and inconsistent readback stay UNKNOWN', async () => {
  await signIn();
  const next = {...deep(source),catalog_revision:2,
    folders:[...source.folders,{folder_id:F_NEW,name:'post_wrong',items:[]}]};
  queue(posted({...next,catalog_revision:9},'create',201));
  await assert.rejects(folders.flowResourceFoldersApi.mutate(
    signed,source,{operation:'create',name:'post_wrong'},true,
  ),/UNKNOWN/);
  queue(posted(next,'delete',201));
  await assert.rejects(folders.flowResourceFoldersApi.mutate(
    signed,source,{operation:'create',name:'post_bad_event'},true,
  ),/UNKNOWN/);
  const valid = {...deep(source),catalog_revision:2,
    folders:[...source.folders,{folder_id:F_NEW,name:'readback_mismatch',items:[]}]};
  queue(posted(valid,'create',201),reply(source));
  await assert.rejects(folders.flowResourceFoldersApi.mutate(
    signed,source,{operation:'create',name:'readback_mismatch'},true,
  ),/UNKNOWN/);
});

test('operator switches mid response and invalid scope cause fail-closed outcome', async () => {
  await signIn();
  queue(() => {auth.signOut(); return reply(source);});
  await assert.rejects(folders.flowResourceFoldersApi.read(signed),/Operator|signed/);
  assert.equal(calls.length,1);
  await signIn({role:'viewer'});
  await assert.rejects(folders.flowResourceFoldersApi.read(signed));
  assert.equal(calls.length,0);
  await signIn();
  await assert.rejects(folders.flowResourceFoldersApi.read({...signed,authorizationSha256:'bad'}));
  await assert.rejects(folders.flowResourceFoldersApi.read({...signed,manifestSha256:'bad'}));
  assert.equal(calls.length,0);
});

test('oversized metadata response is rejected before JSON parsing', async () => {
  await signIn();
  queue(new Response('X'.repeat(33000),{status:200}));
  await assert.rejects(folders.flowResourceFoldersApi.read(signed),/exceeds|Unbounded/);
});

test('conflicting duplicate JSON security fields are rejected even when JSON.parse would pass', async () => {
  await signIn();
  const raw = JSON.stringify(source).replace(
    '"metadata_only":true',
    '"metadata_only":false,"metadata_only":true',
  );
  queue(new Response(raw,{status:200,headers:{'Content-Type':'application/json'}}));
  await assert.rejects(folders.flowResourceFoldersApi.read(signed),/Duplicate|Invalid signed folder JSON/);
  const nested = JSON.stringify(source).replace(
    '"artifact_sha256":"' + SHA + '"',
    '"artifact_sha256":"'+ 'f'.repeat(64) +'","artifact_sha256":"' + SHA + '"',
  );
  queue(new Response(nested,{status:200,headers:{'Content-Type':'application/json'}}));
  await assert.rejects(folders.flowResourceFoldersApi.read(signed),/Duplicate|Invalid signed folder JSON/);
});

test('a POST cannot silently rename unrelated folder names while adding a new one', async () => {
  await signIn();
  const modified = {...deep(source), catalog_revision:2, folders:[
    {...source.folders[0],name:'unexpected_change'},
    {folder_id:F_NEW,name:'added_proposal',items:[]},
  ]};
  queue(posted(modified,'create',201));
  await assert.rejects(folders.flowResourceFoldersApi.mutate(
    signed,source,{operation:'create',name:'added_proposal'},true,
  ),/UNKNOWN/);
  assert.equal(calls.length,1);
});
