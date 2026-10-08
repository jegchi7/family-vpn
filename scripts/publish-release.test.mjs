import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {linkSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {githubTransport, localAssets, matchingRelease, missingAssets, publicationContext, publishRelease} from './publish-release.mjs';

const commit = 'a'.repeat(40);
const context = {repository: 'jegchi7/family-vpn', commit, version: '0.27.0', tag: 'v0.27.0'};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const environment = {
  GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main',
  GITHUB_REPOSITORY: context.repository, GITHUB_SERVER_URL: 'https://github.com',
  GITHUB_API_URL: 'https://api.github.com', GITHUB_SHA: commit
};

function fixtures(t) {
  const directory = mkdtempSync(join(tmpdir(), 'fvpn-publication-'));
  t.after(() => rmSync(directory, {recursive: true, force: true}));
  for (const arch of ['amd64', 'arm64']) {
    const name = `family-vpn-v${context.version}-linux-${arch}.tar.gz`;
    const bytes = Buffer.from(`synthetic-${arch}-archive`);
    writeFileSync(join(directory, name), bytes);
    writeFileSync(join(directory, `${name}.sha256`), `${hash(bytes)}  ${name}\n`);
  }
  return {directory, assets: localAssets(directory, context.version)};
}

function remoteAsset(asset) {
  return {name: asset.name, state: 'uploaded', size: asset.size, digest: `sha256:${asset.digest}`};
}

function simulatedAPI(initial = null, remote = [], options = {}) {
  let release = initial ? structuredClone(initial) : null;
  let tag = release && !release.draft ? commit : null;
  const assets = remote.map(asset => structuredClone(asset));
  const calls = [];
  const api = async (method, path, body, type) => {
    calls.push({method, path, body, type});
    if (method === 'GET' && path.endsWith('/git/ref/heads/main')) return {object: {type: 'commit', sha: options.main ?? commit}};
    if (method === 'GET' && path.includes('/git/ref/tags/')) return tag ? {object: {type: 'commit', sha: options.tag ?? tag}} : null;
    if (method === 'GET' && path.endsWith(`/releases/tags/${context.tag}`)) return release && !release.draft ? {...release} : null;
    if (method === 'GET' && /\/releases\?per_page=100&page=1$/.test(path)) return release ? [{...release}] : [];
    if (method === 'GET' && /\/assets\?per_page=100&page=1$/.test(path)) return structuredClone(assets);
    if (method === 'POST' && path.endsWith('/releases')) {
      assert.equal(release, null, 'never create another draft for an existing version');
      release = {id: 7, ...body};
      return {...release};
    }
    if (method === 'POST' && path.includes('/assets?name=')) {
      const name = path.split('?name=')[1];
      assert.equal(assets.some(asset => asset.name === name), false, 'no asset replacement');
      const asset = remoteAsset({name, size: body.length, digest: hash(body)});
      assets.push(asset);
      return {...asset};
    }
    if (method === 'PATCH' && /\/releases\/7$/.test(path)) {
      release = {...release, ...body};
      tag = commit;
      return {...release};
    }
    throw new Error('Unexpected simulated API operation');
  };
  return {api, calls, assets};
}

test('publication requires official checked main push, not fork, PR, tag or local execution', () => {
  assert.deepEqual(publicationContext(environment, context.version), context);
  for (const [field, value] of [
    ['GITHUB_ACTIONS', 'false'], ['GITHUB_EVENT_NAME', 'pull_request'], ['GITHUB_REF', 'refs/tags/v0.27.0'],
    ['GITHUB_REPOSITORY', 'fork/family-vpn'], ['GITHUB_SERVER_URL', 'https://example.invalid'],
    ['GITHUB_API_URL', 'https://example.invalid'], ['GITHUB_SHA', 'main'], ['GITHUB_SHA', 'A'.repeat(40)]
  ]) assert.throws(() => publicationContext({...environment, [field]: value}, context.version));
  for (const version of ['0.27.0-beta', '../key', 'v0.27.0', '0.27']) assert.throws(() => publicationContext(environment, version));
});

test('both immutable bundle checksums must verify and asset links are rejected', t => {
  const {directory, assets} = fixtures(t);
  assert.equal(assets.length, 4);
  const asset = assets[0];
  const path = join(directory, asset.name);
  writeFileSync(`${path}.sha256`, `${'0'.repeat(64)}  ${asset.name}\n`);
  assert.throws(() => localAssets(directory, context.version), /checksum/);
  writeFileSync(`${path}.sha256`, `${asset.digest}  ${asset.name}\n`);
  const disguised = readFileSync(`${path}.sha256`);
  disguised[0] |= 0x80;
  writeFileSync(`${path}.sha256`, disguised);
  assert.throws(() => localAssets(directory, context.version), /checksum/);
  writeFileSync(`${path}.sha256`, `${asset.digest}  ${asset.name}\n`);
  linkSync(path, join(directory, 'alias'));
  assert.throws(() => localAssets(directory, context.version), /without links/);
});

test('different commit, release scope, duplicate, unknown or changed assets cannot be resumed', t => {
  const {assets} = fixtures(t);
  const release = {id: 7, tag_name: context.tag, target_commitish: commit, draft: true, prerelease: true};
  matchingRelease(release, context);
  for (const changed of [{target_commitish: 'b'.repeat(40)}, {tag_name: 'v0.26.0'}, {prerelease: false}, {draft: undefined}, {id: -1}]) {
    assert.throws(() => matchingRelease({...release, ...changed}, context));
  }
  const asset = remoteAsset(assets[0]);
  for (const remote of [[asset, asset], [{...asset, name: 'private.key'}], [{...asset, size: asset.size + 1}],
    [{...asset, digest: `sha256:${'0'.repeat(64)}`}], [{...asset, state: 'starter'}], [{...asset, digest: null}]]) {
    assert.throws(() => missingAssets(remote, assets));
  }
});

test('new release publishes only after all four uploaded digests verify and binds the tag', async t => {
  const {assets} = fixtures(t);
  const simulated = simulatedAPI();
  assert.deepEqual(await publishRelease(context, assets, simulated.api), {created: true, tag: context.tag});
  const writes = simulated.calls.filter(call => call.method !== 'GET');
  assert.deepEqual(writes.map(call => call.method), ['POST', 'POST', 'POST', 'POST', 'POST', 'PATCH']);
  assert.equal(writes[0].body.target_commitish, commit);
  assert.equal(writes[0].body.draft, true);
  assert.equal(writes.at(-1).body.draft, false);
  assert.deepEqual(simulated.assets.map(asset => asset.name), assets.map(asset => asset.name));
});

test('interrupted matching draft resumes only missing assets and never recreates or overwrites', async t => {
  const {assets} = fixtures(t);
  const simulated = simulatedAPI({id: 7, tag_name: context.tag, target_commitish: commit, draft: true, prerelease: true}, assets.slice(0, 2).map(remoteAsset));
  await publishRelease(context, assets, simulated.api);
  const writes = simulated.calls.filter(call => call.method !== 'GET');
  assert.deepEqual(writes.map(call => call.method), ['POST', 'POST', 'PATCH']);
  assert.equal(writes.every(call => !call.path.endsWith('/releases')), true);
});

test('published matching release is a read-only no-op; mismatched or incomplete release is untouched', async t => {
  const {assets} = fixtures(t);
  const release = {id: 7, tag_name: context.tag, target_commitish: commit, draft: false, prerelease: true};
  const simulated = simulatedAPI(release, assets.map(remoteAsset));
  assert.deepEqual(await publishRelease(context, assets, simulated.api), {created: false, tag: context.tag});
  assert.equal(simulated.calls.every(call => call.method === 'GET'), true);
  for (const [other, remote] of [[{...release, target_commitish: 'b'.repeat(40)}, assets.map(remoteAsset)], [release, assets.slice(0, 3).map(remoteAsset)]]) {
    const refused = simulatedAPI(other, remote);
    await assert.rejects(publishRelease(context, assets, refused.api));
    assert.equal(refused.calls.every(call => call.method === 'GET'), true);
  }
});

test('stale main or moved tag fails before release mutations', async t => {
  const {assets} = fixtures(t);
  const release = {id: 7, tag_name: context.tag, target_commitish: commit, draft: false, prerelease: true};
  for (const options of [{main: 'b'.repeat(40)}, {tag: 'b'.repeat(40)}]) {
    const simulated = simulatedAPI(release, assets.map(remoteAsset), options);
    await assert.rejects(publishRelease(context, assets, simulated.api));
    assert.equal(simulated.calls.every(call => call.method === 'GET'), true);
  }
});

test('main changing after uploads leaves draft unpublished without deleting assets', async t => {
  const {assets} = fixtures(t);
  const simulated = simulatedAPI();
  let reads = 0;
  const api = async (...args) => {
    if (args[0] === 'GET' && args[1].endsWith('/git/ref/heads/main') && ++reads === 2) {
      return {object: {type: 'commit', sha: 'b'.repeat(40)}};
    }
    return simulated.api(...args);
  };
  await assert.rejects(publishRelease(context, assets, api), /Main changed/);
  assert.equal(simulated.assets.length, 4);
  assert.equal(simulated.calls.some(call => call.method === 'PATCH'), false);
});

test('failed upload leaves an unpublished resumable draft and never cleans up remotely', async t => {
  const {assets} = fixtures(t);
  const simulated = simulatedAPI();
  let uploads = 0;
  const api = async (...args) => {
    if (args[0] === 'POST' && args[1].includes('/assets?name=') && ++uploads === 2) throw new Error('Synthetic upload failure');
    return simulated.api(...args);
  };
  await assert.rejects(publishRelease(context, assets, api), /Synthetic upload failure/);
  assert.equal(simulated.assets.length, 1);
  assert.equal(simulated.calls.some(call => call.method === 'PATCH' || call.method === 'DELETE'), false);
});

test('duplicate draft versions fail before any mutation', async t => {
  const {assets} = fixtures(t);
  const simulated = simulatedAPI();
  const draft = {id: 7, tag_name: context.tag, target_commitish: commit, draft: true, prerelease: true};
  const api = async (...args) => args[0] === 'GET' && /\/releases\?per_page=100&page=1$/.test(args[1])
    ? [draft, {...draft, id: 8}] : simulated.api(...args);
  await assert.rejects(publishRelease(context, assets, api), /Multiple releases/);
  assert.equal(simulated.calls.every(call => call.method === 'GET'), true);
});

test('metadata transport is fixed-host, refuses redirects and redacts errors', async () => {
  const token = 'synthetic-actions-token';
  const calls = [];
  const api = githubTransport(token, async (url, options) => {
    calls.push({url, options});
    return new Response('{}', {headers: {'content-type': 'application/json'}});
  });
  await api('GET', '/repos/jegchi7/family-vpn/releases/tags/v0.27.0');
  assert.equal(calls[0].url.startsWith('https://api.github.com/'), true);
  assert.equal(calls[0].options.redirect, 'error');
  await api('POST', '/repos/jegchi7/family-vpn/releases/7/assets?name=family-vpn-v0.27.0-linux-amd64.tar.gz', Buffer.from('synthetic'), 'application/gzip');
  assert.equal(calls[1].url.startsWith('https://uploads.github.com/'), true);
  for (const [method, path] of [['DELETE', '/repos/jegchi7/family-vpn/releases/7'], ['POST', '/repos/fork/family-vpn/releases'], ['GET', 'https://example.invalid'],
    ['GET', '/repos/jegchi7/family-vpn/../../fork/releases'], ['GET', '/repos/jegchi7/family-vpn/%2e%2e/releases'],
    ['POST', '/repos/jegchi7/family-vpn/releases/7/assets?name=private.key']]) {
    await assert.rejects(api(method, path));
  }
  const failed = githubTransport(token, async () => { throw new Error(token); });
  await assert.rejects(failed('GET', '/repos/jegchi7/family-vpn/releases/tags/v0.27.0'), error => !error.message.includes(token));
  const rejected = githubTransport(token, async () => new Response(token, {status: 403}));
  await assert.rejects(rejected('POST', '/repos/jegchi7/family-vpn/releases', {}), error => !error.message.includes(token));
  const oversized = githubTransport(token, async () => new Response(' '.repeat(1024 * 1024 + 1)));
  await assert.rejects(oversized('GET', '/repos/jegchi7/family-vpn/releases/tags/v0.27.0'), /bounds/);
  const streamFailure = githubTransport(token, async () => new Response(new ReadableStream({start(controller) { controller.error(new Error(token)); }})));
  await assert.rejects(streamFailure('GET', '/repos/jegchi7/family-vpn/releases/tags/v0.27.0'), error => !error.message.includes(token));
});

test('workflow gates release writes behind every existing check and excludes fork/PR execution', () => {
  const workflow = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  const jobs = workflow.split('  publish-bootstrap:');
  assert.equal(jobs.length, 2);
  for (const check of ['npm run check', 'npm run test:e2e', 'npm run test:e2e:auth', 'npm run test:e2e:admin']) assert.equal(jobs[0].includes(check), true);
  assert.match(jobs[1], /needs: local-demo/);
  assert.match(jobs[1], /github\.event_name == 'push'.*github\.ref == 'refs\/heads\/main'.*github\.repository == 'jegchi7\/family-vpn'/);
  assert.match(jobs[1], /contents: write/);
  assert.match(jobs[1], /--arch amd64/);
  assert.match(jobs[1], /--arch arm64/);
  assert.equal(jobs[0].includes('contents: write'), false);
});
