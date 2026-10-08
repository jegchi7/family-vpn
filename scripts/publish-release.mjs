import {createHash} from 'node:crypto';
import {lstatSync, readFileSync, realpathSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const repository = 'jegchi7/family-vpn';
const workspace = resolve(fileURLToPath(new URL('..', import.meta.url)));
const maxAssetBytes = 256 * 1024 * 1024;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

export function publicationContext(environment, version) {
  if (environment.GITHUB_ACTIONS !== 'true' || environment.GITHUB_EVENT_NAME !== 'push' ||
      environment.GITHUB_REF !== 'refs/heads/main' || environment.GITHUB_REPOSITORY !== repository ||
      environment.GITHUB_SERVER_URL !== 'https://github.com' || environment.GITHUB_API_URL !== 'https://api.github.com' ||
      !/^[a-f0-9]{40}$/.test(environment.GITHUB_SHA ?? '') || !/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error('Release publication requires an official main push and a stable numeric version');
  }
  return {repository, commit: environment.GITHUB_SHA, version, tag: `v${version}`};
}

function regularFile(path, limit) {
  if (realpathSync(dirname(path)) !== resolve(dirname(path))) throw new Error('Release asset parent aliases are forbidden');
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size <= 0 || stat.size > limit) {
    throw new Error('Release assets must be bounded regular files without links');
  }
  return readFileSync(path);
}

export function localAssets(directory, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid release version');
  const result = [];
  for (const arch of ['amd64', 'arm64']) {
    const name = `family-vpn-v${version}-linux-${arch}.tar.gz`;
    const archive = regularFile(resolve(directory, name), maxAssetBytes);
    const digest = hash(archive);
    const checksum = regularFile(resolve(directory, `${name}.sha256`), 512);
    if (!checksum.equals(Buffer.from(`${digest}  ${name}\n`))) throw new Error('Release archive checksum does not match');
    result.push({name, bytes: archive, size: archive.length, digest, type: 'application/gzip'});
    result.push({name: `${name}.sha256`, bytes: checksum, size: checksum.length, digest: hash(checksum), type: 'text/plain'});
  }
  return result;
}

export function matchingRelease(release, context) {
  if (!Number.isSafeInteger(release?.id) || release.id <= 0 || release.tag_name !== context.tag ||
      release.target_commitish !== context.commit || release.prerelease !== true || typeof release.draft !== 'boolean') {
    throw new Error('Existing release belongs to a different commit or scope; bump the package version');
  }
}

export function missingAssets(remote, local) {
  if (!Array.isArray(remote) || remote.length > local.length) throw new Error('Unexpected existing release assets');
  const expected = new Map(local.map(asset => [asset.name, asset]));
  const seen = new Set();
  for (const asset of remote) {
    const wanted = expected.get(asset?.name);
    if (!wanted || seen.has(asset.name) || asset.state !== 'uploaded' || asset.size !== wanted.size ||
        asset.digest !== `sha256:${wanted.digest}`) {
      throw new Error('Existing release asset conflicts; assets are never replaced or deleted');
    }
    seen.add(asset.name);
  }
  return local.filter(asset => !seen.has(asset.name));
}

export function githubTransport(token, fetcher = fetch) {
  if (typeof token !== 'string' || token.length < 8 || /\s/.test(token)) throw new Error('Actions publication token is unavailable');
  return async (method, path, body, type = 'application/json') => {
    const upload = type !== 'application/json';
    const base = `/repos/${repository}`;
    const version = 'v\\d+\\.\\d+\\.\\d+';
    const get = new RegExp(`^${base}(?:/git/ref/(?:heads/main|tags/${version})|/releases/tags/${version}|/releases\\?per_page=100&page=(?:[1-9]|10)|/releases/[1-9]\\d*/assets\\?per_page=100&page=1)$`);
    const binary = new RegExp(`^${base}/releases/[1-9]\\d*/assets\\?name=family-vpn-${version}-linux-(?:amd64|arm64)\\.tar\\.gz(?:\\.sha256)?$`);
    const valid = upload
      ? method === 'POST' && ['application/gzip', 'text/plain'].includes(type) && binary.test(path)
      : (method === 'GET' && body === undefined && get.test(path)) ||
        (method === 'POST' && path === `${base}/releases`) ||
        (method === 'PATCH' && new RegExp(`^${base}/releases/[1-9]\\d*$`).test(path));
    if (!valid) {
      throw new Error('Unexpected release API operation');
    }
    const headers = {
      Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'family-vpn-release-publisher'
    };
    if (body !== undefined) headers['Content-Type'] = type;
    let response;
    try {
      response = await fetcher(`https://${upload ? 'uploads' : 'api'}.github.com${path}`, {
        method, headers, body: body === undefined ? undefined : upload ? body : JSON.stringify(body),
        redirect: 'error', signal: AbortSignal.timeout(90_000)
      });
    } catch {
      throw new Error('GitHub release request failed; no asset replacement or cleanup was attempted');
    }
    if (response.status === 404 && method === 'GET') return null;
    if (!response.ok) throw new Error(`GitHub release API rejected ${method} with status ${response.status}`);
    // API response text is never included in errors: it can contain URLs or request details.
    const length = Number(response.headers.get('content-length'));
    if (Number.isFinite(length) && length > 1024 * 1024) throw new Error('GitHub release metadata exceeds bounds');
    const reader = response.body?.getReader();
    if (!reader) throw new Error('GitHub release metadata is missing');
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    try {
      for (;;) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 1024 * 1024) { tooLarge = true; throw new Error('Metadata bounds'); }
        chunks.push(value);
      }
    } catch { throw new Error(tooLarge ? 'GitHub release metadata exceeds bounds' : 'GitHub release metadata read failed'); }
    finally { try { await reader.cancel(); } catch { /* Keep transport details out of errors. */ } }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw new Error('GitHub release metadata is invalid'); }
  };
}

async function currentMain(api, context) {
  const ref = await api('GET', `/repos/${repository}/git/ref/heads/main`);
  if (ref?.object?.type !== 'commit' || ref.object.sha !== context.commit) {
    throw new Error('Main changed while checks ran; only the checked current main commit may be published');
  }
}

async function expectedTag(api, context, missingAllowed = false) {
  const ref = await api('GET', `/repos/${repository}/git/ref/tags/${context.tag}`);
  if (!ref && missingAllowed) return;
  if (ref?.object?.type !== 'commit' || ref.object.sha !== context.commit) {
    throw new Error('Release tag does not point directly to the checked commit; tags are never moved');
  }
}

export async function publishRelease(context, assets, api) {
  const names = ['amd64', 'arm64'].flatMap(arch => {
    const name = `family-vpn-v${context.version}-linux-${arch}.tar.gz`;
    return [name, `${name}.sha256`];
  });
  if (assets.length !== 4 || new Set(assets.map(asset => asset.name)).size !== 4 ||
      assets.some(asset => !names.includes(asset.name) || !Buffer.isBuffer(asset.bytes) ||
        asset.size !== asset.bytes.length || asset.size <= 0 || asset.size > maxAssetBytes ||
        asset.digest !== hash(asset.bytes) || asset.type !== (asset.name.endsWith('.sha256') ? 'text/plain' : 'application/gzip'))) {
    throw new Error('Both architecture bundles and checksums are required');
  }
  await currentMain(api, context);
  const path = `/repos/${repository}/releases`;
  let release = await api('GET', `${path}/tags/${context.tag}`);
  if (!release) {
    // The tag endpoint only promises published releases. Authenticated list includes drafts.
    const matches = [];
    for (let page = 1; page <= 10; page++) {
      const list = await api('GET', `${path}?per_page=100&page=${page}`);
      if (!Array.isArray(list) || list.length > 100) throw new Error('GitHub release listing is invalid');
      matches.push(...list.filter(item => item?.tag_name === context.tag));
      if (list.length < 100) break;
      if (page === 10) throw new Error('Release listing exceeds bounds; no duplicate draft is created');
    }
    if (matches.length > 1) throw new Error('Multiple releases claim the same version; no release is modified');
    release = matches[0];
  }
  if (!release) {
    await expectedTag(api, context, true);
    release = await api('POST', path, {
      tag_name: context.tag, target_commitish: context.commit,
      name: `Family VPN ${context.tag} · operator bootstrap`,
      body: `Source commit: ${context.commit}\n\nPrebuilt Linux amd64/arm64 local-stand tools. Operator bootstrap installs pinned VPN cores and stages Foreign configuration. Services/network are not activated; native VPN, client round-trip and production acceptance remain open.\n\nAssets are bound to this commit and will not be replaced.`,
      draft: true, prerelease: true, make_latest: 'false', generate_release_notes: false
    });
  }
  matchingRelease(release, context);
  // A draft release need not create its tag until publication; an existing tag must already match.
  await expectedTag(api, context, release.draft);
  const remote = await api('GET', `${path}/${release.id}/assets?per_page=100&page=1`);
  const absent = missingAssets(remote, assets);
  if (!release.draft) {
    if (absent.length !== 0) throw new Error('Published release is incomplete; published assets are never modified');
    return {created: false, tag: context.tag};
  }
  for (const asset of absent) {
    const uploaded = await api('POST', `${path}/${release.id}/assets?name=${asset.name}`, asset.bytes, asset.type);
    missingAssets([uploaded], [asset]);
  }
  const completed = await api('GET', `${path}/${release.id}/assets?per_page=100&page=1`);
  if (missingAssets(completed, assets).length !== 0) throw new Error('Draft release remains incomplete');
  await currentMain(api, context);
  await expectedTag(api, context, true);
  const published = await api('PATCH', `${path}/${release.id}`, {draft: false, prerelease: true, make_latest: 'false'});
  matchingRelease(published, context);
  if (published.draft) throw new Error('GitHub did not confirm publication');
  await expectedTag(api, context);
  return {created: true, tag: context.tag};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw new Error('Publication takes no command-line overrides');
    const {version} = JSON.parse(readFileSync(resolve(workspace, 'package.json'), 'utf8'));
    const context = publicationContext(process.env, version);
    const assets = localAssets(resolve(workspace, 'build', 'releases'), version);
    const result = await publishRelease(context, assets, githubTransport(process.env.GITHUB_TOKEN));
    console.log(`Release ${result.tag}: ${result.created ? 'published' : 'already matches the checked commit and assets'}.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
