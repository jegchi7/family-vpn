import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync} from 'node:fs';
import {dirname, isAbsolute, relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync} from 'node:zlib';

const workspace = resolve(fileURLToPath(new URL('..', import.meta.url)));
const frontendExtensions = /\.(?:html|js|css|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|wasm)$/i;
const binaries = ['portal', 'admin', 'vpnctl'];

export function parseArguments(args) {
  let arch = 'amd64';
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== '--arch' || i + 1 >= args.length || i !== 0) throw new Error('Usage: release.mjs [--arch amd64|arm64]');
    arch = args[++i];
  }
  if (!['amd64', 'arm64'].includes(arch)) throw new Error('Only Linux amd64 and arm64 release targets are supported');
  return {arch};
}

function checkedRelative(path) {
  if (!/^[A-Za-z0-9._/-]+$/.test(path) || path.split('/').some(part => !part || part.startsWith('.'))) {
    throw new Error('Unsafe release asset name');
  }
  return path;
}

function checkedFile(path) {
  if (realpathSync(dirname(path)) !== resolve(dirname(path))) throw new Error('Release input parent directories must not contain links');
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error('Release inputs must be regular files without links');
  return stat;
}

export function collectFrontend(directory) {
  const files = [];
  if (realpathSync(directory) !== resolve(directory)) throw new Error('Frontend input must not contain directory aliases');
  function walk(current, prefix) {
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Frontend directories must not be symlinks');
    for (const name of readdirSync(current).sort()) {
      const asset = checkedRelative(prefix ? `${prefix}/${name}` : name);
      const path = resolve(current, name);
      const entry = lstatSync(path);
      if (entry.isSymbolicLink()) throw new Error('Frontend links are forbidden');
      if (entry.isDirectory()) walk(path, asset);
      else {
        checkedFile(path);
        if (!frontendExtensions.test(asset)) throw new Error('Unexpected frontend asset type; secrets, maps and state are never packaged');
        files.push({path: `web/dist/${asset}`, mode: 0o644, bytes: readFileSync(path)});
      }
    }
  }
  walk(resolve(directory), '');
  if (!files.some(file => file.path === 'web/dist/index.html')) throw new Error('Run npm run build first: web/dist/index.html is missing');
  return files;
}

function tarString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'ascii');
  if (bytes.length > length) throw new Error('Release path exceeds USTAR bounds');
  bytes.copy(header, offset);
}

function tarNumber(header, offset, length, value) {
  const octal = value.toString(8);
  if (!Number.isSafeInteger(value) || value < 0 || octal.length > length - 1) throw new Error('Release entry exceeds USTAR bounds');
  tarString(header, offset, length, `${octal.padStart(length - 1, '0')}\0`);
}

// Fixed ownership, modes and timestamps also preserve executable bits when built on Windows.
export function encodeTar(files, prefix) {
  checkedRelative(prefix);
  const entries = new Map([[prefix, {path: prefix, mode: 0o755, directory: true}]]);
  for (const file of files) {
    checkedRelative(file.path);
    const path = `${prefix}/${file.path}`;
    if (entries.has(path)) throw new Error('Duplicate release entry');
    const parts = path.split('/');
    for (let i = 1; i < parts.length; i++) {
      const directory = parts.slice(0, i).join('/');
      if (entries.has(directory) && !entries.get(directory).directory) throw new Error('Release path collision');
      entries.set(directory, {path: directory, mode: 0o755, directory: true});
    }
    entries.set(path, {...file, path});
  }
  const blocks = [];
  for (const entry of [...entries.values()].sort((a, b) => a.path.localeCompare(b.path, 'en'))) {
    const header = Buffer.alloc(512);
    let name = entry.path;
    let parent = '';
    if (name.length > 100) {
      const splits = [...name.matchAll(/\//g)].map(match => match.index).reverse();
      const split = splits.find(index => index <= 155 && name.length - index - 1 <= 100);
      if (split === undefined) throw new Error('Release path exceeds USTAR bounds');
      parent = name.slice(0, split);
      name = name.slice(split + 1);
    }
    const bytes = entry.directory ? Buffer.alloc(0) : entry.bytes;
    tarString(header, 0, 100, name);
    tarNumber(header, 100, 8, entry.mode);
    tarNumber(header, 108, 8, 0);
    tarNumber(header, 116, 8, 0);
    tarNumber(header, 124, 12, bytes.length);
    tarNumber(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    tarString(header, 156, 1, entry.directory ? '5' : '0');
    tarString(header, 257, 6, 'ustar\0');
    tarString(header, 263, 2, '00');
    tarString(header, 345, 155, parent);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    tarString(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
    blocks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function releaseFiles(version, arch, files) {
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path, 'en'));
  const manifest = {
    format: 1,
    name: 'family-vpn-local-stand',
    version,
    target: {os: 'linux', arch, cgo_enabled: false},
    build: {trimpath: true, buildvcs: false, frontend: 'prebuilt'},
    scope: {numeric_loopback_https_only: true, production: false, vpn_ready: false, profile_delivery_available: false},
    acceptance: {linux_execution: false, native_vpn: false, client_round_trip: false, uid_isolation: false},
    schemas: {portal: 6, admin: 1},
    files: sorted.map(file => ({path: file.path, size: file.bytes.length, mode: file.mode.toString(8), sha256: sha256(file.bytes)}))
  };
  const manifestFile = {path: 'release.json', mode: 0o644, bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)};
  const checksums = [...sorted, manifestFile].map(file => `${sha256(file.bytes)}  ${file.path}\n`).join('');
  return [...sorted, manifestFile, {path: 'SHA256SUMS', mode: 0o644, bytes: Buffer.from(checksums)}];
}

function outputDirectory() {
  const destination = resolve(workspace, 'build', 'releases');
  for (const path of [resolve(workspace, 'build'), destination]) {
    try {
      const stat = lstatSync(path);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Release output must be a workspace directory without links');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      mkdirSync(path);
    }
  }
  if (realpathSync(destination) !== destination) throw new Error('Release output must not resolve outside the workspace');
  return destination;
}

export function buildRelease(args = process.argv.slice(2)) {
  const {arch} = parseArguments(args);
  const {version} = JSON.parse(readFileSync(resolve(workspace, 'package.json'), 'utf8'));
  if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(version)) throw new Error('Invalid release version');
  // Frontend building/checks are deliberately separate; never rebuild dist while browsers use it.
  const files = collectFrontend(resolve(workspace, 'web', 'dist'));
  for (const path of ['scripts/admin-credentials.py', 'docs/stand-runbook.md']) {
    checkedFile(resolve(workspace, path));
    files.push({path, mode: path.endsWith('.py') ? 0o755 : 0o644, bytes: readFileSync(resolve(workspace, path))});
  }
  const destination = outputDirectory();
  const prefix = `family-vpn-v${version}-linux-${arch}`;
  const output = resolve(destination, `${prefix}.tar.gz`);
  for (const path of [output, `${output}.sha256`]) {
    try { lstatSync(path); throw new Error('Release artifact already exists; preserve it or explicitly remove it before rebuilding'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const stage = mkdtempSync(resolve(destination, '.staging-'));
  try {
    for (const name of binaries) {
      const path = resolve(stage, name);
      const result = spawnSync('go', ['build', '-buildvcs=false', '-trimpath', '-o', path, `./cmd/${name}`], {
        cwd: workspace,
        env: {...process.env, GOOS: 'linux', GOARCH: arch, CGO_ENABLED: '0', GOFLAGS: '', GOWORK: 'off', GOTOOLCHAIN: 'local'},
        stdio: 'inherit'
      });
      if (result.error) throw result.error;
      if (result.status !== 0) throw new Error(`Linux ${arch} ${name} cross-build failed`);
      checkedFile(path);
      files.push({path: `build/${name}`, mode: 0o755, bytes: readFileSync(path)});
    }
    const archive = gzipSync(encodeTar(releaseFiles(version, arch, files), prefix), {level: 9});
    writeFileSync(output, archive, {flag: 'wx', mode: 0o644});
    writeFileSync(`${output}.sha256`, `${sha256(archive)}  ${prefix}.tar.gz\n`, {flag: 'wx', mode: 0o644});
    console.log(`Created ${relative(workspace, output)}`);
    console.log('Cross-build only: Linux execution, native VPN, client and UID isolation acceptance remain false.');
    return output;
  } finally {
    // Only the freshly created staging directory, under this workspace, is eligible for cleanup.
    const staged = relative(destination, stage);
    if (isAbsolute(staged) || staged.startsWith(`..${sep}`) || !staged.startsWith('.staging-') || dirname(stage) !== destination) {
      throw new Error('Unsafe release staging cleanup path');
    }
    rmSync(stage, {recursive: true, force: true});
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { buildRelease(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
