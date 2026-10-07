import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {basename, dirname, join} from 'node:path';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {collectFrontend, encodeTar, parseArguments, releaseFiles} from './release.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function fixture(t) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'family-vpn-release-test-'));
  t.after(() => {
    assert.equal(dirname(root), realpathSync(tmpdir()));
    assert.equal(basename(root).startsWith('family-vpn-release-test-'), true);
    rmSync(root, {recursive: true, force: true});
  });
  const dist = join(root, 'dist');
  mkdirSync(dist);
  writeFileSync(join(dist, 'index.html'), '<!doctype html><script src="/assets/app.js"></script>');
  mkdirSync(join(dist, 'assets'));
  writeFileSync(join(dist, 'assets', 'app.js'), 'console.log("stand");');
  return {root, dist};
}

// Independent small reader validates USTAR headers/checksums without reusing writer logic.
function inspectTar(bytes) {
  const files = new Map();
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      assert.equal(bytes.subarray(offset).every(byte => byte === 0), true);
      assert.ok(bytes.length - offset >= 1024);
      return files;
    }
    const string = (start, size) => header.subarray(start, start + size).toString('ascii').split('\0')[0];
    const octal = (start, size) => Number.parseInt(string(start, size).trim(), 8);
    assert.equal(string(257, 6), 'ustar');
    assert.equal(string(263, 2), '00');
    const sum = header.reduce((total, byte, index) => total + (index >= 148 && index < 156 ? 32 : byte), 0);
    assert.equal(octal(148, 8), sum);
    const name = [string(345, 155), string(0, 100)].filter(Boolean).join('/');
    assert.equal(files.has(name), false);
    const size = octal(124, 12);
    const type = string(156, 1);
    assert.ok(type === '0' || type === '5');
    const data = bytes.subarray(offset + 512, offset + 512 + size);
    assert.equal(data.length, size);
    files.set(name, {mode: octal(100, 8), type, data, uid: octal(108, 8), gid: octal(116, 8), mtime: octal(136, 12)});
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  assert.fail('Missing tar end blocks');
}

test('target selection is closed and rejects conflicting/injected flags', () => {
  assert.deepEqual(parseArguments([]), {arch: 'amd64'});
  assert.deepEqual(parseArguments(['--arch', 'arm64']), {arch: 'arm64'});
  for (const args of [['--arch', 'windows'], ['--arch'], ['--arch', '../arm64'], ['--arch', 'amd64', '--arch', 'arm64'], ['--output', '../../keys'], ['--os', 'windows']]) {
    assert.throws(() => parseArguments(args));
  }
});

test('frontend collection ignores unrelated state and rejects private/hidden/unexpected inputs', t => {
  const {root, dist} = fixture(t);
  mkdirSync(join(root, 'var'));
  writeFileSync(join(root, 'var', 'secret.key'), 'not-a-key');
  assert.deepEqual(collectFrontend(dist).map(file => file.path), ['web/dist/assets/app.js', 'web/dist/index.html']);
  for (const name of ['private.key', 'tls.pem', 'state.db', 'tokens.json', 'app.js.map', '.env', '.git']) {
    const path = join(dist, name);
    writeFileSync(path, 'excluded');
    assert.throws(() => collectFrontend(dist));
    rmSync(path);
  }
});

test('frontend hardlink is rejected even with an allowed asset extension', t => {
  const {root, dist} = fixture(t);
  const privateFile = join(root, 'private.js');
  writeFileSync(privateFile, 'unrelated-private-data');
  linkSync(privateFile, join(dist, 'assets', 'linked.js'));
  assert.throws(() => collectFrontend(dist), /without links/);
});

test('frontend symlink and parent alias are rejected', t => {
  const {root, dist} = fixture(t);
  const alias = join(root, 'alias');
  // Windows junctions do not require the privilege needed for ordinary file symlinks.
  symlinkSync(dist, alias, process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => collectFrontend(alias), /aliases/);
  symlinkSync(join(dist, 'assets'), join(dist, 'linked-assets'), process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => collectFrontend(dist), /links/);
});

test('package metadata never attests Linux/native/client readiness and all declared bytes verify', t => {
  const {dist} = fixture(t);
  const files = releaseFiles('0.24.0', 'arm64', [{path: 'build/portal', mode: 0o755, bytes: Buffer.from('synthetic-binary')}, ...collectFrontend(dist)]);
  const manifest = JSON.parse(files.find(file => file.path === 'release.json').bytes);
  assert.deepEqual(manifest.target, {os: 'linux', arch: 'arm64', cgo_enabled: false});
  assert.equal(Object.values(manifest.acceptance).every(value => value === false), true);
  assert.equal(manifest.scope.production, false);
  assert.equal(manifest.scope.vpn_ready, false);
  assert.equal(manifest.scope.profile_delivery_available, false);
  for (const record of manifest.files) {
    const file = files.find(file => file.path === record.path);
    assert.equal(record.sha256, hash(file.bytes));
    assert.equal(record.size, file.bytes.length);
  }
  for (const line of files.find(file => file.path === 'SHA256SUMS').bytes.toString().trim().split('\n')) {
    const [digest, path] = line.split('  ');
    assert.equal(digest, hash(files.find(file => file.path === path).bytes));
  }
});

test('USTAR preserves executable bits, data, ownership, long paths and deterministic bytes', () => {
  const files = [
    {path: 'build/portal', mode: 0o755, bytes: Buffer.from('synthetic-ELF-data')},
    {path: `web/dist/assets/${'a'.repeat(75)}.js`, mode: 0o644, bytes: Buffer.alloc(513, 0x61)},
    {path: 'docs/stand-runbook.md', mode: 0o644, bytes: Buffer.from('Проверка Unicode содержимого')}
  ];
  const prefix = 'family-vpn-v0.24.0-linux-amd64';
  const archive = encodeTar(files, prefix);
  assert.deepEqual(archive, encodeTar(files, prefix));
  const actual = inspectTar(archive);
  assert.equal(actual.get(`${prefix}/build/portal`).mode, 0o755);
  for (const file of files) assert.deepEqual(actual.get(`${prefix}/${file.path}`).data, file.bytes);
  for (const entry of actual.values()) {
    assert.equal(entry.uid, 0);
    assert.equal(entry.gid, 0);
    assert.equal(entry.mtime, 0);
  }
});

test('archive rejects traversal, hidden, duplicate and path collision entries', () => {
  const file = path => ({path, mode: 0o644, bytes: Buffer.from('x')});
  for (const path of ['../key', '/absolute', 'build/../../key', 'build\\portal', 'web/dist/.env']) {
    assert.throws(() => encodeTar([file(path)], 'release'));
  }
  assert.throws(() => encodeTar([file('build/portal'), file('build/portal')], 'release'));
  assert.throws(() => encodeTar([file('build'), file('build/portal')], 'release'));
});

test('system tar can list and extract the archive without extra entries', t => {
  const {root} = fixture(t);
  const files = [{path: 'build/portal', mode: 0o755, bytes: Buffer.from('binary-test')}, {path: 'web/dist/index.html', mode: 0o644, bytes: Buffer.from('<html>test</html>')}];
  const prefix = 'release-test';
  const archive = join(root, 'stand.tar');
  const out = join(root, 'extract');
  writeFileSync(archive, encodeTar(files, prefix));
  mkdirSync(out);
  const listed = spawnSync('tar', ['-tf', archive], {encoding: 'utf8'});
  assert.ifError(listed.error);
  assert.equal(listed.status, 0, listed.stderr);
  assert.deepEqual(new Set(listed.stdout.trim().split(/\r?\n/).map(path => path.replace(/\/$/, ''))), new Set(inspectTar(readFileSync(archive)).keys()));
  const extraction = spawnSync('tar', ['-xf', archive, '-C', out], {encoding: 'utf8'});
  assert.ifError(extraction.error);
  assert.equal(extraction.status, 0, extraction.stderr);
  for (const file of files) assert.deepEqual(readFileSync(join(out, prefix, file.path)), file.bytes);
  if (process.platform !== 'win32') assert.equal(lstatSync(join(out, prefix, 'build', 'portal')).mode & 0o777, 0o755);
});
