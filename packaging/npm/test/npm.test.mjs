// node --test packaging/npm/test/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { assemble } from '../assemble.mjs';

const require = createRequire(import.meta.url);
const { TARGETS, resolvePlatform } = require('../agentforge-guard/lib/platform.js');
const here = path.dirname(fileURLToPath(import.meta.url));

test('resolves every release target to its platform package', () => {
  assert.deepEqual(resolvePlatform('darwin', 'arm64'), {
    pkg: 'agentforge-guard-darwin-arm64',
    target: 'aarch64-apple-darwin',
    bin: 'bin/afg',
  });
  assert.equal(resolvePlatform('win32', 'x64').bin, 'bin/afg.exe');
  assert.equal(Object.keys(TARGETS).length, 5);
});

test('unsupported platforms and musl fail with an actionable message', () => {
  for (const [p, a, g] of [['freebsd', 'x64', true], ['win32', 'arm64', true], ['linux', 'x64', false]]) {
    const r = resolvePlatform(p, a, g);
    assert.ok(r instanceof Error, `${p}-${a}`);
    assert.match(r.message, /cargo install agentforge-guard/);
  }
});

function fakeDist(version) {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-dist-'));
  const lines = [];
  for (const target of Object.values(TARGETS)) {
    const name = `afg-v${version}-${target}`;
    const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-stage-'));
    fs.mkdirSync(path.join(stage, name));
    const windows = target.includes('windows');
    fs.writeFileSync(path.join(stage, name, windows ? 'afg.exe' : 'afg'), `#!/bin/sh\necho ${target}\n`, { mode: 0o755 });
    const archive = `${name}.${windows ? 'zip' : 'tar.gz'}`;
    const r = windows
      ? spawnSync('zip', ['-qr', path.join(dist, archive), name], { cwd: stage })
      : spawnSync('tar', ['czf', path.join(dist, archive), name], { cwd: stage });
    assert.equal(r.status, 0, String(r.stderr));
    fs.rmSync(stage, { recursive: true });
    lines.push(`${createHash('sha256').update(fs.readFileSync(path.join(dist, archive))).digest('hex')}  ${archive}`);
  }
  fs.writeFileSync(path.join(dist, 'SHA256SUMS'), lines.join('\n') + '\n');
  return dist;
}

test('assembles platform packages and a launcher pinned to the same version', () => {
  const dist = fakeDist('1.2.3-rc.1');
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'afg-out-')), 'npm');
  const pkgs = assemble(dist, '1.2.3-rc.1', out);
  assert.equal(pkgs.length, 6);

  const main = JSON.parse(fs.readFileSync(path.join(out, 'agentforge-guard/package.json'), 'utf8'));
  assert.equal(main.version, '1.2.3-rc.1');
  assert.equal(main.scripts, undefined, 'no install-time scripts');
  assert.deepEqual(Object.values(main.optionalDependencies), Array(5).fill('1.2.3-rc.1'));

  const linux = JSON.parse(fs.readFileSync(path.join(out, 'agentforge-guard-linux-x64/package.json'), 'utf8'));
  assert.deepEqual([linux.os, linux.cpu], [['linux'], ['x64']]);
  const bin = path.join(out, 'agentforge-guard-linux-x64/bin/afg');
  assert.match(fs.readFileSync(bin, 'utf8'), /x86_64-unknown-linux-gnu/);
  assert.ok(fs.statSync(bin).mode & 0o111, 'binary is executable');
  assert.ok(fs.existsSync(path.join(out, 'agentforge-guard-win32-x64/bin/afg.exe')));
});

test('every package ships a README and the metadata supply-chain scanners check', () => {
  const dist = fakeDist('1.2.3');
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'afg-out-')), 'npm');
  for (const name of assemble(dist, '1.2.3', out)) {
    const dir = path.join(out, name);
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    for (const field of ['description', 'keywords', 'author', 'bugs', 'repository', 'homepage', 'license']) {
      assert.ok(pkg[field] && pkg[field].length !== 0, `${name} lacks ${field}`);
    }
    const readme = fs.readFileSync(path.join(dir, 'README.md'), 'utf8');
    assert.ok(readme.length > 200, `${name} README is too short`);
    if (name !== 'agentforge-guard') {
      assert.ok(pkg.files.includes('README.md'), `${name} does not publish its README`);
      const target = Object.values(TARGETS).find((t) => readme.includes(t));
      assert.ok(target, `${name} README does not name its target`);
      assert.match(readme, /SHA256SUMS/);
    }
  }
});

test('a tampered archive aborts assembly', () => {
  const dist = fakeDist('1.0.0');
  fs.appendFileSync(path.join(dist, 'afg-v1.0.0-aarch64-apple-darwin.tar.gz'), 'x');
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'afg-out-')), 'npm');
  assert.throws(() => assemble(dist, '1.0.0', out), /checksum mismatch for afg-v1.0.0-aarch64-apple-darwin.tar.gz/);
});

test('a missing target aborts assembly', () => {
  const dist = fakeDist('1.0.0');
  fs.rmSync(path.join(dist, 'afg-v1.0.0-x86_64-pc-windows-msvc.zip'));
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'afg-out-')), 'npm');
  assert.throws(() => assemble(dist, '1.0.0', out), /missing afg-v1.0.0-x86_64-pc-windows-msvc.zip/);
});

test('the launcher runs the platform binary and forwards args and exit code', { skip: process.platform === 'win32' }, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-launch-'));
  const found = resolvePlatform(process.platform, process.arch);
  if (found instanceof Error) return;
  const pkgDir = path.join(root, 'node_modules', found.pkg);
  fs.mkdirSync(path.join(pkgDir, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: found.pkg, version: '0.0.0' }));
  fs.writeFileSync(path.join(pkgDir, found.bin), '#!/bin/sh\necho "args:$*"\nexit 7\n', { mode: 0o755 });
  const launcher = path.join(root, 'node_modules/agentforge-guard');
  fs.cpSync(path.join(here, '../agentforge-guard'), launcher, { recursive: true });
  const r = spawnSync(process.execPath, [path.join(launcher, 'bin/afg.js'), 'policy', 'explain', '--', 'rm -rf /'], { encoding: 'utf8' });
  assert.equal(r.stdout.trim(), 'args:policy explain -- rm -rf /');
  assert.equal(r.status, 7);
});
