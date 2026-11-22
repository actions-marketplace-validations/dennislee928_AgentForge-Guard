// node --test packaging/npm/test/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { assemble } from '../assemble.mjs';

const require = createRequire(import.meta.url);
const { TARGETS, resolvePlatform } = require('../agentforge-guard/lib/platform.js');

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

function installedFixture() {
  const version = '1.2.3-rc.1';
  const dist = fakeDist(version);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-integrity-'));
  const out = path.join(root, 'out');
  assemble(dist, version, out);
  const modules = path.join(root, 'node_modules');
  fs.renameSync(out, modules);
  const found = resolvePlatform(process.platform, process.arch);
  assert.ok(!(found instanceof Error));
  return {
    dir: path.join(modules, found.pkg),
    binary: path.join(modules, found.pkg, found.bin),
    launcher: path.join(modules, 'agentforge-guard', 'bin/afg.js'),
    cleanup() {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(dist, { recursive: true, force: true });
    },
  };
}

for (const failure of ['binary', 'same-size', 'version', 'manifest', 'digest', 'target', 'symlink']) {
  test(`launcher rejects ${failure} tampering before the binary runs`, { skip: process.platform === 'win32' }, () => {
    const fixture = installedFixture();
    try {
      const artifactFile = path.join(fixture.dir, 'artifact.json');
      if (failure === 'binary') fs.appendFileSync(fixture.binary, '# tampered\n');
      if (failure === 'same-size') {
        const bytes = fs.readFileSync(fixture.binary);
        bytes[bytes.length - 2] ^= 1;
        fs.writeFileSync(fixture.binary, bytes);
      }
      if (failure === 'version') {
        const file = path.join(fixture.dir, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
        pkg.version = '9.9.9';
        fs.writeFileSync(file, JSON.stringify(pkg));
      }
      if (failure === 'manifest') fs.rmSync(artifactFile, { force: true });
      if (failure === 'digest' || failure === 'target') {
        const manifest = JSON.parse(fs.readFileSync(artifactFile, 'utf8'));
        if (failure === 'digest') manifest.sha256 = 'invalid';
        else manifest.target = 'wrong-target';
        fs.writeFileSync(artifactFile, JSON.stringify(manifest));
      }
      if (failure === 'symlink') {
        fs.renameSync(fixture.binary, `${fixture.binary}.other`);
        fs.symlinkSync(`${fixture.binary}.other`, fixture.binary);
      }
      const ran = spawnSync(process.execPath, [fixture.launcher], { encoding: 'utf8' });
      assert.equal(ran.status, 1);
      assert.equal(ran.stdout, '', 'unverified binary must not run');
      assert.match(ran.stderr, /integrity|version mismatch/i);
    } finally {
      fixture.cleanup();
    }
  });
}

test('all npm artifacts ship runnable package tests and binary integrity metadata', () => {
  const dist = fakeDist('1.2.3-rc.1');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-selftest-'));
  try {
    const out = path.join(root, 'out');
    for (const name of assemble(dist, '1.2.3-rc.1', out)) {
      const dir = path.join(out, name);
      const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
      assert.deepEqual(pkg.scripts, { test: 'node --test test/package.test.cjs' });
      assert.ok(pkg.files.includes('test/package.test.cjs'));
      if (name !== 'agentforge-guard') {
        const artifact = JSON.parse(fs.readFileSync(path.join(dir, 'artifact.json'), 'utf8'));
        assert.equal(artifact.name, name);
        assert.equal(artifact.version, pkg.version);
        assert.equal(artifact.sha256, createHash('sha256').update(fs.readFileSync(path.join(dir, artifact.binary))).digest('hex'));
      }
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(dist, { recursive: true, force: true });
  }
});

test('assembles platform packages and a launcher pinned to the same version', () => {
  const dist = fakeDist('1.2.3-rc.1');
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'afg-out-')), 'npm');
  const pkgs = assemble(dist, '1.2.3-rc.1', out);
  assert.equal(pkgs.length, 6);

  const main = JSON.parse(fs.readFileSync(path.join(out, 'agentforge-guard/package.json'), 'utf8'));
  assert.equal(main.version, '1.2.3-rc.1');
  assert.deepEqual(main.scripts, { test: 'node --test test/package.test.cjs' }, 'only an explicit test command, no lifecycle hooks');
  assert.deepEqual(Object.values(main.optionalDependencies), Array(5).fill('1.2.3-rc.1'));

  const linux = JSON.parse(fs.readFileSync(path.join(out, 'agentforge-guard-linux-x64/package.json'), 'utf8'));
  assert.deepEqual([linux.os, linux.cpu], [['linux'], ['x64']]);
  const bin = path.join(out, 'agentforge-guard-linux-x64/bin/afg');
  assert.match(fs.readFileSync(bin, 'utf8'), /x86_64-unknown-linux-gnu/);
  assert.ok(fs.statSync(bin).mode & 0o111, 'binary is executable');
  assert.ok(fs.existsSync(path.join(out, 'agentforge-guard-win32-x64/bin/afg.exe')));
});

test('npm packages are MIT only and platform packages have a real entry point', () => {
  const dist = fakeDist('1.2.3');
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'afg-out-')), 'npm');
  const require2 = createRequire(import.meta.url);
  for (const name of assemble(dist, '1.2.3', out)) {
    const dir = path.join(out, name);
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    // One license per package: scanners read two license files as "Apache-2.0 AND MIT".
    assert.equal(pkg.license, 'MIT', `${name} license`);
    assert.ok(fs.existsSync(path.join(dir, 'LICENSE')), `${name} has LICENSE`);
    assert.ok(!fs.readdirSync(dir).some((f) => /APACHE/i.test(f)), `${name} ships no Apache license file`);
    assert.ok(!pkg.files.some((f) => /APACHE/i.test(f)), `${name} files list has no Apache license`);
    if (name !== 'agentforge-guard') {
      // A JS entry point that resolves to the shipped binary, so the package is not "empty".
      assert.equal(pkg.main, 'index.js', `${name} main`);
      assert.ok(pkg.files.includes('index.js'), `${name} publishes index.js`);
      const resolved = require2(path.join(dir, 'index.js'));
      assert.ok(fs.existsSync(resolved), `${name} index.js points at a file: ${resolved}`);
      assert.match(path.basename(resolved), /^afg(\.exe)?$/);
    }
  }
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

test('platform READMEs describe the JavaScript wrapper and give an exact verification identity', () => {
  const dist = fakeDist('1.2.3-rc.1');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-readme-'));
  try {
    const out = path.join(root, 'npm');
    for (const name of assemble(dist, '1.2.3-rc.1', out).filter((p) => p !== 'agentforge-guard')) {
      const readme = fs.readFileSync(path.join(out, name, 'README.md'), 'utf8');
      assert.doesNotMatch(readme, /no JavaScript/);
      assert.match(readme, /index\.js/);
      assert.match(readme, /--certificate-identity/);
      assert.match(readme, /release\.yml@refs\/tags\/v1\.2\.3-rc\.1/);
      assert.match(readme, /--certificate-oidc-issuer/);
      assert.match(readme, /cmp /);
    }
  } finally {
    fs.rmSync(dist, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('npm tarballs ship only intended files and preserve binaries and entry points', () => {
  const version = '1.2.3-rc.1';
  const dist = fakeDist(version);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-pack-'));
  try {
    const out = path.join(root, 'npm');
    const names = assemble(dist, version, out);
    const emptyConfig = path.join(root, 'empty.npmrc');
    fs.writeFileSync(emptyConfig, '');
    for (const name of names) {
      const dir = path.join(out, name);
      // Simulate build residue. npm's files allowlist must exclude it, even in bin/.
      fs.writeFileSync(path.join(dir, 'local.env'), 'TEST_TOKEN=obviously-fake\n');
      fs.writeFileSync(path.join(dir, 'bin', 'accidental.env'), 'TEST_TOKEN=obviously-fake\n');
      const packed = spawnSync('npm', [
        'pack', '--json', '--ignore-scripts', '--offline', '--userconfig', emptyConfig,
        '--cache', path.join(root, 'cache'), '--pack-destination', root,
      ], { cwd: dir, encoding: 'utf8' });
      assert.equal(packed.status, 0, packed.stderr);
      const [info] = JSON.parse(packed.stdout);
      const platform = name !== 'agentforge-guard';
      const exe = name.includes('win32') ? 'bin/afg.exe' : 'bin/afg';
      const expectedFiles = platform
        ? ['LICENSE', 'README.md', 'package.json', 'index.js', exe, 'lib/integrity.js', 'artifact.json', 'test/package.test.cjs']
        : ['LICENSE', 'README.md', 'package.json', 'bin/afg.js', 'lib/platform.js', 'lib/integrity.js', 'test/package.test.cjs'];
      assert.deepEqual(info.files.map((f) => f.path).sort(), expectedFiles.sort(), name);

      const unpack = path.join(root, name);
      fs.mkdirSync(unpack);
      const extracted = spawnSync('tar', ['xzf', path.join(root, info.filename), '-C', unpack]);
      assert.equal(extracted.status, 0, String(extracted.stderr));
      const pkgDir = path.join(unpack, 'package');
      const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
      assert.equal(pkg.version, version);
      assert.equal(pkg.license, 'MIT');
      assert.deepEqual(pkg.scripts, { test: 'node --test test/package.test.cjs' }, `${name}: only a test script, no lifecycle hooks`);
      assert.equal(pkg.dependencies, undefined, `${name}: no extra runtime dependencies`);
      if (platform) {
        assert.equal(pkg.optionalDependencies, undefined);
        const resolved = require(pkgDir);
        assert.equal(resolved, fs.realpathSync(path.join(pkgDir, exe)));
        assert.deepEqual(fs.readFileSync(resolved), fs.readFileSync(path.join(dir, exe)));
        assert.ok(fs.statSync(resolved).mode & 0o111, `${name}: executable mode survives npm pack`);
        const selftest = spawnSync(process.execPath, ['--test', path.join(pkgDir, 'test/package.test.cjs')], { encoding: 'utf8' });
        assert.equal(selftest.status, 0, selftest.stdout + selftest.stderr);
      } else {
        assert.deepEqual(Object.keys(pkg.optionalDependencies).sort(), names.filter((n) => n !== name).sort());
        assert.deepEqual(Object.values(pkg.optionalDependencies), Array(5).fill(version));
        for (const entry of Object.values(pkg.bin)) {
          assert.ok(fs.statSync(path.join(pkgDir, entry)).mode & 0o111, `${entry}: executable launcher`);
        }
      }
    }
    // Exercise the extracted tarballs together, as npm lays them out on this host.
    const found = resolvePlatform(process.platform, process.arch);
    if (!(found instanceof Error) && process.platform !== 'win32') {
      const launcher = path.join(root, 'agentforge-guard', 'package');
      const modules = path.join(launcher, 'node_modules');
      fs.mkdirSync(modules);
      fs.cpSync(path.join(root, found.pkg, 'package'), path.join(modules, found.pkg), { recursive: true });
      const ran = spawnSync(process.execPath, [path.join(launcher, 'bin/afg.js'), '--version'], { encoding: 'utf8' });
      assert.equal(ran.status, 0, ran.stderr);
      assert.equal(ran.stdout.trim(), found.target);
      const selftest = spawnSync(process.execPath, ['--test', path.join(launcher, 'test/package.test.cjs')], { encoding: 'utf8' });
      assert.equal(selftest.status, 0, selftest.stdout + selftest.stderr);
    }
  } finally {
    fs.rmSync(dist, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
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
  const fixture = installedFixture();
  try {
    fs.writeFileSync(fixture.binary, '#!/bin/sh\necho "args:$*"\nexit 7\n', { mode: 0o755 });
    const file = path.join(fixture.dir, 'artifact.json');
    const artifact = JSON.parse(fs.readFileSync(file, 'utf8'));
    artifact.sha256 = createHash('sha256').update(fs.readFileSync(fixture.binary)).digest('hex');
    fs.writeFileSync(file, JSON.stringify(artifact));
    const r = spawnSync(process.execPath, [fixture.launcher, 'policy', 'explain', '--', 'rm -rf /'], { encoding: 'utf8' });
    assert.equal(r.stdout.trim(), 'args:policy explain -- rm -rf /');
    assert.equal(r.status, 7);
  } finally {
    fixture.cleanup();
  }
});
