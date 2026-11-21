#!/usr/bin/env node
// Build the npm packages from a release's dist/ directory.
//
//   node packaging/npm/assemble.mjs <dist-dir> <version> <out-dir>
//
// <dist-dir> holds afg-v<version>-<target>.tar.gz|.zip and SHA256SUMS, exactly as
// release.yml produces them. Every archive is checked against SHA256SUMS before it
// is unpacked; any mismatch or missing target aborts. Writes one package per
// platform plus the `agentforge-guard` launcher package, each ready for `npm publish`.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { TARGETS } = require('./agentforge-guard/lib/platform.js');
const repoRoot = path.resolve(here, '../..');

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr}`);
}

function sums(dist) {
  const map = new Map();
  for (const line of fs.readFileSync(path.join(dist, 'SHA256SUMS'), 'utf8').split('\n')) {
    const m = line.match(/^([0-9a-f]{64})\s+\*?(\S+)$/);
    if (m) map.set(m[2], m[1]);
  }
  return map;
}

export function assemble(dist, version, out) {
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`bad version ${version}`);
  const expected = sums(dist);
  const main = JSON.parse(fs.readFileSync(path.join(here, 'agentforge-guard/package.json'), 'utf8'));
  fs.rmSync(out, { recursive: true, force: true });
  main.optionalDependencies = {};

  for (const [key, target] of Object.entries(TARGETS)) {
    const [os, cpu] = key.split('-');
    const windows = os === 'win32';
    const archive = `afg-v${version}-${target}.${windows ? 'zip' : 'tar.gz'}`;
    const file = path.join(dist, archive);
    if (!fs.existsSync(file)) throw new Error(`missing ${archive}`);
    const digest = createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (expected.get(archive) !== digest) throw new Error(`checksum mismatch for ${archive}`);

    const name = `agentforge-guard-${key}`;
    const pkgDir = path.join(out, name);
    const tmp = fs.mkdtempSync(path.join(out + '-tmp-'));
    try {
      if (windows) run('unzip', ['-q', file, '-d', tmp]);
      else run('tar', ['xzf', file, '-C', tmp]);
      const exe = windows ? 'afg.exe' : 'afg';
      const bin = path.join(tmp, `afg-v${version}-${target}`, exe);
      if (!fs.existsSync(bin)) throw new Error(`${archive} has no ${exe}`);
      fs.mkdirSync(path.join(pkgDir, 'bin'), { recursive: true });
      fs.copyFileSync(bin, path.join(pkgDir, 'bin', exe));
      fs.chmodSync(path.join(pkgDir, 'bin', exe), 0o755);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    for (const f of ['LICENSE-MIT', 'LICENSE-APACHE']) fs.copyFileSync(path.join(repoRoot, f), path.join(pkgDir, f));
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify(
        {
          name,
          version,
          description: `The ${target} binary for agentforge-guard. Install agentforge-guard instead.`,
          license: main.license,
          homepage: main.homepage,
          repository: main.repository,
          os: [os],
          cpu: [cpu],
          files: ['bin', 'LICENSE-MIT', 'LICENSE-APACHE'],
          preferUnplugged: true,
        },
        null,
        2,
      ) + '\n',
    );
    main.optionalDependencies[name] = version;
  }

  const mainDir = path.join(out, 'agentforge-guard');
  for (const f of ['bin/afg.js', 'lib/platform.js']) {
    fs.mkdirSync(path.join(mainDir, path.dirname(f)), { recursive: true });
    fs.copyFileSync(path.join(here, 'agentforge-guard', f), path.join(mainDir, f));
  }
  fs.chmodSync(path.join(mainDir, 'bin/afg.js'), 0o755);
  for (const f of ['README.md', 'LICENSE-MIT', 'LICENSE-APACHE']) fs.copyFileSync(path.join(repoRoot, f), path.join(mainDir, f));
  main.version = version;
  delete main.scripts;
  fs.writeFileSync(path.join(mainDir, 'package.json'), JSON.stringify(main, null, 2) + '\n');
  return [...Object.keys(main.optionalDependencies), 'agentforge-guard'];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [dist, version, out] = process.argv.slice(2);
  if (!dist || !version || !out) {
    console.error('usage: assemble.mjs <dist-dir> <version> <out-dir>');
    process.exit(2);
  }
  for (const p of assemble(path.resolve(dist), version, path.resolve(out))) console.log(p);
}
