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

// The README shipped in each platform package: what the binary is, and how to check it.
function platformReadme(name, target, version, repo) {
  const tag = `v${version}`;
  const windows = target.includes('windows');
  const directory = `afg-${tag}-${target}`;
  const archive = `${directory}.${windows ? 'zip' : 'tar.gz'}`;
  const exe = windows ? 'afg.exe' : 'afg';
  const repository = repo.replace('https://github.com/', '');
  return `# ${name}

The prebuilt \`afg\` binary of [AgentForge Guard](${repo}) for \`${target}\`.

**Do not install this package directly.** Install \`agentforge-guard\` instead. Its launcher picks the
right platform package through \`optionalDependencies\`; nothing is downloaded or run at install time.

\`\`\`sh
npm install -g agentforge-guard
\`\`\`

## Contents

- \`bin/\`: the \`afg\` executable, built from the tagged source by the
  [release workflow](${repo}/blob/${tag}/.github/workflows/release.yml).
  This package ships a native binary, a small JavaScript path export, and no install scripts.
- \`index.js\`: exports the absolute path of the binary (\`require('${name}')\`).
- \`LICENSE\`: MIT. (The source repository is MIT OR Apache-2.0; the npm packages are published under MIT.)

## Verifying the binary

- This package is published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements),
  which links it to the GitHub Actions run that built it: \`npm audit signatures\`.
- The binary is the one in \`afg-${tag}-${target}\` from the
  [${tag} GitHub Release](${repo}/releases/tag/${tag}). That archive is listed in the release's \`SHA256SUMS\`
  and signed with Sigstore (\`<archive>.sigstore.json\`).

To compare this npm package's binary with the signed release, run these commands in an empty
directory using a POSIX shell (Git Bash on Windows). They need npm, GitHub CLI, cosign,
${windows ? 'unzip, ' : ''}tar and cmp. Stop if any command fails; a matching checksum alone does not authenticate the publisher.

\`\`\`sh
npm pack ${name}@${version} --ignore-scripts
tar xzf ${name}-${version}.tgz
gh release download ${tag} --repo ${repository} --pattern '${archive}' --pattern '${archive}.sigstore.json'
cosign verify-blob --bundle '${archive}.sigstore.json' --certificate-identity '${repo}/.github/workflows/release.yml@refs/tags/${tag}' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' '${archive}'
gh attestation verify '${archive}' --repo ${repository}
${windows ? `unzip -q '${archive}'` : `tar xzf '${archive}'`}
cmp 'package/bin/${exe}' '${directory}/${exe}'
\`\`\`

The signatures identify the release workflow; comparing the extracted files checks that npm ships
the same binary. Neither check proves that the program has no vulnerabilities.

## Scanner interpretation

The three-line \`index.js\` only exports the binary path. A scanner that counts JavaScript lines
may label it a trivial package even though the payload is a compiled Rust program. Review the
binary and its provenance rather than treating that line count as the implementation size.
See the [Socket findings and packaging checks](${repo}/blob/${tag}/docs/npm-package-security.md).

Source, documentation and security policy: ${repo}
`;
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
    const exe = windows ? 'afg.exe' : 'afg';
    const tmp = fs.mkdtempSync(path.join(out + '-tmp-'));
    try {
      if (windows) run('unzip', ['-q', file, '-d', tmp]);
      else run('tar', ['xzf', file, '-C', tmp]);
      const bin = path.join(tmp, `afg-v${version}-${target}`, exe);
      if (!fs.existsSync(bin)) throw new Error(`${archive} has no ${exe}`);
      fs.mkdirSync(path.join(pkgDir, 'bin'), { recursive: true });
      fs.copyFileSync(bin, path.join(pkgDir, 'bin', exe));
      fs.chmodSync(path.join(pkgDir, 'bin', exe), 0o755);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    // npm packages are MIT only: scanners read two license files as "Apache-2.0 AND MIT".
    fs.copyFileSync(path.join(repoRoot, 'LICENSE-MIT'), path.join(pkgDir, 'LICENSE'));
    fs.writeFileSync(
      path.join(pkgDir, 'index.js'),
      "'use strict';\n// Absolute path of the afg binary shipped in this package.\n" +
        `module.exports = require('node:path').join(__dirname, 'bin', '${exe}');\n`,
    );
    fs.writeFileSync(path.join(pkgDir, 'README.md'), platformReadme(name, target, version, main.homepage));
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify(
        {
          name,
          version,
          description: `The ${target} binary for agentforge-guard. Install agentforge-guard instead.`,
          keywords: main.keywords,
          author: main.author,
          license: main.license,
          homepage: main.homepage,
          repository: main.repository,
          bugs: main.bugs,
          os: [os],
          cpu: [cpu],
          main: 'index.js',
          files: [`bin/${exe}`, 'index.js', 'README.md', 'LICENSE'],
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
  fs.copyFileSync(path.join(repoRoot, 'README.md'), path.join(mainDir, 'README.md'));
  fs.copyFileSync(path.join(repoRoot, 'LICENSE-MIT'), path.join(mainDir, 'LICENSE'));
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
