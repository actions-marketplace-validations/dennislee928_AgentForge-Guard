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
npm install -g agentforge-guard@${version}
\`\`\`

## Requirements

This package targets \`${target}\`; npm checks its \`os\` and \`cpu\` fields during installation.
Use Node.js 18 or newer for the launcher, path export and package tests.
The executable is prebuilt: a Rust compiler is not required for the npm installation.
Docker is needed only when your execution policy routes a command to the container backend.
Installing this package does not start Docker or execute the native binary.

Linux release binaries use glibc. Alpine and other musl distributions should build from source:

\`\`\`sh
cargo install agentforge-guard --version ${version}
\`\`\`

The source installation needs the Rust toolchain specified by the tagged repository.
If an older Linux distribution reports missing glibc symbols, build from source on that system.
There is no runtime download fallback for an unsupported OS, CPU or C library.

## Using the installed command

Run the launcher name directly; \`npm afg\` is not an npm subcommand.
Each command below is a separate shell command, and \`--\` uses two ordinary hyphens.

\`\`\`sh
afg --version
afg --help
afg policy explain -- cargo test
\`\`\`

The policy explanation evaluates the command without running it.
Initialize and review a policy in your own repository before using \`afg run\`.
See the [command reference](${repo}/blob/${tag}/README.md#command-reference)
and the [security boundaries](${repo}/blob/${tag}/docs/security-boundaries.md).
Allowing a command such as \`cargo test\` permits arbitrary test code to run with its backend's privileges.
Argument matching and agent prompt instructions are not security boundaries.

## Contents

- \`bin/\`: the \`afg\` executable, built from the tagged source by the
  [release workflow](${repo}/blob/${tag}/.github/workflows/release.yml).
  This package ships a native binary, a small JavaScript path export, and no install scripts.
- \`index.js\`: exports the absolute path of the binary (\`require('${name}')\`).
- \`lib/integrity.js\`: checks the package identity, regular binary file and SHA-256 digest.
- \`artifact.json\`: records the package version, target, binary digest and source archive digest.
- \`test/package.test.cjs\`: runnable tests of the installed artifact and its path export.
- \`LICENSE\`: MIT. (The source repository is MIT OR Apache-2.0; the npm packages are published under MIT.)

## Startup integrity checks

The launcher requires the platform package to have the same version as the launcher.
Before spawning the binary it validates the target, fixed binary path, artifact metadata and digest.
An absent manifest, malformed digest, version mismatch or changed binary causes an error.
The binary must be a regular file; replacing it with a symbolic link is rejected.
Requiring this platform package also checks its binary before returning the absolute path string.
That API does not execute the native program, so it can be inspected on another platform.

The digest check detects damaged installations and binary-only modifications.
It reads the executable locally and uses Node's built-in SHA-256 implementation.
It sends no telemetry, reads no credentials and makes no network requests.
It does not authenticate a manifest that an attacker can replace together with the binary and verifier.
It also does not close a race in which a local attacker changes a file after verification.
Use npm signatures and the signed release comparison below to establish artifact origin.

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
set -eu
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

## Running the packaged tests

After unpacking the npm tarball with the commands above, run:

\`\`\`sh
npm --prefix package test
\`\`\`

The tests use only Node built-ins; no dependency installation is needed.
They check artifact identity, the binary checksum, the path export and the absence of lifecycle hooks.
They do not execute the platform binary, so these checks work even on a different host OS or CPU.
There are no preinstall, install, postinstall, prepare or prepublish scripts.
The \`test\` script runs only when explicitly requested.

The repository CI also packs and extracts all six npm packages, exercises the host launcher,
and tests rejection of changed binaries, mixed versions, missing metadata and symlink substitution.
Rust policy, adversarial and backend tests run separately in
[CI](${repo}/blob/${tag}/.github/workflows/ci.yml).
Passing package tests establishes packaging behavior; it does not replace the independent security review.

## Troubleshooting installation

If the launcher reports a missing platform package, reinstall with optional dependencies enabled.
Avoid \`--omit=optional\` and \`--no-optional\`; the native executable is an optional dependency selected by npm.
The launcher and platform package must both be version \`${version}\`.
For an integrity failure, reinstall the exact version from npm rather than editing \`artifact.json\`.
If it persists, compare with the signed release and report the discrepancy.

An \`EACCES\` error under \`/usr/local/lib/node_modules\` is a local npm permission problem.
Use a Node version manager, or choose a user-owned npm prefix and put its \`bin\` directory on PATH.
The [npm permissions guide](https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally/)
describes the supported setup; package installation does not require modifying system permissions.

If \`afg\` is not found after a successful install, check the npm prefix and your shell PATH.
Restart the shell after updating its configuration.
For source builds and unsupported targets, use the Cargo command in Requirements above.
${windows ? 'On Windows, the native executable is `afg.exe`; the JavaScript launcher remains `afg`.' : 'The native executable is `afg`; its executable file mode is preserved in the npm tarball.'}

## Scanner interpretation

The three-line \`index.js\` delegates to the integrity verifier and exports the binary path.
The native program is implemented in Rust, so JavaScript line counts do not measure its implementation size.
Filesystem and cryptographic access in the verifier implement the documented digest check.
Download counts, prerelease status and independent scanner heuristics can still affect public scores.
No synthetic downloads or scanner exclusions are used to raise those scores.
Review the binary and its provenance as well as the scanner's findings.
See the [Socket findings and packaging checks](${repo}/blob/${tag}/docs/npm-package-security.md).

## Source and support

The [tagged source](${repo}/tree/${tag}) contains the Rust workspace, package assembler and tests.
The [release workflow](${repo}/blob/${tag}/.github/workflows/release.yml) records the build targets
and publishes the archives used by this npm package.
Report reproducible installation problems through [GitHub issues](${repo}/issues).
For security reports, follow [SECURITY.md](${repo}/blob/${tag}/SECURITY.md) and omit credentials from logs.

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
    fs.mkdirSync(path.join(pkgDir, 'lib'));
    fs.mkdirSync(path.join(pkgDir, 'test'));
    fs.copyFileSync(path.join(here, 'agentforge-guard/lib/integrity.js'), path.join(pkgDir, 'lib/integrity.js'));
    fs.copyFileSync(path.join(here, 'platform-package.test.cjs'), path.join(pkgDir, 'test/package.test.cjs'));
    fs.writeFileSync(path.join(pkgDir, 'artifact.json'), JSON.stringify({
      schemaVersion: 1,
      name,
      version,
      target,
      binary: `bin/${exe}`,
      sha256: createHash('sha256').update(fs.readFileSync(path.join(pkgDir, 'bin', exe))).digest('hex'),
      archive: { name: archive, sha256: digest },
    }, null, 2) + '\n');
    fs.writeFileSync(
      path.join(pkgDir, 'index.js'),
      "'use strict';\n// Verify the installed binary before exporting its absolute path.\n" +
        "module.exports = require('./lib/integrity.js').verifyBinary(__dirname);\n",
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
          files: [`bin/${exe}`, 'index.js', 'lib/integrity.js', 'artifact.json', 'test/package.test.cjs', 'README.md', 'LICENSE'],
          engines: main.engines,
          scripts: { test: 'node --test test/package.test.cjs' },
          preferUnplugged: true,
        },
        null,
        2,
      ) + '\n',
    );
    main.optionalDependencies[name] = version;
  }

  const mainDir = path.join(out, 'agentforge-guard');
  for (const f of ['bin/afg.js', 'lib/platform.js', 'lib/integrity.js', 'test/package.test.cjs']) {
    fs.mkdirSync(path.join(mainDir, path.dirname(f)), { recursive: true });
    fs.copyFileSync(path.join(here, 'agentforge-guard', f), path.join(mainDir, f));
  }
  fs.chmodSync(path.join(mainDir, 'bin/afg.js'), 0o755);
  fs.copyFileSync(path.join(repoRoot, 'README.md'), path.join(mainDir, 'README.md'));
  fs.copyFileSync(path.join(repoRoot, 'LICENSE-MIT'), path.join(mainDir, 'LICENSE'));
  main.version = version;
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
