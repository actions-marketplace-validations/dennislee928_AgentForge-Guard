#!/usr/bin/env node
'use strict';

// Runs the `afg` binary from the matching optional platform package.
// Nothing is downloaded at install or run time, and no shell is involved.
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { resolvePlatform } = require('../lib/platform.js');
const { verifyBinary } = require('../lib/integrity.js');
const { version } = require('../package.json');

function glibc() {
  if (process.platform !== 'linux') return true;
  const header = process.report && process.report.getReport().header;
  return Boolean(header && header.glibcVersionRuntime);
}

const found = resolvePlatform(process.platform, process.arch, glibc());
if (found instanceof Error) {
  console.error(found.message);
  process.exit(1);
}

let binary;
try {
  const directory = path.dirname(require.resolve(`${found.pkg}/package.json`));
  binary = verifyBinary(directory, { name: found.pkg, version, target: found.target, binary: found.bin });
} catch (error) {
  console.error(
    `agentforge-guard: binary integrity check failed for ${found.pkg}: ${error.message}. ` +
      'Reinstall without --no-optional / --omit=optional, or install from source with: cargo install agentforge-guard',
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(`agentforge-guard: failed to run ${binary}: ${result.error.message}`);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status ?? 1);
