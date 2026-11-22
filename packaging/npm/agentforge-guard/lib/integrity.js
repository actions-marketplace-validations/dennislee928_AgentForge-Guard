'use strict';

const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Detect mixed versions and damaged installations. The co-shipped manifest is
// not a trust anchor: authenticate the npm provenance/release signatures too.
function verifyBinary(directory, expected = {}) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
    const artifact = JSON.parse(fs.readFileSync(path.join(directory, 'artifact.json'), 'utf8'));
    const binary = pkg.os[0] === 'win32' ? 'bin/afg.exe' : 'bin/afg';
    if (expected.name && pkg.name !== expected.name) throw new Error('package name mismatch');
    if (expected.version && pkg.version !== expected.version) throw new Error('version mismatch');
    if (artifact.schemaVersion !== 1 || artifact.name !== pkg.name || artifact.version !== pkg.version) {
      throw new Error('artifact identity mismatch');
    }
    if (artifact.binary !== binary || (expected.binary && artifact.binary !== expected.binary)) {
      throw new Error('binary path mismatch');
    }
    if (!artifact.target || (expected.target && artifact.target !== expected.target)) {
      throw new Error('target mismatch');
    }
    if (typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256)) {
      throw new Error('invalid binary checksum');
    }
    const extension = pkg.os[0] === 'win32' ? 'zip' : 'tar.gz';
    if (artifact.archive?.name !== `afg-v${pkg.version}-${artifact.target}.${extension}` ||
        typeof artifact.archive.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.archive.sha256)) {
      throw new Error('invalid source archive metadata');
    }
    const file = path.join(directory, binary);
    if (!fs.lstatSync(file).isFile()) throw new Error('binary must be a regular file, not a symlink');
    const actual = createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (actual !== artifact.sha256) throw new Error('binary checksum mismatch');
    return fs.realpathSync(file);
  } catch (error) {
    throw new Error(`agentforge-guard: binary integrity check failed: ${error.message}`);
  }
}

module.exports = { verifyBinary };
