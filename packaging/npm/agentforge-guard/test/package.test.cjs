'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { resolvePlatform } = require('../lib/platform.js');
const { verifyBinary } = require('../lib/integrity.js');
const pkg = require('../package.json');

test('launcher pins every platform dependency to its own version', () => {
  assert.equal(Object.keys(pkg.optionalDependencies).length, 5);
  assert.deepEqual([...new Set(Object.values(pkg.optionalDependencies))], [pkg.version]);
});

test('installed host binary passes identity and checksum verification', () => {
  const found = resolvePlatform(process.platform, process.arch);
  assert.ok(!(found instanceof Error), found.message);
  const directory = path.dirname(require.resolve(`${found.pkg}/package.json`));
  const verified = verifyBinary(directory, { name: found.pkg, version: pkg.version, target: found.target, binary: found.bin });
  assert.equal(require(found.pkg), verified);
});

test('unsupported targets have explicit source-install guidance', () => {
  assert.match(resolvePlatform('freebsd', 'x64').message, /cargo install/);
  assert.match(resolvePlatform('linux', 'x64', false).message, /musl/);
});
