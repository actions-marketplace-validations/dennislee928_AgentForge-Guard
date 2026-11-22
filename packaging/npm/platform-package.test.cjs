'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const pkg = require('../package.json');
const artifact = require('../artifact.json');
const { verifyBinary } = require('../lib/integrity.js');

test('artifact identifies this package and its source archive', () => {
  assert.equal(artifact.name, pkg.name);
  assert.equal(artifact.version, pkg.version);
  assert.match(artifact.archive.sha256, /^[a-f0-9]{64}$/);
  assert.ok(artifact.archive.name.includes(artifact.target));
});

test('path export verifies the installed binary bytes without executing them', () => {
  const directory = path.join(__dirname, '..');
  assert.equal(require('../index.js'), verifyBinary(directory));
});

test('package has no lifecycle hooks or runtime dependencies', () => {
  assert.deepEqual(pkg.scripts, { test: 'node --test test/package.test.cjs' });
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.optionalDependencies, undefined);
});
