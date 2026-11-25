const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('npm artifact includes exactly the declared runtime assets and loads with the n8n peer', () => {
  const root = path.resolve(__dirname, '..');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-n8n-pack-'));
  const unexpected = path.join(root, 'dist', 'unexpected-test-fixture.env');
  try {
    fs.writeFileSync(unexpected, 'FAKE_TEST_VALUE_ONLY=not-a-secret\n');
    const packed = spawnSync('npm', ['pack', '--json', '--ignore-scripts', '--offline', '--pack-destination', scratch], {
      cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: scratch }, timeout: 30000,
    });
    assert.equal(packed.status, 0, packed.stderr);
    const [manifest] = JSON.parse(packed.stdout);
    const files = manifest.files.map(x => x.path).sort();
    const pkg = require('../package.json');
    assert.deepEqual(files, [...pkg.files, 'README.md', 'package.json'].sort());
    assert.ok(!files.some(x => /unexpected|node_modules|\.map$|\.ts$|\.env$/.test(x)));
    const extracted = spawnSync('tar', ['-xzf', path.join(scratch, manifest.filename), '-C', scratch], { encoding: 'utf8', env: { PATH: process.env.PATH }, timeout: 10000 });
    assert.equal(extracted.status, 0, extracted.stderr);
    const destination = path.join(scratch, 'package');
    fs.symlinkSync(path.join(root, 'node_modules'), path.join(destination, 'node_modules'), 'dir');
    for (const file of [...pkg.n8n.nodes, ...pkg.n8n.credentials]) {
      const exported = require(path.join(destination, file));
      const Class = Object.values(exported)[0];
      const instance = new Class();
      assert.ok(instance.description || instance.authenticate);
    }
  } finally {
    fs.rmSync(unexpected, { force: true });
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
