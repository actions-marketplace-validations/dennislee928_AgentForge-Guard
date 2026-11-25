const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { AgentForgeGuard } = require('../dist/nodes/AgentForgeGuard/AgentForgeGuard.node.js');

test('TypeScript node → HTTP → real Rust core preserves decisions and stops on policy changes', { timeout: 30000 }, async () => {
  const repo = path.resolve(__dirname, '../../..');
  const binary = path.join(repo, 'target/debug', process.platform === 'win32' ? 'afg.exe' : 'afg');
  assert.ok(fs.existsSync(binary), 'Build Rust first: cargo build --locked -p agentforge-guard');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'afg-n8n-gateway-'));
  const home = path.join(temp, 'home');
  const cwd = path.join(temp, 'repo');
  fs.mkdirSync(home);
  fs.mkdirSync(cwd);
  fs.copyFileSync(path.join(repo, 'crates/afg-core/policies/default.yaml'), path.join(cwd, 'agentforge.yaml'));
  const key = 'FAKE-n8n-integration-test-key-0000000000';
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, AFG_GATEWAY_API_KEY: key };
  const explained = spawnSync(binary, ['policy', 'explain', '--json', '--', 'git', 'status'], { cwd, env, encoding: 'utf8', timeout: 10000 });
  assert.equal(explained.status, 0, explained.stderr);
  const { policyHash } = JSON.parse(explained.stdout);
  const gateway = spawn(binary, ['gateway', '--listen', '127.0.0.1:0', '--policy-hash', policyHash], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    const baseUrl = await new Promise((resolve, reject) => {
      let text = '';
      const timer = setTimeout(() => reject(new Error('Gateway startup timeout')), 10000);
      gateway.once('error', error => { clearTimeout(timer); reject(error); });
      gateway.once('exit', code => { clearTimeout(timer); reject(new Error(`Gateway startup exited ${code}: ${text}`)); });
      gateway.stderr.on('data', chunk => {
        text += chunk;
        const found = text.match(/listening on (127\.0\.0\.1:\d+)/);
        if (found) { clearTimeout(timer); resolve(`http://${found[1]}`); }
      });
    });
    const unauthorized = await fetch(`${baseUrl}/v1/health`);
    assert.equal(unauthorized.status, 401);
    for (const [argv, effect] of [[['git', 'status'], 'allow'], [['terraform', 'destroy'], 'deny'], [['kubectl', 'apply'], 'require-approval'], [['sh', '-c', 'touch MUST_NOT_EXIST'], 'route']]) {
      const ctx = {
        getInputData: () => [{ json: {} }],
        getNodeParameter: name => ({ resource: 'policy', operation: 'evaluate', argv, requestedBackend: 'policy' })[name],
        getCredentials: async () => ({ baseUrl }),
        getNode: () => ({ name: 'Guard', type: 'agentForgeGuard', typeVersion: 1, position: [0, 0], parameters: {} }),
        continueOnFail: () => false,
        helpers: { httpRequestWithAuthentication: async (_name, options) => {
          const response = await fetch(options.url, { method: options.method, headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: JSON.stringify(options.body), redirect: 'error', signal: AbortSignal.timeout(options.timeout) });
          if (!response.ok) throw new Error('HTTP request failed');
          return response.json();
        } },
      };
      const [[item]] = await new AgentForgeGuard().execute.call(ctx);
      assert.equal(item.json.effect, effect);
      assert.equal(item.json.policyHash, policyHash);
      fs.writeFileSync(path.join(cwd, 'agentforge.yaml'), 'invalid policy');
      await assert.rejects(new AgentForgeGuard().execute.call(ctx));
      fs.copyFileSync(path.join(repo, 'crates/afg-core/policies/default.yaml'), path.join(cwd, 'agentforge.yaml'));
    }
    assert.ok(!fs.existsSync(path.join(cwd, 'MUST_NOT_EXIST')));
  } finally {
    if (gateway.exitCode === null) {
      gateway.kill('SIGINT');
      await new Promise(resolve => { gateway.once('exit', resolve); setTimeout(() => { gateway.kill('SIGKILL'); resolve(); }, 2000).unref(); });
    }
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
