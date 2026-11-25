const { test } = require('node:test');
const assert = require('node:assert/strict');
const { AgentForgeGuard } = require('../dist/nodes/AgentForgeGuard/AgentForgeGuard.node.js');
const { AgentForgeGuardApi } = require('../dist/credentials/AgentForgeGuardApi.credentials.js');

const decision = (effect = 'allow') => ({ schemaVersion: 1, effect, backend: effect === 'deny' ? null : effect === 'route' ? 'container' : 'local', ruleId: 'fixture', reasons: ['fixture'], policyVersion: 'agentforge.dev/v1', policyHash: `sha256:${'a'.repeat(64)}` });

function context(parameters = {}, responses = [decision()]) {
  const requests = [];
  let calls = 0;
  const ctx = {
    getInputData: () => responses.map(() => ({ json: { input: true } })),
    getNodeParameter: (name, index) => ({ resource: 'policy', operation: 'evaluate', argv: '["git","status"]', requestedBackend: 'policy', ...parameters })[name],
    getCredentials: async () => ({ baseUrl: 'https://guard.example.test', apiKey: 'FAKE-key-for-tests-only-00000000000' }),
    getNode: () => ({ name: 'AgentForge Guard', type: 'agentForgeGuard', typeVersion: 1, position: [0, 0], parameters: {} }),
    continueOnFail: () => false,
    helpers: { httpRequestWithAuthentication: async (credential, options) => {
      requests.push({ credential, options });
      const value = responses[calls++];
      if (value instanceof Error) throw value;
      return value;
    } },
  };
  return { ctx, requests };
}

test('official n8n metadata and credentials resolve to usable classes', () => {
  const pkg = require('../package.json');
  assert.ok(pkg.keywords.includes('n8n-community-node-package'));
  assert.deepEqual(pkg.dependencies, undefined);
  const node = new AgentForgeGuard();
  assert.equal(node.description.name, 'agentForgeGuard');
  const credential = new AgentForgeGuardApi();
  assert.equal(credential.name, 'agentForgeGuardApi');
  assert.match(credential.authenticate.properties.headers.Authorization, /Bearer/);
});

test('evaluations preserve all four core decisions and item pairing', async () => {
  const responses = ['allow', 'deny', 'require-approval', 'route'].map(decision);
  const { ctx, requests } = context({}, responses);
  const [items] = await new AgentForgeGuard().execute.call(ctx);
  assert.deepEqual(items.map(x => x.json.effect), responses.map(x => x.effect));
  assert.deepEqual(items.map(x => x.pairedItem), [0, 1, 2, 3].map(item => ({ item })));
  assert.equal(requests[0].credential, 'agentForgeGuardApi');
  assert.equal(requests[0].options.url, 'https://guard.example.test/v1/evaluate');
  assert.deepEqual(requests[0].options.body, { argv: ['git', 'status'] });
  assert.equal(requests[0].options.timeout, 10000);
  assert.equal(requests[0].options.disableFollowRedirect, true);
});

test('analyze and validate use the real API; validate refuses all non-allow effects', async () => {
  const { ctx, requests } = context({ resource: 'command', operation: 'analyze', requestedBackend: 'container' });
  await new AgentForgeGuard().execute.call(ctx);
  assert.equal(requests[0].options.body.requestedBackend, 'container');
  for (const effect of ['deny', 'require-approval', 'route']) {
    const { ctx } = context({ resource: 'security', operation: 'validate' }, [decision(effect)]);
    await assert.rejects(new AgentForgeGuard().execute.call(ctx), /Security validation/);
  }
});

test('malformed and unavailable responses never become allow', async () => {
  for (const response of [null, {}, { ...decision(), schemaVersion: 2 }, { ...decision(), effect: 'approved' }, { ...decision(), policyHash: 'oops' }, { ...decision(), backend: null }, { ...decision('deny'), backend: 'local' }, { ...decision(), reasons: [1] }, new Error('timeout')]) {
    const { ctx } = context({}, [response]);
    await assert.rejects(new AgentForgeGuard().execute.call(ctx));
  }
});

test('invalid argv, unsupported operations and unsafe URLs fail before HTTP', async () => {
  for (const parameters of [{ argv: 'git status' }, { argv: '[]' }, { argv: '[1]' }, { argv: '["git","\\u0000"]' }, { resource: 'audit', operation: 'export' }, { resource: 'command', operation: 'evaluate' }]) {
    const { ctx, requests } = context(parameters);
    await assert.rejects(new AgentForgeGuard().execute.call(ctx));
    assert.equal(requests.length, 0);
  }
  for (const baseUrl of ['http://remote.example.test', 'https://user:password@example.test', 'https://example.test?key=x', 'file:///tmp/x']) {
    const { ctx, requests } = context();
    ctx.getCredentials = async () => ({ baseUrl });
    await assert.rejects(new AgentForgeGuard().execute.call(ctx));
    assert.equal(requests.length, 0);
  }
});

test('continue-on-fail produces an explicit error without an allow decision or leaked credentials', async () => {
  const { ctx } = context({}, [new Error('Authorization: Bearer FAKE-secret-request-value')]);
  ctx.continueOnFail = () => true;
  const [[item]] = await new AgentForgeGuard().execute.call(ctx);
  assert.equal(item.json.effect, undefined);
  assert.equal(item.json.error, 'AgentForge Guard request failed; no decision was accepted');
  assert.ok(!JSON.stringify(item).includes('FAKE-secret'));
});
