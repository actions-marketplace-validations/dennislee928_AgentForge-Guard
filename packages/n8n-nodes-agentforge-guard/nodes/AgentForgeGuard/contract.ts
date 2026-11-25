import type { IDataObject } from 'n8n-workflow';

export function gatewayUrl(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Invalid gateway URL');
  const url = new URL(value);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(loopback && url.protocol === 'http:')) ||
      url.username || url.password || url.search || url.hash) {
    throw new Error('Gateway requires HTTPS, or HTTP on loopback, without URL credentials, query or fragment');
  }
  return url.toString().replace(/\/$/, '');
}

export function parseArgv(value: unknown): string[] {
  const argv: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > 256 ||
      !argv.every(a => typeof a === 'string' && !a.includes('\0') && new TextEncoder().encode(a).length <= 4096)) {
    throw new Error('Argv must be a nonempty JSON array of at most 256 strings, each at most 4096 bytes without NUL');
  }
  if (new TextEncoder().encode(JSON.stringify({ argv })).length > 64 * 1024) {
    throw new Error('Request exceeds the gateway body limit');
  }
  return argv as string[];
}

export function checkedEvaluation(value: unknown): IDataObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid gateway response');
  const d = value as Record<string, unknown>;
  const backend = d.backend;
  if (d.schemaVersion !== 1 || !['allow', 'deny', 'require-approval', 'route'].includes(String(d.effect)) ||
      (d.effect === 'deny' ? backend !== null : !['local', 'container', 'cloudflare'].includes(String(backend))) ||
      typeof d.ruleId !== 'string' || !d.ruleId ||
      !Array.isArray(d.reasons) || !d.reasons.every(r => typeof r === 'string') ||
      typeof d.policyVersion !== 'string' || !/^agentforge\.dev\/v(1|1alpha1)$/.test(d.policyVersion) ||
      typeof d.policyHash !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(d.policyHash)) {
    throw new Error('Invalid gateway decision contract');
  }
  return {
    schemaVersion: 1,
    effect: d.effect as string,
    backend: backend as string | null,
    ruleId: d.ruleId,
    reasons: d.reasons as string[],
    policyVersion: d.policyVersion,
    policyHash: d.policyHash,
  };
}
