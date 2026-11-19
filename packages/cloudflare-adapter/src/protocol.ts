// Wire protocol between `afg` (Rust CloudflareExecutor) and this Worker.
//
// The Worker makes no policy decisions (ADR 0002). It executes only requests
// that afg has already decided on and signed with the per-project key:
//   X-AFG-Signature: v1=<hex HMAC-SHA256(key, raw body)>
// Every request carries `issuedAt` (within ±MAX_SKEW_SECONDS) and a unique
// `id`. The Durable Object for that id refuses a second run (no replay).

export const PROTOCOL_VERSION = 1;
export const MAX_SKEW_SECONDS = 300;
export const WORKSPACE = "/workspace";

export interface ExecuteRequest {
  version: 1;
  kind: "execute";
  /** afg's audit id; also the Durable Object name. */
  id: string;
  issuedAt: number;
  /** Exact argv. No shell is added. */
  argv: string[];
  /** Working directory relative to the workspace root ("" = root). */
  cwd: string;
  env: Record<string, string>;
  timeoutSeconds: number;
  network: "none" | "bridge";
  /** Base64 tar archive of afg's manifest-filtered snapshot. */
  archive: string;
  /** Snapshot manifest hash, echoed back for the audit record. */
  manifestHash: string;
}

export interface CleanupRequest {
  version: 1;
  kind: "cleanup";
  id: string;
  issuedAt: number;
}

export type WireRequest = ExecuteRequest | CleanupRequest;

export interface ExecuteResponse {
  id: string;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
  stdout: Stream;
  stderr: Stream;
  manifestHash: string;
}

export interface Stream {
  /** Base64 of the first `limit` bytes. */
  data: string;
  len: number;
  truncated: boolean;
  sha256: string;
}

export interface Limits {
  maxArchiveBytes: number;
  maxTimeoutSeconds: number;
  maxOutputBytes: number;
}

export function hex(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s: string): Uint8Array | null {
  if (s.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Constant-time HMAC verification via WebCrypto. */
export async function verifySignature(keyHex: string, body: string, header: string | null): Promise<boolean> {
  const key = fromHex(keyHex);
  if (!key || key.length < 32 || !header?.startsWith("v1=")) return false;
  const tag = fromHex(header.slice(3));
  if (!tag) return false;
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", k, tag, new TextEncoder().encode(body));
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ID = /^[0-9a-f-]{8,64}$/;

/** Structural validation. Returns a list of problems (empty = valid). */
export function validate(r: unknown, limits: Limits, nowSeconds: number): string[] {
  const e: string[] = [];
  if (typeof r !== "object" || r === null) return ["request must be an object"];
  const o = r as Record<string, unknown>;
  if (o.version !== PROTOCOL_VERSION) e.push("unsupported protocol version");
  if (typeof o.id !== "string" || !ID.test(o.id)) e.push("invalid id");
  if (typeof o.issuedAt !== "number" || Math.abs(nowSeconds - o.issuedAt) > MAX_SKEW_SECONDS) {
    e.push("issuedAt outside the allowed window");
  }
  if (o.kind === "cleanup") return e;
  if (o.kind !== "execute") return [...e, "unknown kind"];
  const argv = o.argv;
  if (!Array.isArray(argv) || argv.length === 0 || !argv.every((a) => typeof a === "string")) {
    e.push("argv must be a non-empty string array");
  } else if (argv[0] === "") {
    e.push("empty executable");
  }
  const cwd = o.cwd;
  if (typeof cwd !== "string" || cwd.startsWith("/") || cwd.split("/").some((s) => s === "..")) {
    e.push("cwd must be a relative path inside the workspace");
  }
  const env = o.env;
  if (typeof env !== "object" || env === null || Array.isArray(env)) {
    e.push("env must be an object");
  } else {
    for (const [k, v] of Object.entries(env)) {
      if (!ENV_NAME.test(k) || typeof v !== "string") e.push(`invalid env entry ${k}`);
    }
  }
  if (typeof o.timeoutSeconds !== "number" || !(o.timeoutSeconds > 0) || o.timeoutSeconds > limits.maxTimeoutSeconds) {
    e.push(`timeoutSeconds must be in (0, ${limits.maxTimeoutSeconds}]`);
  }
  if (o.network !== "none" && o.network !== "bridge") e.push("network must be none or bridge");
  if (typeof o.archive !== "string" || o.archive.length > Math.ceil(limits.maxArchiveBytes / 3) * 4) {
    e.push("archive missing or larger than maxArchiveBytes");
  }
  if (typeof o.manifestHash !== "string") e.push("manifestHash missing");
  return e;
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

export async function stream(buf: ArrayBuffer, limit: number): Promise<Stream> {
  const all = new Uint8Array(buf);
  return {
    data: bytesToBase64(all.subarray(0, limit)),
    len: all.length,
    truncated: all.length > limit,
    sha256: "sha256:" + hex(await crypto.subtle.digest("SHA-256", all)),
  };
}
