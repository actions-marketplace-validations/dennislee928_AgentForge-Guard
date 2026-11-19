import { describe, expect, it } from "vitest";
import vector from "../../../tests/cloudflare-contract/vector.json";
import { type Limits, bytesToBase64, base64ToBytes, stream, validate, verifySignature } from "../src/protocol";

const lim: Limits = { maxArchiveBytes: 1024, maxTimeoutSeconds: 600, maxOutputBytes: 4 };
const now = 1_800_000_000;
const ok = {
  version: 1,
  kind: "execute",
  id: "01a1f45b58d8-a359828fc6a4c34a",
  issuedAt: now,
  argv: ["sh", "scripts/check.sh"],
  cwd: "",
  env: { CI: "true" },
  timeoutSeconds: 60,
  network: "none",
  archive: "",
  manifestHash: "sha256:x",
};

describe("signature (shared vector with the Rust signer)", () => {
  it("accepts the vector produced by afg", async () => {
    expect(await verifySignature(vector.keyHex, vector.body, vector.header)).toBe(true);
  });
  it("rejects tampering, wrong keys and malformed headers", async () => {
    expect(await verifySignature(vector.keyHex, vector.body + " ", vector.header)).toBe(false);
    expect(await verifySignature("00".repeat(32), vector.body, vector.header)).toBe(false);
    expect(await verifySignature(vector.keyHex, vector.body, vector.header.replace("v1=", "v2="))).toBe(false);
    expect(await verifySignature(vector.keyHex, vector.body, null)).toBe(false);
    expect(await verifySignature("abcd", vector.body, vector.header)).toBe(false);
  });
});

describe("validate", () => {
  it("accepts a well-formed request", () => {
    expect(validate(ok, lim, now)).toEqual([]);
  });
  it("rejects stale, traversal, shellless-breaking and oversized requests", () => {
    expect(validate({ ...ok, issuedAt: now - 301 }, lim, now)).toContain("issuedAt outside the allowed window");
    expect(validate({ ...ok, cwd: "../etc" }, lim, now)[0]).toMatch(/cwd/);
    expect(validate({ ...ok, cwd: "/etc" }, lim, now)[0]).toMatch(/cwd/);
    expect(validate({ ...ok, argv: [] }, lim, now)[0]).toMatch(/argv/);
    expect(validate({ ...ok, argv: "rm -rf /" }, lim, now)[0]).toMatch(/argv/);
    expect(validate({ ...ok, env: { "A=B": "x" } }, lim, now)[0]).toMatch(/env/);
    expect(validate({ ...ok, timeoutSeconds: 601 }, lim, now)[0]).toMatch(/timeout/);
    expect(validate({ ...ok, network: "host" }, lim, now)[0]).toMatch(/network/);
    expect(validate({ ...ok, archive: "A".repeat(2000) }, lim, now)[0]).toMatch(/archive/);
    expect(validate({ ...ok, id: "../../x" }, lim, now)).toContain("invalid id");
    expect(validate({ ...ok, version: 2 }, lim, now)).toContain("unsupported protocol version");
  });
});

describe("helpers", () => {
  it("round-trips base64 and truncates output streams", async () => {
    const b = new Uint8Array([0, 1, 2, 250, 255]);
    expect(base64ToBytes(bytesToBase64(b))).toEqual(b);
    const s = await stream(b.buffer, 4);
    expect(s).toMatchObject({ len: 5, truncated: true });
    expect(base64ToBytes(s.data)).toEqual(b.subarray(0, 4));
    expect(s.sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
