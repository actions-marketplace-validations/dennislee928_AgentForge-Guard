# Plan: a production Cloudflare Worker backend (T16)

This plan takes the existing Cloudflare adapter (`packages/cloudflare-adapter`) from "contract-tested against a mock" to "deployed, verified against a live account, and safe to recommend". It follows `.ignore/reference.txt`:
- Rust (`afg-core`) is the **only** policy decision point.
- The Worker executes **pre-approved, signed** requests in a disposable Linux container.
- The SDK and runtime version are pinned.
- Workspaces are uploaded as a manifest-filtered snapshot.
- Session lifecycle, cost and cleanup are explicit.
- Code Mode, MCP and Sandboxes stay separate layers.

Status inputs:
- The adapter and its README.
- `docs/provider-compatibility.md`.
- Cloudflare docs read on 2026-11-22: Containers overview, get-started, scheduling-policy, the Durable Object container API, outbound traffic, limits, pricing and FAQ.

Wherever this plan says "verify", the docs either didn't state the fact or were only partly read.

## 1. What exists today

| Piece | Where | State |
|---|---|---|
| Worker: POST `/v1/execute` and `/v1/cleanup`, HMAC `X-AFG-Signature: v1=…` over the raw body, ±300 s `issuedAt` window, structural validation, size cap | `packages/cloudflare-adapter/src/index.ts`, `src/protocol.ts` | ✅ written, unit-tested |
| One Durable Object per request id: replay protection (`used` flag), TTL alarm, container always destroyed | `AfgSandbox` in `src/index.ts` | ✅ written, never run live |
| Snapshot: manifest-filtered tar streamed into `tar -x`; argv run under coreutils `timeout`; output bounded and hashed | same | ✅ written, never run live |
| Rust client: signs requests, enforces cost caps (`maxRunsPerHour`, `maxUploadMb`, `timeoutSeconds`) | `crates/afg-executor` (Cloudflare backend), `crates/afg-cli/tests/cloudflare_cli.rs` | ✅ contract-tested against `tests/cloudflare-contract/mock_worker.rs` |
| Live round trip | `live_cloudflare_round_trip` (opt-in) | ❌ never run |

## 2. Gaps found against the current Cloudflare docs

| # | Gap | Risk | Fix |
|---|---|---|---|
| G1 | `wrangler.jsonc` uses `migrations: new_sqlite_classes` and an `AFG_IMAGE` string var. Under `scheduling_policy: "durable_object"` the documented shape is `"images": { "base": { "dockerfile": "./Dockerfile" } }` and `exports: { AfgSandbox: { type: "durable-object", storage: "sqlite" } }`. Wrangler builds the image, pushes it and pins it by digest, then exposes it as `ctx.container.images.base` | Deploy fails, or an unpinned or wrong image runs | Rewrite the config to the documented shape. Start with `image: this.ctx.container.images.base`, and drop `AFG_IMAGE` |
| G2 | `start()` sets no `instance`, so the default `lite` is used (256 MiB, 1/16 vCPU). Builds and tests will OOM. There's no swap, and OOM restarts the instance | Spurious failures; the policy's `memoryMB` and `cpus` are ignored | Send `memoryMB`, `cpus` and `diskMB` from the decision in the signed request. Map them to `instance: { vcpu, memoryMib, diskMb }`, clamped by `MAX_*` env limits in the Worker |
| G3 | `exec(..., { user: "65534" })`: the docs require `"uid:gid"`. They also state that **`user` does not restrict privileges under `durable_object`** | The exec call may be rejected; worse, the docs overstate the privilege drop | Use `user: "65534:65534"`. Document that the container, not the uid, is the boundary, and update `docs/security-boundaries.md` and the README |
| G4 | Egress is all or nothing (`enableInternet`) | Installs need `bridge`, which opens the whole internet | Add `network: allowlist` with hosts, implemented with `enableInternet: false` plus `interceptOutboundHttps(host, …)`. Only HTTP(S) works, with at most 128 entries. The image must trust `/etc/cloudflare/certs/cloudflare-containers-ca.crt` |
| G5 | `scheduling_policy` is **immutable**: switching means a new Container application | A wrong first deploy has to be redone | Deploy to a dedicated application name per environment (`agentforge-sandbox-staging`, `-prod`) and verify on staging first |
| G6 | The image must be `linux/amd64`, and wrangler needs local Docker to build on deploy | Deploys fail from Apple Silicon or Docker-less machines | Deploy from CI (`ubuntu-latest`, amd64, Docker present) with a scoped API token, never from laptops |
| G7 | Containers need the **Workers Paid** plan. Billing is per 10 ms while active (memory and disk as provisioned, CPU as used), plus egress | Unexpected cost | Keep the cost caps in afg and the Worker. Add Worker-side per-key rate limiting. Document the expected cost per run |
| G8 | `exec()` doesn't start a stopped container, and `start()` throws if it's already running | Race on a cold start | Keep the `running` check and readiness loop. Treat an OOM restart as a failed run, never a retry |

## 3. Work items (each test-first)

### T16.1: Config and runtime to the current API (G1, G2, G3, G8)
- **`wrangler.jsonc`:**
  - `images.base.dockerfile`;
  - `exports` instead of `migrations`;
  - `compatibility_date` bumped;
  - no `AFG_IMAGE`;
  - `MAX_VCPU`, `MAX_MEMORY_MIB` and `MAX_DISK_MB` vars.
- **`src/index.ts`:**
  - `start({ image: ctx.container.images.base, instance, enableInternet, env: {} })`;
  - `exec` with `user: "65534:65534"`;
  - an instance object clamped to the limits.
- **`src/protocol.ts`:**
  - add `resources: { vcpu, memoryMib, diskMb }` to `ExecuteRequest` and the validator;
  - bump the protocol version field.
  
  The Rust signer in `afg-executor` sends the policy's `container.memoryMB` and `cpus`. The shared signature test vector is updated on both sides.
- **Tests:**
  - vitest for the resource clamping and the `uid:gid` form;
  - the Rust contract test against the mock Worker, so the new field is sent and validated;
  - `wrangler deploy --dry-run` in CI.

### T16.2: Egress allowlist (G4)
- **Policy schema:** `backends.cloudflare.network: none | allowlist | bridge`, with `allowHosts: [...]` (hostnames and globs). `afg policy validate` warns on `bridge` and errors on more than 64 hosts.
- **Worker:** for `allowlist`, use `enableInternet: false` plus `interceptOutboundHttps` for each host, forwarding to the real host. Non-HTTP traffic and other hosts stay unreachable, because DNS resolves only intercepted names.
- **Image:** add the Cloudflare containers CA to the system trust store at build time.
- **Tests:** a unit test for the allowlist-to-intercept mapping. A live E2E test (T16.4) checks that `curl` to an allowed host succeeds and to another host fails.

### T16.3: Abuse, cost and key handling (G7)
- **Worker:** a per-key rate limit (Durable Object counter or Workers Rate Limiting binding), returning 429. The request-size cap already exists. A daily ceiling comes from an env var.
- **Keys:** document rotation: `wrangler secret put AFG_SIGNING_KEY` plus the afg key file. Add `key_id` to the signature header (`v1;kid=…`) so two keys can be valid during a rotation.
- **Logs:** Workers Logs keep only id, decision hash, duration and exit code. No argv values that redaction would flag, and no output.

### T16.4: Live verification (closes the "never run live" gap)
- **`.github/workflows/cloudflare-e2e.yml`:**
  - `workflow_dispatch` plus weekly;
  - environment `cloudflare-staging`, with required reviewers;
  - secrets `CLOUDFLARE_API_TOKEN` (scoped to Workers and Containers on one account) and `AFG_CLOUDFLARE_KEY`.
- **Steps:**
  1. `wrangler deploy` to `agentforge-sandbox-staging`.
  2. Run `cargo test -p afg-cli --test cloudflare_cli -- --ignored live_` against it.
  3. Tear down: delete the staging Worker and its images after the run, unless `keep=true`.
- **Live tests to add:** each maps to the Security Validation Matrix (Milestone v1.1):

| Live test | Expected |
|---|---|
| Allowed `sh check.sh` round trip | Exit code and output returned, `manifestHash` matches |
| `.env` / `~/.ssh` absent from the uploaded snapshot | Not present in the container |
| Replay of the same signed request | Rejected (id already used) |
| Bad or expired signature | 401 / 400 |
| `network: none`: `curl https://example.com` | Fails |
| `network: allowlist` (example.com only): allowed and other host | Allowed succeeds, other fails |
| Command exceeds `timeoutSeconds` | Exit 124, container destroyed |
| Memory above the instance | Run fails (OOM); next request unaffected |
| TTL alarm: kill the invocation mid-run | Container destroyed by the alarm (`wrangler containers list` shows none) |

### T16.5: Docs and release
- **Update** `packages/cloudflare-adapter/README.md` (deploy through CI, the immutable scheduling policy, the Paid plan, amd64), `docs/provider-compatibility.md` (status: verified live, with the date and version), `docs/security-boundaries.md` (`user` isn't a privilege boundary under `durable_object`) and `docs/threat-model.md` (the Worker endpoint is a new attack surface: signed requests, rate limits, key rotation).
- **Record** T16.1–T16.5 in `docs/plan.md`, with an alignment-log entry.
- **Ship** in the next rc. The README's Limitations line about Cloudflare changes only after T16.4 passes.

## 4. Out of scope, per the reference
- **Code Mode / Dynamic Workers** for running commands. Dynamic Workers can't start native processes, so shell, compiler and install workloads belong in the container.
- **MCP:** a "Cloudflare MCP sandbox shell" is not what this is. An MCP server that calls `afg run`, with the decision still in Rust, is a separate item.
- **Policy decisions in TypeScript.** The Worker checks only the signature and the request's structure (ADR 0002).
- **Claiming CI fidelity.** This is preflight, not a runner replacement (see `docs/provider-compatibility.md`).

## 5. Acceptance criteria
- `pnpm -C packages/cloudflare-adapter check` (typecheck plus vitest), `cargo test --workspace` and `wrangler deploy --dry-run` pass in CI.
- `cloudflare-e2e.yml` passes all T16.4 live tests on a fresh staging deploy, and leaves no running containers or Workers behind.
- No secret ever appears in a request body, Worker log, audit record or the repo.
- The docs say exactly what was verified live, and on which date and version.

## 6. Prerequisites from the owner
- A Cloudflare account on the **Workers Paid** plan.
- A scoped API token: Workers Scripts edit plus Containers edit, limited to one account.
- A GitHub environment `cloudflare-staging` with required reviewers, holding that token and the afg signing key.
- An approval-gated afg policy rule for `npx wrangler` (deploys reach the network and change infrastructure).

## 7. Verify before implementing
These points weren't fully covered by the docs read for this plan:
- The full `containers` and `exports` key list on the wrangler configuration page; only a summary was read.
- The default of `enableInternet` when it's omitted. Always set it explicitly.
- Whether the `basic` instance type is accepted under `durable_object`. The limits page lists it; the scheduling-policy page says the runtime rejects it.
- The current major version of `@cloudflare/sandbox`. The adapter doesn't use it; it uses the raw Container API.
