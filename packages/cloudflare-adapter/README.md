# @agentforge/cloudflare-adapter

The Cloudflare backend for AgentForge Guard: a Worker plus one Durable Object
container for each approved request.

**This adapter makes no policy decisions** (ADR 0002). `afg` evaluates the
policy locally, then sends a request signed with a per-project HMAC key. The
Worker:

1. verifies the `X-AFG-Signature: v1=<hmac>` header over the raw body;
2. validates the request's structure and that `issuedAt` is within ±300 s;
3. hands it to the Durable Object named after the request id, which runs each
   id **at most once**, so requests can't be replayed.

The container then:

- starts with **no internet** unless the decision allowed `bridge`;
- receives the manifest-filtered snapshot as a tar stream into `tar -x`;
- runs the exact argv as uid 65534 under coreutils `timeout`;
- returns the exit code and bounded output with SHA-256 digests;
- is **always destroyed** afterwards. An alarm at `SESSION_TTL_SECONDS` destroys it even if the invocation dies.

The adapter uses the Workers runtime Container API directly (`ctx.container`:
`start`, `exec`, `destroy`), which is the Sandbox SDK 1.0 model. It doesn't
use the SDK's `Files` helper, so the image needs only coreutils and `tar`, not
`sandbox-shim`.

## Status

| Check | Status |
|---|---|
| Type-checks with TypeScript 7.0.2 against `@cloudflare/workers-types` 5.20261119.1 | ✅ |
| Unit tests for the protocol, including the shared signature vector with the Rust signer | ✅ |
| `wrangler deploy --dry-run` (wrangler 4.165.0) accepts the config and bundles the Worker | ✅ |
| Deployed and exercised against a real Cloudflare account | ❌ not yet. Needs an account; see the opt-in live test |

## Deploy (unverified; check the current Containers docs first)

```sh
cd packages/cloudflare-adapter
# 1. Build and push the image, then put its digest-pinned reference in wrangler.jsonc (AFG_IMAGE).
# 2. Generate a key and share it with afg:
openssl rand -hex 32 > ~/.config/agentforge/cloudflare.key   # afg reads AFG_CLOUDFLARE_KEY or this file
npx wrangler secret put AFG_SIGNING_KEY < ~/.config/agentforge/cloudflare.key
# 3. Deploy. Moving a class to scheduling_policy "durable_object" cannot be undone.
npx wrangler deploy
```

Then enable the backend in `agentforge.yaml`:

```yaml
execution:
  backends:
    cloudflare: { enabled: true, endpoint: "https://agentforge-sandbox.<you>.workers.dev" }
```

The Cloudflare sandbox is **not** a 1:1 reproduction of CI. See
[docs/provider-compatibility.md](../../docs/provider-compatibility.md).
