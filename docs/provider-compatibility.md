# Provider Compatibility

What each execution backend can and can't faithfully reproduce. A sandbox
is good for **script preflight and build or test verification**. Final CI
fidelity still needs the real CI runner.

## Backends at a glance

| | `local` | `container` (Docker) | `cloudflare` |
|---|---|---|---|
| Who decides | afg-core | afg-core | afg-core (the Worker only verifies the signature) |
| Filesystem | the live workspace | a filtered **copy**, writable, discarded | a filtered **copy** (tar upload), discarded |
| Network | the host's | `none` by default | **off** unless `network: bridge` |
| Credentials | env allowlist only | none unless allowlisted | none unless allowlisted |
| Toolchains | yours, with native caches | whatever the image has | whatever the image has |
| Cost and lifetime | local | local | `maxUploadMb`, `timeoutSeconds` (at most 3600), `maxRunsPerHour`, always destroyed, TTL alarm |
| Needs | nothing | Docker | a Cloudflare account and the deployed Worker |

## CI features a sandbox does not reproduce

| Feature | `container` / `cloudflare` | Notes |
|---|---|---|
| Plain shell scripts, builds, unit and integration tests | ✅ | The intended use: preflight before CI |
| Language caches (`GOCACHE`, `target/`, `node_modules`) | ⚠️ cold | Snapshots exclude gitignored files, so every run starts cold. Use `local` for fast iteration |
| GitHub Actions `uses:` steps and the expression context | ❌ | afg runs commands, not workflows |
| OIDC tokens (`id-token: write`), cloud federation | ❌ | No identity is issued, by design. Never pass long-lived cloud keys instead |
| Repository and organization secrets | ❌ | Deliberately absent |
| Service containers (`services:`), Docker-in-Docker, privileged containers | ❌ | No Docker socket and no privileges, by design |
| Kubernetes or GitLab executors, runner labels and hardware | ❌ | |
| Network egress to package registries | ⚠️ | Off by default. Installs need `network: bridge` (a validator warning) or human approval locally |
| Artifacts and caches between jobs | ❌ | Results come back as exit code plus bounded output only |
| Exact OS and kernel parity with `ubuntu-latest` | ⚠️ | Use an image that matches your runner if parity matters |

## Cloudflare-specific notes

- The adapter uses the Workers runtime Container API (`ctx.container`: `start`, `exec`, `destroy`), which is the Sandbox SDK 1.0 model. It runs **one container per request id**, which also blocks replays.
- **Status.** It type-checks against `@cloudflare/workers-types`, wrangler's dry run accepts the config, and the protocol is contract-tested against a mock Worker. It **has not been exercised against a live account**: `live_cloudflare_round_trip` is opt-in.
- **Irreversible migration.** Moving a Durable Object class to `scheduling_policy: "durable_object"` can't be undone. Read the current Cloudflare docs before deploying.
- **Changed defaults.** `enableInternet` defaults to `false` in the 1.0 model. afg sets it from the signed request's `network`.

## Choosing a backend

- **Trusted, deterministic dev loop** (`cargo check`, `go test`, `pnpm lint`): `local`.
- **Unknown scripts, generated code, third-party repos**: `container`.
- **The same, without local Docker**, or where you want the code off the workstation entirely: `cloudflare`.
- **Infrastructure mutation**: none of them. Use `require-approval` or `deny`, and a human-controlled CI/CD pipeline.
