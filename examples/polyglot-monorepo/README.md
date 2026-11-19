# Example: polyglot monorepo

A Go API, a Rust service and a Next.js app in one repository, used by the
AgentForge Guard quickstart and CI demos.

```sh
cd examples/polyglot-monorepo
afg doctor                                   # detects Go, Rust and Next.js
afg run -- go test ./...                     # (from services/go-api) allowed, runs locally
afg run -- terraform destroy                 # denied, exit 126, audited
afg run -- sh scripts/untrusted.sh           # routed to a Docker container
afg audit tail
```

`agentforge.yaml` is exactly what `afg init` generates here; a test keeps it in sync.
`.env.example` holds placeholders only.
