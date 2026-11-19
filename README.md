# AgentForge Guard

**AgentForge Guard (`afg`) is a policy-driven, agent-agnostic code-execution tool for AI coding agents.** A single policy file decides what an agent's commands may do:

- Deterministic development work (builds, tests, linters) runs **locally**, with your native toolchain and caches.
- Untrusted code (scripts, generated shell) runs in a **Docker sandbox** with no network and no host secrets.
- Infrastructure changes (deploys, `kubectl apply`, `git push`) need **human approval**, or are denied.
- Every decision is written to a **redacted audit log**.

> Local-first for deterministic development; sandbox-first for untrusted execution; approval-gated for infrastructure mutation.

Status: **v0.1.0, an early release.** It is not production-ready. See [docs/plan.md](docs/plan.md) for the roadmap.

## Quickstart

Requires Rust 1.89+. Docker is optional and only needed for the container backend.

```sh
git clone <this repository> agentforge-guard && cd agentforge-guard
cargo install --path crates/afg-cli          # installs the `afg` binary

cd examples/polyglot-monorepo                # or any repository of yours
afg init --force                             # writes agentforge.yaml from detected stacks
afg doctor                                   # stacks, per-command decisions, backends, risks
```

Run commands through the policy:

```sh
(cd services/rust-service && afg run -- cargo test)   # allowed → runs locally
afg run -- terraform destroy                 # denied → exit 126, audited
afg run -- sh scripts/untrusted.sh           # routed → Docker, no network, no secrets
afg run -- kubectl apply -f k8s/             # asks a human on the terminal
afg policy explain -- git -c core.pager=sh log   # shows why, without running anything
afg audit tail
```

## Demos

1. **Polyglot repository.** In `examples/polyglot-monorepo`, `afg doctor` finds the Go API, the Rust service and the Next.js app, and shows the policy decision for each verification command.
2. **Unsafe command prevention.** `afg run -- terraform destroy` is denied by the `destructive-operations` rule, and the audit log records argv, cwd, the policy hash and the rule.
3. **Untrusted script execution.** `scripts/untrusted.sh` runs in a container. It cannot read `.env`, `~/.ssh` or the Docker socket, and cannot reach the network.

Demos 2 and 3 run in CI on every pull request ([scripts/ci-demos.sh](scripts/ci-demos.sh)).

## How it works

```text
argv ─► normalize ─► protected paths ─► rules ─► fallback ─► backend ─► audit
         │             │                 │         │
         │             │                 │         └ default: deny
         │             │                 └ deny > require-approval > route > allow
         │             └ ~/.ssh, ~/.aws, .env*, *.pem, docker.sock … → deny
         └ resolve the executable, unwrap env/nice/timeout, mark shells,
           interpreters, xargs/make and shell syntax as *opaque*
```

- **Fail closed.** Unknown commands are denied unless the policy's `fallback` says otherwise. Opaque commands, such as `bash -c …` or `env X=1 cmd`, never match `allow` rules. They can only be routed to a sandbox, sent for approval, or denied.
- **No implicit shell.** `afg` runs a structured argv against the executable's resolved absolute path, with a cleared environment (an allowlist) and closed stdin.
- **TOCTOU checks.** The program and any script arguments are pinned (hashed) when the decision is made and re-checked just before execution.
- **The container backend** runs `docker run` with `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, a non-root user, memory, CPU and pids limits, and a *copy* of the workspace that excludes gitignored and credential files. The Docker socket and `$HOME` are never mounted. **Changes made inside the container are discarded.**

The policy format is described in [docs/policy-reference.md](docs/policy-reference.md), and the design decisions in [docs/adr/](docs/adr/).

## Managed mode vs. integration mode

| | Managed mode: `afg run -- …` | Integration mode: agent hooks (v0.2) |
|---|---|---|
| Who spawns the process | afg | the agent |
| Policy enforcement | **enforced** by afg's executor | advisory; it depends on the agent's hook API |
| Sandbox, env clearing, pinning | yes | only what the agent provides |

These are **not** equivalent levels of protection. See [docs/security-boundaries.md](docs/security-boundaries.md).

## Limitations

Read these before relying on afg:

- **Prompt instructions are not a security boundary**, and neither is argv matching. Allowing `go test` or `cargo test` lets arbitrary test code run with your privileges.
- **Approval is read from the controlling terminal.** A process that drives its own pseudo-terminal can answer the prompt. Out-of-band approval tokens are planned for v0.2 (T7.4).
- **Redaction is pattern-based and best effort.** Environment *values* are never recorded, and output is stored only as a length and a SHA-256.
- **Docker isolation is only as strong as the Docker runtime and kernel.** Pin images by digest.
- **Agents that don't use `afg` are not affected by it.** Agent-level read rules and OS sandboxes are still needed.
- **There is no Windows support for process-group cleanup yet.** The Cloudflare backend is planned for v0.4.

## Exit codes

| Code | Meaning |
|---|---|
| command's own code | `afg run` executed the command |
| 2 | usage or configuration error (for example, no `agentforge.yaml`) |
| 124 | the command timed out |
| 125 | afg could not execute an approved command (for example, Docker is unavailable) |
| 126 | denied by policy, approval refused, or a pinned file changed |
| 127 | executable not found |

## Development

```sh
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo test --workspace -- --ignored          # Docker isolation suite
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
