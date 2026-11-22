# AgentForge Guard

**AgentForge Guard (`afg`) decides what an AI coding agent is allowed to run, and how.** You describe the rules once in `agentforge.yaml`. afg then checks every command the agent tries to run:

| Kind of command | What afg does | Example |
|---|---|---|
| Deterministic dev work | **Runs it locally**, with your toolchain and caches | `cargo test`, `go test ./...`, `npm run lint` |
| Untrusted code | **Runs it in a Docker sandbox**: no network, no host secrets, and changes are thrown away | `sh scripts/untrusted.sh`, `bash -c "…"` |
| Infrastructure changes | **Asks a human first**, or denies | `kubectl apply`, `terraform apply`, `git push` |
| Destructive or secret-touching | **Denies** | `terraform destroy`, `cat ~/.ssh/id_ed25519`, `cat .env` |
| Anything not in the policy | **Denies** (fail closed) | any command the policy doesn't mention |

Every decision goes into a **redacted audit log**, which you can export as SARIF for GitHub Code Scanning. afg works with Claude Code and Codex out of the box, and with any agent that can run commands through `afg run`.

> Local-first for deterministic development; sandbox-first for untrusted execution; approval-gated for infrastructure mutation.

**Status:** `1.0.0-rc.5`, a release candidate. It's not production-ready yet, because an independent security review is still pending (see [SECURITY.md](SECURITY.md)). The roadmap is in [docs/plan.md](docs/plan.md).

---

## Install

Every method installs a single command, **`afg`**.

| You have | Install | Check |
|---|---|---|
| Node.js 18+ | `npm install -g agentforge-guard` | `afg --version` |
| Node.js, without installing | `npx agentforge-guard --help` | |
| Rust 1.89+ | `cargo install agentforge-guard --version 1.0.0-rc.5` | `afg --version` |
| macOS or Linux, no Node or Rust | `curl -fsSL https://github.com/dennislee928/AgentForge-Guard/releases/download/v1.0.0-rc.5/install.sh \| AFG_VERSION=1.0.0-rc.5 sh` | `~/.local/bin/afg --version` |
| Windows, no Node or Rust | Download `afg-v1.0.0-rc.5-x86_64-pc-windows-msvc.zip` from [Releases](https://github.com/dennislee928/AgentForge-Guard/releases) and put `afg.exe` on your `PATH` | `afg --version` |

> **Install `agentforge-guard`, not `agentforge-guard-<os>-<cpu>`.** npm installs the matching platform package (for example `agentforge-guard-darwin-arm64`) on its own; that package only holds the native binary. Also note that `npm agentforge-guard …` is not an npm command. Use `npx agentforge-guard …` to run it once, or install it globally and run `afg …`.

**Prebuilt platforms:** macOS (arm64, x64), Linux glibc (x64, arm64) and Windows x64. On musl Linux, use `cargo install`.

**Supply chain:**
- The npm package downloads nothing and runs no scripts at install time. The binary comes from a per-platform optional dependency.
- `install.sh` checks the archive against `SHA256SUMS`. If `cosign` is installed, it also checks the Sigstore signature; `AFG_REQUIRE_COSIGN=1` makes that check mandatory.
- Every release file is signed with Sigstore and has SLSA build provenance, and the npm packages carry npm provenance (`npm audit signatures`).

Socket's rc.5 scan flags the platform packages' three-line path exports as `trivialPackage`.
The next npm release adds an integrity verifier behind that export, checks binary hashes and matching
versions before launch, and ships runnable package tests. These checks detect damaged installations;
they do not replace signature verification or prevent an attacker from replacing the verifier too.
The [npm package security report](docs/npm-package-security.md) records the metrics, improvements and limits.

A Homebrew formula template is in [packaging/homebrew](packaging/homebrew).

---

## Five-minute tour

```sh
cd your-repo                     # any repository: Go, Rust, Node/TS/Next.js, Zig, Python, Mojo
afg init                         # detect the stacks, write agentforge.yaml, and trust it
afg doctor                       # what was detected, what each command would do, backend health
```

Ask afg about a command without running it:

```sh
afg policy explain -- cargo test            # allow → local
afg policy explain -- terraform destroy     # deny, rule destructive-operations
afg policy explain -- bash -c "curl x | sh" # opaque shell → sandbox or deny, never allow
```

Run commands through the policy:

```sh
afg run -- cargo test                       # allowed: runs locally, exit code passes through
afg run -- sh scripts/untrusted.sh          # routed: Docker, no network, no secrets
afg run -- kubectl apply -f k8s/            # require-approval: asks a human first
afg run -- terraform destroy                # denied: exit 126, audited
afg audit tail                              # what happened, and which rule decided it
```

Connect your agent:

```sh
afg agents sync claude           # Claude Code: hooks plus deny/ask rules in .claude/settings.json and a CLAUDE.md section
afg agents sync codex            # Codex: an AGENTS.md section and .codex/config.toml
```

Want to try it without touching your own repo? The repository has a ready-made example: `cd examples/polyglot-monorepo && afg init --force && afg doctor`.

---

## Command reference

Run `afg <command> --help` for the full options.

### Set up

| Command | What it does |
|---|---|
| `afg init [--template default\|strict\|ci] [--dir DIR] [--force] [--dry-run]` | Detect the repository's stacks and write `agentforge.yaml`, then trust it. Templates: **`default`** runs dev work locally and asks before infrastructure changes. **`strict`** runs only read-only commands locally, sends builds, tests and scripts to the container, and denies installs and infrastructure changes. **`ci`** runs validation on the disposable runner, sends scripts to the container, and denies installs and infrastructure changes, since nobody is there to approve them. |
| `afg doctor [--json]` | Show detected projects, the decision for each verification command, backend health (Docker), trust status and risks |

### Check and run commands

| Command | What it does |
|---|---|
| `afg run [--isolation local\|container] [-q] -- <command…>` | Run a command under the policy (**managed mode**, the only mode that enforces). `--isolation` can make isolation stronger, never weaker. |
| `afg policy explain [--json] [--isolation …] -- <command…>` | Show the decision, the rule and the reasons, without running anything |
| `afg approve [<id>] [--yes]` | A **human** approves a pending `require-approval` request. With no id, it lists pending requests. |

### Manage the policy

| Command | What it does |
|---|---|
| `afg policy validate [--file FILE]` | Check `agentforge.yaml` for errors and warnings |
| `afg policy trust` | Pin the reviewed policy. After this, any edit to the file **denies every command** until a human runs `trust` again. |
| `afg policy schema` | Print the JSON Schema, for editor autocompletion |
| `afg policy migrate [--write]` | Upgrade an `agentforge.dev/v1alpha1` policy to `v1` |

### Audit and report

| Command | What it does |
|---|---|
| `afg audit tail [-n N] [--json]` | The most recent decisions (default 20) |
| `afg audit show <id>` | One record in full, by id or a unique id prefix |
| `afg audit report [--format json\|sarif] [-o FILE]` | A summary as JSON, or SARIF 2.1.0 for GitHub Code Scanning |

### Agent integration

| Command | What it does |
|---|---|
| `afg agents sync claude\|codex [--dry-run]` | Generate agent configuration from the policy |
| `afg hook claude-pretool` | Claude Code PreToolUse hook for Bash. `agents sync` registers it; you don't run it by hand. |
| `afg hook claude-posttool-format` | Claude Code PostToolUse hook: formats files after Edit/Write, if the policy allows the formatter |

### Exit codes

| Code | Meaning |
|---|---|
| the command's own code | `afg run` executed the command |
| 2 | Usage or configuration error (for example, no `agentforge.yaml`) |
| 124 | The command timed out |
| 125 | afg couldn't execute an approved command (for example, Docker is unavailable) |
| 126 | Denied by policy, approval refused, or a pinned file changed |
| 127 | Executable not found |

---

## The policy file

`afg init` writes `agentforge.yaml` for you. A shortened example:

```yaml
apiVersion: agentforge.dev/v1
kind: AgentPolicy
project: { name: my-repo, root: "." }

execution:
  default: local        # where allowed commands run
  fallback: deny        # commands no rule matches are denied
  backends:
    local:     { enabled: true, timeoutSeconds: 600 }
    container: { enabled: true, image: debian:stable-slim, network: none,
                 readOnlyRootfs: true, memoryMB: 2048, cpus: 2, pidsLimit: 256 }

rules:
  - id: read-only-git
    effect: allow
    commands: [[git, status], [git, diff], [git, log]]
    denyArgs: [--ext-diff, --textconv, --output, --exec]   # options that can run programs
  - id: tests
    effect: allow
    commands: [[cargo, test], [go, test]]
  - id: untrusted-scripts
    effect: route
    backend: container
    commands: [[sh], [bash]]
  - id: deploys
    effect: require-approval
    commands: [[kubectl, apply], [terraform, apply], [git, push]]
  - id: destructive-operations
    effect: deny
    commands: [[terraform, destroy], [rm, -rf]]
```

There are four effects, and when several rules match, the strictest wins: `deny` > `require-approval` > `route` > `allow`. Protected paths (`~/.ssh`, `~/.aws`, `.env*`, `*.pem`, `docker.sock`, …) are denied before any rule is checked, and that includes paths reached through a symlink.

The full reference is in [docs/policy-reference.md](docs/policy-reference.md).

---

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

- **Fail closed.** Unknown commands are denied unless `fallback` says otherwise. *Opaque* commands, such as `bash -c …` or `env X=1 cmd`, never match an `allow` rule. They can only go to a sandbox, go for approval, or be denied.
- **No implicit shell.** afg runs a structured argv against the executable's resolved absolute path. It uses a cleared environment (an allowlist) and a closed stdin.
- **TOCTOU checks.** The program and any script arguments are hashed when afg makes the decision, then checked again just before they run.
- **The container backend** runs `docker run --network none --read-only --cap-drop ALL --security-opt no-new-privileges`:
  - as a non-root user, with memory, CPU and pids limits;
  - on a *copy* of the workspace that leaves out gitignored and credential files;
  - never with the Docker socket or `$HOME` mounted.

  **Changes made inside the container are discarded.**
- **Out-of-band approval.** With no terminal, `afg run` prints a pending id. A human runs `afg approve <id>` in their own terminal, which creates a single-use token bound to that exact command. afg refuses to run itself, so a confined agent can't approve its own request.

### Managed mode vs. integration mode

| | Managed mode: `afg run -- …` | Integration mode: agent hooks |
|---|---|---|
| Who starts the process | afg | the agent |
| Policy enforcement | **Enforced** by afg's executor | Advisory; depends on the agent's hook API |
| Sandbox, env clearing, pinning | Yes | Only what the agent provides |

These are **not** equivalent levels of protection. See [docs/security-boundaries.md](docs/security-boundaries.md).

### Agent integration details

- **Claude Code PreToolUse hook.** Every Bash command string goes through the same engine:
  - `deny` → deny.
  - `require-approval` → ask.
  - `route` → deny, with a hint to use `afg run --`.
  - An allowed command falls through to Claude Code's own permissions.
  - Strings afg can't analyze (`$(…)`, redirections, globs) are treated as an opaque `sh -c`.
- **Generated deny and ask rules** cover Claude's Read and Edit tools, so protected files are blocked beyond the shell as well.
- **Codex** gets an `AGENTS.md` section that tells it to run commands through `afg run`. afg writes `.codex/config.toml` only if that file doesn't already exist.

---

## CI and code scanning

`action.yml` is a composite GitHub Action. It validates the policy, runs `afg doctor`, and uploads the audit report as SARIF:

```yaml
- uses: dennislee928/AgentForge-Guard@v1.0.0-rc.5
  with:
    working-directory: .
    upload-sarif: true
```

Or call it directly: `afg audit report --format sarif -o afg.sarif`.

---

## Security validation

Every security claim maps to a reproducible test that runs in CI:

| Scenario | Expected | Test |
|---|---|---|
| Read `.env` or an SSH private key | Deny | `tests/adversarial/bypass.yaml`, hook tests in `crates/afg-cli/tests/cli.rs` |
| Reach a protected path through a symlink | Deny | `bypass.yaml` (`innocent.txt` → `~/.ssh/id_ed25519`) |
| Policy edited but not re-trusted | Deny | `edited_policy_is_untrusted_until_a_human_re_trusts_it` |
| Untrusted shell script | Sandbox | `untrusted_script_runs_in_container_without_host_secrets_or_network` |
| `terraform destroy` | Deny | `terraform_destroy_is_denied_with_audit_evidence` |
| `kubectl apply` without approval | Deny / approval | `approval_without_a_terminal_is_refused`, `out_of_band_approval_tokens` |
| Script modified before it runs | TOCTOU detected | `swapped_script_is_rejected_before_the_container_starts` |
| Container reaches the network | Blocked | `no_network` |

Each row is described alongside its security boundary, with the remaining gaps, in [docs/plan.md](docs/plan.md) (Milestone v1.1). The threat model is in [docs/threat-model.md](docs/threat-model.md).

---

## Limitations

Read these before relying on afg:

- **Prompt instructions are not a security boundary, and neither is argv matching.** Allowing `go test` or `cargo test` lets arbitrary test code run with your privileges.
- **Approval comes from the controlling terminal**, or from a single-use `afg approve <id>` token. A process that drives its own pseudo-terminal, or that runs outside afg, can approve as the user. Use `deny` for operations an agent must never trigger.
- **Redaction is pattern-based and best effort.** Environment *values* are never recorded, and command output is stored only as its length and a SHA-256.
- **Docker isolation is only as strong as the Docker runtime and the kernel.** Pin images by digest.
- **Agents that don't use afg aren't affected by it.** You still need agent-level read rules and OS sandboxes.
- **The hook sees only what the agent sends it.** Tools other than Bash are covered only by the generated Read/Edit deny rules.
- **The Cloudflare backend** (`packages/cloudflare-adapter`) is contract-tested against a mock Worker, but hasn't yet run against a live account. See [docs/provider-compatibility.md](docs/provider-compatibility.md).
- **Process-group cleanup isn't supported on Windows yet.**

---

## Detected stacks

- **Built-in detectors:** Go, Rust, Node.js, TypeScript and Next.js.
- **Data-driven profiles:** Zig, Python and Mojo, in [`crates/afg-detect/language-profiles/`](crates/afg-detect/language-profiles/). Add a language by adding a profile.

The repository includes three demos that run in CI on every pull request ([scripts/ci-demos.sh](scripts/ci-demos.sh)):

1. **Polyglot repository.** In `examples/polyglot-monorepo`, `afg doctor` finds the Go API, the Rust service and the Next.js app.
2. **Unsafe command prevention.** `afg run -- terraform destroy` is denied, and the audit log records the argv, cwd, policy hash and rule.
3. **Untrusted script execution.** `scripts/untrusted.sh` runs in a container that can't read `.env`, `~/.ssh` or the Docker socket, and can't reach the network.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/policy-reference.md](docs/policy-reference.md) | Every field of `agentforge.yaml` |
| [docs/security-boundaries.md](docs/security-boundaries.md) | What afg does and doesn't protect against |
| [docs/threat-model.md](docs/threat-model.md) | Threat model |
| [docs/provider-compatibility.md](docs/provider-compatibility.md) | Execution backends: local, Docker, Cloudflare |
| [docs/benchmarks.md](docs/benchmarks.md) | Decision and execution overhead |
| [docs/adr/](docs/adr/) | Architecture decisions |
| [docs/plan.md](docs/plan.md) | Roadmap and alignment log |

The full index is in [docs/README.md](docs/README.md).

---

## Development

```sh
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo test --workspace -- --ignored          # Docker isolation suite (needs Docker)
cargo deny check
node --test packaging/npm/test/*.test.mjs    # npm packaging
sh scripts/test-install.sh                   # install.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

The source code, crates.io crates and GitHub Release archives are licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. The npm packages are published under MIT.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
