# AgentForge Guard — Assessment & Implementation Plan

## Context

The repo is empty apart from `LICENSE` (MIT), `.gitignore` (which ignores `/.ignore`) and `.gitattributes`. The spec is `.ignore/reference.txt`, a Chinese-language review of a hybrid AI-coding-sandbox architecture followed by a proposal to build it as an open-source tool, **AgentForge Guard (`afg`)**. `afg` is an agentic code-execution tool. Every command an agent wants to run goes through a single Rust policy engine. That engine decides allow, deny, require-approval or route, then runs the command on a local, Docker or (later) Cloudflare backend and writes a redacted audit record.

User decisions:
- **It is not an MCP server.** It is an agentic code-execution tool. Agents use it through `afg run` (managed mode) and through native agent hooks. MCP is dropped from the plan.
- **License:** dual MIT / Apache-2.0.
- **Scope:** every milestone is planned at task level.

Working rules for execution:
- **One commit per completed task**, as a Conventional Commit ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **A phase alignment check at the end of each phase.** Re-read `docs/plan.md`, tick the finished tasks, record any deviations or new risks in its "Alignment log", fix drift, then commit `docs(plan): align after phase N`.
- Work on a branch per milestone (`milestone/v0.1`, and so on) and fast-forward merge to `main` locally when the milestone passes its gate. Never push without asking.
- Use TDD. The workspace must build and all tests must pass after every task.

## Assessment of reference.txt

**Sound, keep:**
- Run deterministic development work locally, run untrusted code in a sandbox, and gate infrastructure changes behind approval.
- Use four trust tiers, T0–T3.
- "Prompt instructions are not a security boundary."
- Fail closed on unknown commands.
- Use structured argv and never run commands through an implicit shell.
- Have a single policy engine that every adapter shares.
- Separate managed mode from agent-integration mode, and be honest about the difference.
- Upload a manifest-filtered workspace to remote sandboxes.
- Test for TOCTOU (time-of-check to time-of-use) races.
- Treat test runners and build tools as arbitrary code execution.

**Issues to correct in the plan:**
1. **Roadmaps conflict.** §6 makes v0.2 "agent integration" and v0.3 "Cloudflare". The language section makes v0.2 "Zig" and v0.4 "Mojo", and puts a TypeScript MCP server in v0.1. This plan merges them into one ordering (below) and drops MCP.
2. **The repo layout has duplicates:** `afg-mcp` (Rust) and `packages/mcp-server` (TS). Both are dropped. TypeScript is kept only for the Cloudflare adapter and generated policy types.
3. **The sample policy's `read-only` rule is unsafe as written.** A plain argv-prefix match on `["git","diff"]` also allows `git diff --ext-diff`, `git -c diff.external=… diff` and `--output=…`, and each of these can run code or write files. Rules therefore need argument constraints (`denyArgs` and `allowFlags`), and global options such as `git -c` or `--git-dir` must be normalized before matching.
4. **Approval semantics are underspecified.** If an agent can answer the approval prompt, the approval is meaningless. Approval must come from a human-controlled channel: the controlling TTY, or a signed one-time token. With no TTY, the command is denied.
5. **Some claims were unverified as of 2026-11-19 and must be checked at implementation time, not trusted:**
   - Cloudflare Sandbox SDK "1.0" and its API.
   - The exact Codex config keys.
   - The JSON contract for Claude Code hooks.
   The plan pins versions and re-reads the official docs in the task that uses each one.
6. **Toolchain gaps on this machine.** Go and Zig are not installed; Rust 1.99, Docker 29, Node 24 and pnpm 9 are. Tests that need Go or Zig use detection fixtures, and live toolchain tests are `#[ignore]`d unless the tool is present. CI installs both.
7. **License.** The repo is MIT and the reference recommends Apache-2.0. Resolved to dual licensing.

## Architecture (fixed decisions)

- **Rust workspace crates:**
  - `afg-core`: policy schema, normalizer, evaluator, decision types.
  - `afg-detect`: stack and agent detection.
  - `afg-executor`: the `Executor` trait plus the `local` and `docker` backends.
  - `afg-report`: audit JSONL, redaction, SARIF.
  - `afg-cli`: the `afg` binary, using clap and tokio.
- **TypeScript (`packages/`)** exists only from v0.4: `policy-types` (generated from JSON Schema) and `cloudflare-adapter`.
- **Evaluation pipeline:**
  1. Parse the request into `ExecutionRequest { argv, cwd, env_allowlist, timeout, limits, network, snapshot }`.
  2. **Normalize:**
     - Resolve the executable to an absolute path and canonicalize it.
     - Unwrap known wrappers: `env`, `command`, `exec`, `nice`, `nohup`, `timeout`, `sudo` (sudo → deny).
     - Detect shell interpreters (`sh`, `bash`, `zsh`, `-c`) and treat them as opaque.
     - Detect `xargs`, `find -exec` and `make` as indirect execution, and treat them as opaque.
  3. **Protected-path check.** Any argument or cwd that canonically resolves, following symlinks, into a protected path is denied. Protected paths are `~/.ssh`, `~/.aws`, `~/.kube`, `~/.config/gcloud`, `.env*`, `*.pem`, `id_*` and the docker socket.
  4. **Rule match.** The precedence is deny > require-approval > route > allow. Anything unmatched or opaque falls to `execution.fallback`, which defaults to `deny`; a policy can set it to `route: container`.
  5. Return a `Decision { effect, backend, rule_id, reasons[], policy_hash }`.
- **TOCTOU defenses:**
  - The executor runs the resolved absolute path, not `$PATH` lookup.
  - Script files named in argv are hashed at check time and re-verified immediately before execution.
  - Docker runs against a copied snapshot directory, not the live tree.
- **Docker backend:** it runs `docker run` with a structured argv. The flags are:
  - `--rm`, `--network none` (by default), `--read-only`, `--tmpfs /tmp`.
  - `--memory`, `--cpus` and `--pids-limit` from the policy.
  - `--cap-drop ALL`, `--security-opt no-new-privileges`, `--user <uid>:<gid>`.
  - An env allowlist only.
  - Never a docker socket or a `$HOME` mount.
  - The snapshot is built from a manifest that excludes secrets and `.gitignore`d files, and is bind-mounted.
- **Audit:** append-only JSONL in `.agentforge/audit/`. Each record holds:
  - argv, cwd, the policy version and hash, the decision, the backend, the exit code, the duration and the output digests.
  - Secrets redacted: env values are always redacted, and token, key and PEM patterns are scrubbed from argv and output excerpts.

## Milestone v0.1 — CLI + Policy Engine + Docker Sandbox

### Phase 0 — Foundations
- [x] **T0.1** Add `LICENSE-MIT` (moved from `LICENSE`) and `LICENSE-APACHE`, and set `license = "MIT OR Apache-2.0"` in the README section and in Cargo.
- [x] **T0.2** Copy this plan into `docs/plan.md`, with checkboxes and an empty Alignment log. This file is the tracked source of truth for alignment checks.
- [ ] **T0.3** Write the ADRs in `docs/adr/`:
  - 0001 Rust core.
  - 0002 Single policy engine.
  - 0003 Fail-closed normalization.
  - 0004 Docker via CLI argv, no socket mounts.
  - 0005 No MCP; managed mode plus hooks.
  - 0006 Dual license.
- [ ] **T0.4** Write `docs/threat-model.md` (trust tiers T0–T3, attacker = the agent or the code it generated, assets, bypass classes) and `docs/security-boundaries.md`, which spells out managed mode versus integration mode.
- [ ] **T0.5** Create the Cargo workspace skeleton with the five crates. Add `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, and update `.gitignore` to cover `target/` and `.agentforge/audit/`.
- [ ] **T0.6** Write `CLAUDE.md` and `AGENTS.md` for contributors: the TDD rule, the Definition of Done commands, and "never weaken a deny test".
- [ ] **T0.7** Add `.github/workflows/ci.yml`, which runs fmt, clippy with `-D warnings`, test and cargo-deny on Linux and macOS.
- **Gate:** `cargo build` and `cargo test --workspace` pass with zero tests. Run the alignment check.

### Phase 1 — Policy schema & evaluator (`afg-core`)
- [ ] **T1.1** Write the v1alpha1 serde types with `deny_unknown_fields`. They cover the reference schema plus the `denyArgs`/`allowFlags` rule constraints and `protectedPaths`.
- [ ] **T1.2** Generate `agentforge.schema.json` with `schemars`. A test checks that the committed schema matches the generated one.
- [ ] **T1.3** Write the semantic validator: duplicate rule ids, unknown backends, a `route` rule with no backend, and a disabled backend being referenced.
- [ ] **T1.4** Write the normalizer: executable resolution, wrapper unwrapping, shell/indirect opacity, and `git` global-option handling.
- [ ] **T1.5** Write the protected-path checker, which uses canonicalization and resolves symlinks.
- [ ] **T1.6** Write the evaluator, covering precedence, fallback and the `Decision` reasons.
- [ ] **T1.7** Ship the built-in `policies/default.yaml`, `strict.yaml` and `ci.yaml`.
- [ ] **T1.8** Add the fixture suite `tests/policy-fixtures/*.yaml`, as triples of (policy, argv, expected decision), plus a table-driven runner. Future adapters must also pass these as conformance tests.
- [ ] **T1.9** Write the adversarial suite `tests/adversarial/`. It covers:
  - `bash -c`, `env sh`, nested shells.
  - `$(…)` and backtick substitution inside args.
  - `git -c`, `--ext-diff`.
  - `../` traversal and a symlink pointing to a fake `~/.ssh`.
  - `make deploy`, `xargs`.
  - Unicode and whitespace tricks in argv.

  Each case must end in deny or route.
- **Gate:** all fixtures pass. Run the alignment check.

### Phase 2 — Detection (`afg-detect`)
- [ ] **T2.1** Write the `Detector` trait and the Go detector (`go.mod`, `go.work`), which suggests `go vet ./...` and `go test ./...`.
- [ ] **T2.2** Write the Rust detector (`Cargo.toml`, with workspaces).
- [ ] **T2.3** Write the Node/TS/Next.js detector:
  - Inputs: `package.json`, `tsconfig.json`, `next.config.*`, and the package manager from its lockfile.
  - It suggests the scripts the project defines.
  - It marks `install` as T2, so that step runs in a container.
- [ ] **T2.4** Write the agent detector: `CLAUDE.md`, `.claude/`, `AGENTS.md`, `.codex/`.
- [ ] **T2.5** Write the risk detector, which flags committed `.env` files, a kubeconfig in the repo, terraform state, and CI scripts.
- [ ] **T2.6** Add fixture repos under `tests/language-detection/`. They are monorepos with nested projects.
- **Gate:** run the alignment check.

### Phase 3 — Executors (`afg-executor`)
- [ ] **T3.1** Write the `Executor` trait (`execute` and `cleanup`), along with `ExecutionRequest`, `ExecutionResult` and `ExecutionError`.
- [ ] **T3.2** Write the local executor:
  - No shell; it runs `Command::new(abs_path)`.
  - The environment is cleared, then only allowlisted variables are passed.
  - It enforces the timeout and kills the whole process group.
  - It captures and streams output.
- [ ] **T3.3** Write the snapshot builder: it builds a manifest from git-tracked files minus protected patterns, copies them to a temp dir, and records the manifest hash.
- [ ] **T3.4** Write the Docker executor, which builds the argv as specified in Architecture and checks that Docker is available.
- [ ] **T3.5** Add TOCTOU re-verification: script hashes and executable identity are re-checked immediately before spawning.
- [ ] **T3.6** Write isolation tests in `tests/sandbox-isolation/`. Each one is `#[ignore]` unless Docker is present.
  - A fake host `.env` and a fake `~/.ssh` key are unreadable from inside the container.
  - Network egress fails.
  - Writing to the root filesystem fails.
  - The memory limit OOM-kills the process.
  - The timeout kills the process.
  - The docker socket is absent.
- **Gate:** run the alignment check.

### Phase 4 — Audit & redaction (`afg-report`)
- [ ] **T4.1** Write the audit record type and the JSONL writer, which uses append mode and file locking.
- [ ] **T4.2** Write the redactor. It removes env values and scrubs these patterns:
  - AWS, GitHub and Slack tokens.
  - JWTs.
  - PEM blocks.
  - `key=` and `token=` assignments.

  Add property tests that check redacted output never contains seeded secrets.
- **Gate:** run the alignment check.

### Phase 5 — CLI (`afg-cli`)
- [ ] **T5.1** Write `afg init`. It writes `agentforge.yaml` from the detection results and the default policy. It never downloads or runs anything, and it refuses to overwrite an existing file without `--force`.
- [ ] **T5.2** Write `afg doctor`: the detected stacks and agents, risks, backend availability, and validation of the policy. It supports `--json`.
- [ ] **T5.3** Write `afg policy explain -- <argv>` (decision, matched rule, reasons) and `afg policy validate`.
- [ ] **T5.4** Write `afg run [--isolation local|container] -- <argv>`. It goes evaluate → approval → route → execute → audit. Its exit code passes through, and denials use exit code 126.
- [ ] **T5.5** Write the approval flow. It prompts on `/dev/tty` with the exact argv, cwd and backend. With no TTY, the command is denied. It never reads the approval from stdin.
- [ ] **T5.6** Write `afg audit tail` and `afg audit show <id>`.
- [ ] **T5.7** Write CLI integration tests with `assert_cmd`. They cover the full flow `init → doctor → run → audit` on a temp repo.
- **Gate:** run the alignment check.

### Phase 6 — Examples, docs, release gate
- [ ] **T6.1** Build `examples/polyglot-monorepo`: a Go API, a Rust service and a Next.js app, plus a committed sample `agentforge.yaml`.
- [ ] **T6.2** Add CI demo jobs:
  - (a) `terraform destroy` is denied, and the job asserts the audit record.
  - (b) An untrusted script run in Docker cannot read the host's fake credentials or reach the network.
- [ ] **T6.3** Write the README (quickstart, managed vs. integration mode, the honest limitations section) and `docs/policy-reference.md`.
- [ ] **T6.4** Add `CONTRIBUTING.md`, `SECURITY.md` and the issue templates.
- **Gate (v0.1 DoD):** fmt, clippy with `-D warnings`, and `cargo test --workspace` all pass. The deny and isolation tests pass, with isolation run on Linux CI. No secrets appear in the audit logs. The quickstart works from a clean checkout. Then run the alignment check, merge to `main`, and tag `v0.1.0` locally.

## Milestone v0.2 — Agent Integration & Reporting

The Claude Code hook JSON contract and the Codex config keys must be verified against the current official docs when these tasks start.

### Phase 7 — Claude Code adapter (`adapters/claude/`)
- [ ] **T7.1** Write `afg hook claude-pretool`. It reads the PreToolUse JSON from stdin, evaluates `Bash` commands with the same engine, and returns allow, deny or ask. Opaque shell strings are tokenized conservatively, and anything ambiguous returns deny or ask.
- [ ] **T7.2** Write the PostToolUse formatter hook, which runs after an Edit or Write operation. It is documented as running after that tool operation, not as an "onSave" event.
- [ ] **T7.3** Write `afg agents sync claude`. It generates the `.claude/settings.json` permission rules (allow/ask/deny, plus Read deny rules for protected paths) and the hook registration, and inserts a `CLAUDE.md` section between markers. The command is idempotent.
### Phase 8 — Codex adapter (`adapters/codex/`)
- [ ] **T8.1** Write `afg agents sync codex`. It inserts an `AGENTS.md` section between markers and generates recommended `.codex/config.toml` sandbox and approval settings as guidance.
- [ ] **T8.2** Check that `CLAUDE.md` and `AGENTS.md` are generated from one template, with a snapshot test.
### Phase 9 — Reporting & CI
- [ ] **T9.1** Write `afg audit report --format json|sarif`. Denied and approval-gated events map to SARIF results.
- [ ] **T9.2** Build a composite GitHub Action, `action.yml`, that runs `afg doctor` and `afg policy validate` and uploads the SARIF.
- [ ] **T9.3** Write conformance tests that check the hook decisions equal the `afg policy explain` decisions across every fixture.
- **Gate:** run the alignment check and tag `v0.2.0`.

## Milestone v0.3 — Language Profiles (Zig, data-driven detection)

- [ ] **T10.1** Move the hard-coded detectors to data-driven `language-profiles/*.yaml` files, which hold markers, verification commands and their tiers. The existing tests must stay green.
- [ ] **T10.2** Add a Zig profile (`build.zig`, `build.zig.zon` → `zig build`, `zig build test`) and a Zig version check.
- [ ] **T10.3** Add a Python profile, which is needed before Mojo. `pip install` is T2.
- [ ] **T10.4** Add a Mojo profile, covering detection and a build command only.
- [ ] **T10.5** Add Go and Zig to the CI matrix, which un-ignores the live toolchain tests. Add `examples/zig-project`.
- **Gate:** run the alignment check and tag `v0.3.0`.

## Milestone v0.4 — Cloudflare Sandbox Backend (TypeScript)

- [ ] **T11.1** Add the pnpm workspace and `packages/policy-types`, which generates TS types from `agentforge.schema.json`. CI fails if the generated types drift from the schema.
- [ ] **T11.2** Write `packages/cloudflare-adapter`, a Worker plus Sandbox SDK. Pin the SDK major version after re-reading the current docs. It exposes an authenticated execute endpoint that accepts only pre-approved `ExecutionRequest`s, signed by the CLI with a per-project key. It makes no policy decisions itself.
- [ ] **T11.3** Write the Rust `CloudflareExecutor`. It uploads the manifest-filtered snapshot, runs the command, downloads the result, and cleans up the session.
- [ ] **T11.4** Add lifecycle controls: session TTL, cost and timeout caps, and guaranteed cleanup when a run fails.
- [ ] **T11.5** Add tests:
  - A mocked Worker that checks the contract.
  - An opt-in live test that needs `CF_*` env vars.
  - A test proving that protected files never appear in the upload manifest.
- [ ] **T11.6** Write `docs/provider-compatibility.md`, covering the CI fidelity limits: OIDC, privileged Docker and service containers.
- **Gate:** run the alignment check and tag `v0.4.0`.

## Milestone v0.5 — Optional Native Helper & Mojo Plugin (experimental, gated)

- [ ] **T12.1** Build a benchmark and profiling harness for policy evaluation and executor overhead.
- [ ] **T12.2** Build the Zig native helper (`native/zig-helper`) **only if** T12.1 or a platform feature (process telemetry, C ABI) justifies it. It is a separate optional binary and makes no policy decisions.
- [ ] **T12.3** Build `plugins/mojo-compute` as an experimental, separately installed plugin for log and telemetry analysis. It runs through an authorized executor and gets no extra privileges.
- **Gate:** run the alignment check. If T12.1 shows no need, record that decision in an ADR and skip T12.2/T12.3.

## Milestone v1.0 — Stable

- [ ] **T13.1** Add fuzzing of the normalizer and policy parser (`cargo-fuzz`) and run it in a scheduled CI job.
- [ ] **T13.2** Have someone review the threat model, and add a regression test for every bypass found.
- [ ] **T13.3** Add a supply-chain workflow (`security.yml`): cargo-audit, cargo-deny, OSV, CodeQL, Dependabot.
- [ ] **T13.4** Add a release workflow (`release.yml`). It builds binaries for macOS arm64/x64, Linux x64/arm64 and Windows x64, and produces an SBOM (CycloneDX), cosign signing and SLSA provenance. It also publishes to crates.io, after checking that the name is free.
- [ ] **T13.5** Mark the policy schema `v1`, with a migration from `v1alpha1` (`afg policy migrate`).
- [ ] **T13.6** Run a documentation pass and set up a Homebrew tap.
- **Gate:** run the alignment check and tag `v1.0.0`. Never claim production readiness without green isolation and bypass suites.

## Verification

- **Every task:** `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- **Docker isolation:** `cargo test --workspace -- --ignored` runs locally. Docker 29 is present.
- **End-to-end (v0.1):** in a temp copy of `examples/polyglot-monorepo`:
  1. Run `afg init`.
  2. Run `afg doctor --json` and check that it lists Go, Rust and Next.js.
  3. Run `afg run -- cargo check`, which should be allowed and run locally.
  4. Run `afg run -- terraform destroy`, which should be denied with exit code 126 and leave an audit record.
  5. Run `afg run --isolation container -- sh ./untrusted.sh`, which should fail to read the fake creds and the network.
  6. Run `afg audit tail` and check that it shows redacted records.
- **v0.2:** pipe sample PreToolUse JSON into `afg hook claude-pretool` and compare the result with `afg policy explain`.
- **v0.4:** run the contract tests against the mocked Worker, plus the opt-in live run.

## Alignment log

- 2026-11-19 — T0.1: `license` field in Cargo deferred to T0.5 (no `Cargo.toml` exists yet). LICENSE-APACHE uses the standard terms-only text (as in serde).
