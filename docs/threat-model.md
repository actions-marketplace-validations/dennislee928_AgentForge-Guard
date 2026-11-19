# Threat Model

## Scope

`afg` runs between an AI coding agent and the system it acts on. This model covers v0.1 (local and Docker backends) and is revisited in every milestone.

## Attacker

The **agent itself**, or **code the agent generated or fetched** (scripts, dependencies, tests). Assume it is non-malicious but steerable. Prompt injection from repository content, issues, web pages or tool output can turn it into an active adversary. Prompt instructions (`CLAUDE.md`, `AGENTS.md`) are **not** a security boundary.

## Assets

| Asset | Examples |
|---|---|
| Host credentials | `~/.ssh`, `~/.aws`, `~/.kube`, `~/.config/gcloud`, `.env*`, `*.pem`, tokens in the environment |
| Shared infrastructure | Kubernetes clusters, cloud accounts, shared databases, registries |
| Source integrity | Git history, release artifacts |
| The host | The filesystem outside the workspace, the Docker daemon (`docker.sock`) |
| Audit integrity | `.agentforge/audit/*.jsonl` |

## Trust tiers

| Tier | Examples | Handling |
|---|---|---|
| T0: read-only | `git status`, `rg`, `cargo metadata`, `kubectl get` | Local, allowed |
| T1: workspace mutation | Edits, `cargo check/test`, `go test`, `pnpm lint` | Local, allowed (still arbitrary code: build scripts and tests can do anything the user can) |
| T2: untrusted execution | Unknown scripts, `npm install`, third-party repos, generated shell | Routed to a container; no secrets, no network by default |
| T3: infrastructure mutation | `kubectl apply`, `terraform apply`, `docker push`, deploys | Human approval, or denied; preferably done in CI/CD |

## Bypass classes (each must have tests)

1. **Shell wrappers:** `bash -c`, `sh -c`, `env sh`, nested shells. These are opaque and go to the fallback.
2. **Indirect execution:** `xargs`, `find -exec`, `make`, package scripts. These are opaque.
3. **Command substitution:** `$(…)` and backticks inside arguments (only meaningful if a shell is involved; never introduced by afg).
4. **Option smuggling:** `git -c`, `--ext-diff`, `--output`, `--upload-pack`, and similar. Blocked by `denyArgs` and normalization.
5. **Path tricks:** `../` traversal, symlinks into protected paths, case and Unicode confusables. Paths are canonicalized before checking.
6. **PATH hijack:** a repo-local `./cargo` shadows the real binary. The executable is resolved to a canonical absolute path and shown in the decision.
7. **TOCTOU:** a script or binary is changed between the check and the run. Hashes are re-verified before spawning; containers run on a snapshot.
8. **Approval spoofing:** the agent answers its own prompt. Approval is read only from the controlling TTY; with no TTY, the command is denied.
9. **Secret exfiltration through output or audit:** output and audit are redacted, and the environment is cleared down to an allowlist.
10. **Sandbox escape:** Docker socket or `$HOME` mounts, privileged flags, capabilities. These are never used (ADR 0004).
11. **Hardlinks to secrets** (found in the T13.2 review): an innocent-looking path that shares an inode with a protected file. A file with a link count above 1 is checked against the inodes inside the protected paths.
12. **Unlisted secret stores** (T13.2): shell and REPL histories, `~/.vault-token`, `~/.terraform.d`, password stores and keychains are now built-in protected paths.
13. **Policy tampering** (T13.2): the agent edits `agentforge.yaml` (or `.claude/settings.json`) to loosen its own rules. `afg init` and `afg policy trust` pin the policy hash under the protected `~/.config/agentforge`, and a changed policy denies everything. `afg agents sync claude` adds Edit deny rules for afg's own config files.
14. **Self-approval and self-trust:** the agent runs `afg approve` or `afg policy trust`. afg never runs itself, in managed mode or the hook.

## Out of scope (v0.1)

- Kernel or container-runtime escapes. We rely on Docker and keep our configuration minimal.
- Agents that ignore `afg` entirely in integration mode. See [security-boundaries.md](security-boundaries.md).
- Malicious code running in T1 with the user's privileges. Users who want more isolation should route T1 to a container.
