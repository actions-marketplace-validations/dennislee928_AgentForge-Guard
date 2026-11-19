# CLAUDE.md

Instructions for Claude Code in this repository. Keep in sync with `AGENTS.md`; both share the same body.

## Project

AgentForge Guard (`afg`) is a policy-driven code-execution tool for AI coding agents. Plan: `docs/plan.md`. Decisions: `docs/adr/`. Threat model: `docs/threat-model.md`.

## Rules

- Work task by task from `docs/plan.md`. Commit once per finished task (Conventional Commits), and tick its checkbox in the same commit.
- At the end of each phase, re-read `docs/plan.md`, record any deviations in its Alignment log, and commit `docs(plan): align after phase N`.
- Use TDD: write the failing test first. The workspace must build and pass all tests after every commit.
- `afg-core` is the only crate that makes authorization decisions (ADR 0002). Never add policy logic anywhere else.
- **Never weaken, delete or `#[ignore]` a deny, adversarial or isolation test to make a change pass.** Fix the code instead.
- Never use an implicit shell (`sh -c`) in executors. Never inherit the full host environment. Never mount the Docker socket or `$HOME`.
- Never commit real secrets. Test credentials must be obviously fake (e.g. `AKIAFAKEFAKEFAKEFAKE`).
- Docs must not claim that argv matching or prompt instructions are security boundaries.

## Definition of Done (every commit)

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Docker isolation tests: `cargo test --workspace -- --ignored` (requires Docker).
