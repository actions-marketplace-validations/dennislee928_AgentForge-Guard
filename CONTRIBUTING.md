# Contributing to AgentForge Guard

Thanks for helping. Because afg is security tooling, the bar for changes to
decision and isolation code is high.

## Ground rules

- **The policy engine is the single source of truth.** Authorization decisions live only in `afg-core` (ADR 0002). Executors, the CLI and adapters must not make their own.
- **Use TDD.** Add a failing test first. Every commit must pass the Definition of Done below.
- **Never weaken, delete or `#[ignore]` a test in `tests/adversarial/`, `tests/policy-fixtures/` or the Docker isolation suite to make a change pass.** If a fixture has to change, explain why in the PR.
- **Fail closed.** If you can't classify a command safely, it must end in `deny` or `route`, never `allow`.
- **No implicit shell, no inherited environment.** Never mount the Docker socket or `$HOME`.
- **Use only obviously fake credentials in tests** (`AKIAFAKE…`, `FAKEFAKE…`).
- **Make no claims of safety in docs** that the tests don't back up. Argv matching and prompt instructions are not security boundaries.

## Definition of Done

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo test --workspace -- --ignored     # Docker isolation; required for executor changes
scripts/ci-demos.sh target/debug/afg    # README demos
```

## Workflow

- Work from [docs/plan.md](docs/plan.md). Make one commit per task, using Conventional Commits.
- At the end of each phase, update the plan's Alignment log.
- Record significant design changes as an ADR in `docs/adr/`.
- Regenerate checked-in artifacts when their sources change:
  - `AFG_BLESS=1 cargo test -p afg-core schema` regenerates `agentforge.schema.json`.
  - `afg init --force --dir examples/polyglot-monorepo` regenerates the example policy.

## License

By contributing, you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, as described in the README.
