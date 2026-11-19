# ADR 0003: Fail-closed command normalization

- Status: Accepted
- Date: 2026-11-19

## Context

Prefix-matching argv cannot see through `bash -c`, `env sh`, `xargs`, `make`, command substitution or global options such as `git -c`. Claiming to understand those would be false assurance.

## Decision

Before matching, argv is normalized: the executable is resolved to a canonical absolute path, known wrappers are unwrapped (`sudo` is denied), and shell interpreters and indirect executors are marked *opaque*. Opaque or unmatched commands fall to `execution.fallback`, which defaults to `deny` (a policy may set it to route to a container). Rules can constrain arguments (`denyArgs`, `allowFlags`). Precedence: deny > require-approval > route > allow.

## Consequences

Some legitimate commands are denied until users write explicit rules. The docs must never claim that argv matching proves a command is safe.
