# ADR 0002: A single policy engine

- Status: Accepted
- Date: 2026-11-19

## Context

If the CLI, agent hooks and remote adapters each evaluated policy separately, the same command could be allowed in one entry point and denied in another.

## Decision

`afg-core` is the only component that makes authorization decisions. Hooks, executors and remote adapters receive a `Decision` and must never re-derive one. All entry points are tested against the shared fixtures in `tests/policy-fixtures/` (conformance tests).

## Consequences

Remote adapters (e.g. the Cloudflare Worker) accept only requests that the CLI has already approved and signed. Adding an entry point means adding it to the conformance suite.
