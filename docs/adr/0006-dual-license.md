# ADR 0006: Dual license MIT OR Apache-2.0

- Status: Accepted
- Date: 2026-11-19

## Context

The repo began as MIT, and the reference recommended Apache-2.0 for its patent grant.

## Decision

The project is dual-licensed MIT OR Apache-2.0, which is the Rust-ecosystem convention (`LICENSE-MIT`, `LICENSE-APACHE`, `license = "MIT OR Apache-2.0"` in Cargo).

## Consequences

Contributions are accepted under both licenses. Dependencies must be compatible with both (enforced by cargo-deny).
