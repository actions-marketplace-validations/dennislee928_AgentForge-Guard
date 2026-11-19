# ADR 0001: Rust for the core and CLI

- Status: Accepted
- Date: 2026-11-19

## Context

The tool must ship as a single, cross-platform binary with no runtime dependency, and its policy engine is security-critical code that benefits from strong typing and exhaustive matching.

## Decision

The policy engine, executors, detection, reporting and CLI are written in Rust as a Cargo workspace (`afg-core`, `afg-detect`, `afg-executor`, `afg-report`, `afg-cli`). TypeScript is used only where an external platform requires it (the Cloudflare adapter, from v0.4).

## Consequences

Users install one binary. Contributors need a Rust toolchain; TypeScript tooling is optional and confined to `packages/`.
