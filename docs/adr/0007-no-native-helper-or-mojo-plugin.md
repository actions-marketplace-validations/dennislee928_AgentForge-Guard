# ADR 0007: No Zig native helper or Mojo compute plugin (for now)

- Status: Accepted
- Date: 2026-11-19

## Context

The reference proposed an optional Zig native helper (process telemetry, C
ABI, cross-compiled tools) and an experimental Mojo plugin (vectorized log
and telemetry analysis). The plan (T12.2 and T12.3) made both conditional on
evidence from the benchmark harness (T12.1) or on a concrete platform need.

## Evidence

From [docs/benchmarks.md](../benchmarks.md) (Apple M3):

- Policy evaluation takes 40–140 µs per command. The cost is dominated by
  deliberate filesystem calls (symlink resolution), not computation.
- LocalExecutor overhead is 61 µs on top of an 801 µs process spawn.
- A snapshot takes about 10 ms for a small tree. Container and Cloudflare runs
  are dominated by container start-up and the user's own build or test time.
- Audit logs are JSONL, append-only, and read only by `afg audit`. There is no
  analysis workload large enough to benefit from GPU or SIMD compute.

No platform feature is missing either. Process-group control and file locking
are covered by `rustix` and `std`, and cross-platform binaries come from the
Rust release workflow (T13.4).

## Decision

- **Skip T12.2.** There will be no Zig native helper. A second native language
  would add toolchain and CI cost with no measurable benefit. Zig projects
  remain fully supported as a *target* language (the v0.3 profile and
  `examples/zig-project`).
- **Skip T12.3.** There will be no Mojo compute plugin. Mojo projects remain
  supported for detection and build (the v0.3 profile).

## Revisit when

- profiling shows afg's own overhead is a significant share of real agent
  sessions (more than 5% of wall time);
- a platform capability is needed that Rust can't reasonably provide, such as
  kernel-level telemetry; or
- audit analytics grows into a large-scale workload (millions of records,
  similarity search, and so on).

Any such helper must stay a separate optional binary that makes **no policy
decisions** (ADR 0002) and runs only through an authorized executor.
