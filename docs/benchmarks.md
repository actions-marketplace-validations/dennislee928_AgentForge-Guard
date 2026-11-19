# Benchmarks (T12.1)

Reproduce with `cargo bench -p afg-core` and `cargo bench -p afg-executor`.
These are plain std-timing harnesses (no benchmark framework dependency) that
report medians.

**Machine:** Apple M3, macOS (Darwin 24.6), Rust 1.99, release profile. **Date:** 2026-11-19.

## Policy evaluation (`afg-core`)

| Case | No PATH lookup | With PATH lookup |
|---|---:|---:|
| allow: `cargo test --workspace` | 77 µs | 117 µs |
| deny: `kubectl -n prod delete pod x` | 132 µs | 140 µs |
| opaque: `bash -c …` | 77 µs | 89 µs |
| fallback: `curl https://example.com` | 91 µs | 106 µs |
| protected: `cat ~/.ssh/id_ed25519` | 41 µs | 54 µs |
| `evaluate_shell("cd web && pnpm lint; git status")` | 135 µs | n/a |
| parse + validate `policies/default.yaml` | 143 µs | n/a |

Most of the time goes to the protected-path check, which deliberately hits the
filesystem (`canonicalize`, `symlink_metadata`) for every argument so that
symlinks are resolved. Rule matching itself is a small share.

## Execution overhead (`afg-executor`)

| Measurement | Median |
|---|---:|
| spawn `/usr/bin/true` directly | 801 µs |
| spawn through `LocalExecutor` (cleared env, pin re-verification, capture, process-group kill) | 861 µs |
| **LocalExecutor overhead** | **61 µs** |
| snapshot build (container and Cloudflare backends), `crates/` (57 files) | 10.4 ms |

## Conclusion

afg's per-command cost is roughly 0.1–0.2 ms of policy evaluation plus about
0.06 ms of executor overhead. That is under a quarter of the cost of spawning
the cheapest possible process, and orders of magnitude below a container start
(hundreds of milliseconds) or any real build or test. Neither a native helper
nor a GPU or vector compute plugin would buy a measurable improvement; see
[ADR 0007](adr/0007-no-native-helper-or-mojo-plugin.md).
