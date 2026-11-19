# Sandbox isolation tests

The container backend's isolation guarantees, tested against a real Docker
daemon. They live in `crates/afg-executor/tests/sandbox_isolation.rs` and are
`#[ignore]`d by default:

```sh
cargo test -p afg-executor --test sandbox_isolation -- --ignored
```

CI runs them on the Linux reference runner. Every credential they use is fake.
Never weaken, delete or skip these tests to make a change pass.
