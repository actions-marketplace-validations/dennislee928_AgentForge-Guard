# Example: Zig project

Targets the Zig 0.14/0.15 build API. CI runs it with Zig 0.15.1.

```sh
cd examples/zig-project
afg doctor
afg run -- zig build test     # allowed (T1), runs locally
afg run -- zig build --fetch  # T2: needs approval
```
