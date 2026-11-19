//! Policy-evaluation benchmark (T12.1). Run with: cargo bench -p afg-core
//! It uses std timing (no harness dependency) and reports the median of
//! several rounds, in nanoseconds per evaluation.

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use afg_core::{Engine, EvalRequest, Policy};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..iters / 10 {
        f();
    }
    let rounds: Vec<f64> = (0..9)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        })
        .collect();
    println!("{name:<48} {:>10.0} ns/op", median(rounds));
}

fn main() {
    let policy = Policy::from_yaml(afg_core::builtin::policy_source("default").unwrap()).unwrap();
    let cwd = std::env::temp_dir();
    let engine = Engine::new(policy, &cwd, Some(Path::new("/nonexistent-home")));
    let path = std::env::var_os("PATH");
    let cases: &[(&str, &[&str])] = &[
        (
            "allow: cargo test --workspace",
            &["cargo", "test", "--workspace"],
        ),
        (
            "deny: kubectl -n prod delete pod x",
            &["kubectl", "-n", "prod", "delete", "pod", "x"],
        ),
        ("opaque: bash -c ...", &["bash", "-c", "terraform destroy"]),
        (
            "fallback: curl https://example.com",
            &["curl", "https://example.com"],
        ),
        (
            "protected: cat ~/.ssh/id_ed25519",
            &["cat", "~/.ssh/id_ed25519"],
        ),
    ];
    for (name, argv) in cases {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        bench(&format!("evaluate (no PATH lookup) {name}"), 20_000, || {
            black_box(engine.evaluate(&EvalRequest {
                argv: &argv,
                cwd: &cwd,
                path_env: None,
                requested_backend: None,
            }));
        });
        bench(&format!("evaluate (PATH lookup) {name}"), 5_000, || {
            black_box(engine.evaluate(&EvalRequest {
                argv: &argv,
                cwd: &cwd,
                path_env: path.as_deref(),
                requested_backend: None,
            }));
        });
    }
    bench(
        "evaluate_shell: cd web && pnpm lint; git status",
        10_000,
        || {
            black_box(engine.evaluate_shell("cd web && pnpm lint; git status", &cwd, None));
        },
    );
    bench("policy parse + validate (default.yaml)", 2_000, || {
        let p = Policy::from_yaml(black_box(
            afg_core::builtin::policy_source("default").unwrap(),
        ))
        .unwrap();
        black_box(afg_core::validate::validate(&p));
    });
}
