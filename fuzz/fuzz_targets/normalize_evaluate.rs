#![no_main]
//! Arbitrary argv → evaluate never panics, and argv with shell syntax or
//! control characters is never allowed.
use std::sync::OnceLock;

use afg_core::{Effect, Engine, EvalRequest, Policy};
use libfuzzer_sys::fuzz_target;

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| {
        let p = Policy::from_yaml(afg_core::builtin::policy_source("default").unwrap()).unwrap();
        Engine::new(p, &std::env::temp_dir(), Some(std::path::Path::new("/nonexistent-home")))
    })
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let argv: Vec<String> = s.split('\u{1f}').map(str::to_owned).collect();
    let cwd = std::env::temp_dir();
    let d = engine().evaluate(&EvalRequest { argv: &argv, cwd: &cwd, path_env: None, requested_backend: None });
    let suspicious = argv.iter().any(|a| {
        a.contains("$(") || a.contains('`') || a.chars().any(|c| c.is_control() && c != '\t')
    });
    if suspicious {
        assert_ne!(d.effect, Effect::Allow, "{argv:?}");
    }
});
