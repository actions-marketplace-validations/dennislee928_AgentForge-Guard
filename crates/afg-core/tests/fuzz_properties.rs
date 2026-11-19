//! Stable, property-based versions of the cargo-fuzz targets in fuzz/
//! (T13.1). They run in the normal test suite; the libFuzzer targets run
//! weekly in CI on nightly.

use afg_core::shell::split_commands;
use afg_core::{Effect, Engine, EvalRequest, Policy};
use proptest::prelude::*;

fn engine() -> Engine {
    let p = Policy::from_yaml(afg_core::builtin::policy_source("default").unwrap()).unwrap();
    Engine::new(
        p,
        &std::env::temp_dir(),
        Some(std::path::Path::new("/nonexistent-home")),
    )
}

fn word() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,8}",
        Just("git".to_owned()),
        Just("kubectl".to_owned()),
        Just("terraform".to_owned()),
        Just("sh".to_owned()),
        Just("env".to_owned()),
        Just("-c".to_owned()),
        Just("delete".to_owned()),
        Just("destroy".to_owned()),
        Just("$(id)".to_owned()),
        Just("`id`".to_owned()),
        Just(";".to_owned()),
        Just("|".to_owned()),
        Just("~/.ssh/id_rsa".to_owned()),
        Just(".env".to_owned()),
        Just("X=1".to_owned()),
        ".{0,12}",
    ]
}

fn quote(a: &str) -> String {
    format!("'{}'", a.replace('\'', r"'\''"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn evaluate_never_panics_and_never_allows_shell_syntax(argv in prop::collection::vec(word(), 0..8)) {
        let e = engine();
        let cwd = std::env::temp_dir();
        let d = e.evaluate(&EvalRequest { argv: &argv, cwd: &cwd, path_env: None, requested_backend: None });
        let suspicious = argv.iter().any(|a| a.contains("$(") || a.contains('`') || [";", "|"].contains(&a.as_str())
            || a.chars().any(|c| c.is_control() && c != '\t'));
        if suspicious {
            prop_assert_ne!(d.effect, Effect::Allow, "{:?}", argv);
        }
        // Destructive targets are never allowed, however they are wrapped.
        if argv.iter().any(|a| a == "terraform") && argv.iter().any(|a| a == "destroy") {
            prop_assert_ne!(d.effect, Effect::Allow, "{:?}", argv);
        }
    }

    #[test]
    fn shell_split_round_trips(s in ".{0,60}") {
        if let Ok(cmds) = split_commands(&s) {
            let again: String = cmds.iter()
                .map(|c| c.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>().join("; ");
            prop_assert_eq!(split_commands(&again).unwrap(), cmds);
        }
    }

    #[test]
    fn hook_path_never_allows_what_argv_path_denies(argv in prop::collection::vec(word(), 1..6)) {
        let e = engine();
        let cwd = std::env::temp_dir();
        let a = e.evaluate(&EvalRequest { argv: &argv, cwd: &cwd, path_env: None, requested_backend: None });
        let quoted = argv.iter().map(|x| quote(x)).collect::<Vec<_>>().join(" ");
        let h = e.evaluate_shell(&quoted, &cwd, None);
        if a.effect != Effect::Allow {
            prop_assert_ne!(h.effect, Effect::Allow, "{:?}", argv);
        }
    }

    #[test]
    fn policy_parser_never_panics(s in ".{0,200}") {
        if let Ok(p) = Policy::from_yaml(&s) {
            let _ = afg_core::validate::validate(&p);
        }
    }
}
