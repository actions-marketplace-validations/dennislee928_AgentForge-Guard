//! Built-in policies shipped with afg (`policies/*.yaml`).

/// Each built-in policy's name and YAML source.
pub const POLICIES: &[(&str, &str)] = &[
    ("default", include_str!("../../../policies/default.yaml")),
    ("strict", include_str!("../../../policies/strict.yaml")),
    ("ci", include_str!("../../../policies/ci.yaml")),
];

/// The YAML source of a built-in policy, by name.
pub fn policy_source(name: &str) -> Option<&'static str> {
    POLICIES.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::{Severity, validate};
    use crate::{Effect, Engine, EvalRequest, Policy};
    use std::path::Path;

    fn engine(name: &str) -> Engine {
        let p = Policy::from_yaml(policy_source(name).unwrap()).unwrap();
        Engine::new(
            p,
            &std::env::temp_dir(),
            Some(Path::new("/nonexistent-home")),
        )
    }

    fn effect(e: &Engine, argv: &[&str]) -> Effect {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let cwd = std::env::temp_dir();
        e.evaluate(&EvalRequest {
            argv: &argv,
            cwd: &cwd,
            path_env: None,
            requested_backend: None,
        })
        .effect
    }

    #[test]
    fn all_builtins_parse_and_validate_without_errors() {
        for (name, src) in POLICIES {
            let p = Policy::from_yaml(src).unwrap_or_else(|e| panic!("{name}: {e}"));
            let errs: Vec<_> = validate(&p)
                .into_iter()
                .filter(|i| i.severity == Severity::Error)
                .collect();
            assert!(errs.is_empty(), "{name}: {errs:?}");
        }
    }

    #[test]
    fn default_policy_tiers() {
        let e = engine("default");
        assert_eq!(effect(&e, &["git", "status"]), Effect::Allow);
        assert_eq!(effect(&e, &["cargo", "test", "--workspace"]), Effect::Allow);
        assert_eq!(effect(&e, &["sh", "./scripts/check.sh"]), Effect::Route);
        assert_eq!(effect(&e, &["pnpm", "install"]), Effect::RequireApproval);
        assert_eq!(
            effect(&e, &["kubectl", "apply", "-f", "x.yaml"]),
            Effect::RequireApproval
        );
        assert_eq!(
            effect(&e, &["git", "push", "origin", "main"]),
            Effect::RequireApproval
        );
        assert_eq!(
            effect(&e, &["git", "push", "origin", "--force"]),
            Effect::Deny
        );
        assert_eq!(effect(&e, &["terraform", "destroy"]), Effect::Deny);
        assert_eq!(effect(&e, &["rg", "--pre", "x", "pat"]), Effect::Deny);
        assert_eq!(effect(&e, &["curl", "https://example.com"]), Effect::Deny);
    }

    #[test]
    fn strict_and_ci_never_require_approval_for_infra() {
        for name in ["strict", "ci"] {
            let e = engine(name);
            assert_eq!(
                effect(&e, &["kubectl", "apply", "-f", "x"]),
                Effect::Deny,
                "{name}"
            );
            assert_eq!(effect(&e, &["npm", "install"]), Effect::Deny, "{name}");
        }
        assert_eq!(effect(&engine("strict"), &["cargo", "test"]), Effect::Route);
        assert_eq!(effect(&engine("ci"), &["cargo", "test"]), Effect::Allow);
    }
}
