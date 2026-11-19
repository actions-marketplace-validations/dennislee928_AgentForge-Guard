//! Runs every case in `tests/policy-fixtures/` and `tests/adversarial/`
//! against the policy engine.

use std::path::{Path, PathBuf};

use afg_core::conformance::FixtureFile;
use afg_core::{Engine, EvalRequest, Policy};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Run every fixture file in `dir`, and return the number of cases.
pub fn run_dir(dir: &str) -> usize {
    let dir = repo_root().join(dir);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no fixtures in {}", dir.display());

    // A scratch workspace, plus a fake home that holds a fake key.
    let scratch = std::env::temp_dir().join(format!("afg-fixtures-{}", std::process::id()));
    let home = scratch.join("home");
    let cwd = scratch.join("repo");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(home.join(".ssh/id_ed25519"), "FAKE").unwrap();
    #[cfg(unix)]
    {
        let link = cwd.join("innocent.txt");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(home.join(".ssh/id_ed25519"), &link).unwrap();
    }
    let home_s = home.display().to_string();

    let mut failures = Vec::new();
    let mut count = 0;
    for f in &files {
        let fx = FixtureFile::from_yaml(&std::fs::read_to_string(f).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let policy = Policy::from_yaml(&fx.policy_source().expect("known policy")).unwrap();
        let engine = Engine::new(policy, &cwd, Some(&home));
        for (i, case) in fx.cases.iter().enumerate() {
            count += 1;
            let argv: Vec<String> = case
                .argv
                .iter()
                .map(|a| a.replace("$HOME", &home_s))
                .collect();
            let d = engine.evaluate(&EvalRequest {
                argv: &argv,
                cwd: &cwd,
                path_env: None,
                requested_backend: case.requested,
            });
            if let Err(e) = case.check(d.effect, d.backend, &d.rule_id) {
                failures.push(format!(
                    "{}#{i} {:?}{}: {e}\n    reasons: {:?}",
                    f.file_name().unwrap().to_string_lossy(),
                    case.argv,
                    case.note
                        .as_deref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default(),
                    d.reasons
                ));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        failures.is_empty(),
        "{} failing cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
    count
}

#[test]
fn policy_fixtures() {
    assert!(run_dir("tests/policy-fixtures") >= 40);
}

#[test]
fn adversarial_cases_never_allow() {
    // Meta-check: an adversarial case may only expect deny or route.
    let dir = repo_root().join("tests/adversarial");
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let fx = FixtureFile::from_yaml(&std::fs::read_to_string(&p).unwrap()).unwrap();
        for c in &fx.cases {
            assert!(
                matches!(c.expect, afg_core::Effect::Deny | afg_core::Effect::Route),
                "{}: adversarial case {:?} must expect deny or route",
                p.display(),
                c.argv
            );
        }
    }
    assert!(run_dir("tests/adversarial") >= 60);
}

/// Quote an argv for a POSIX shell, so the hook path sees exactly this argv.
fn shell_quote(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// How the Claude Code hook surfaces an effect: route becomes deny, because
/// native Bash cannot route. Higher is stricter.
fn hook_rank(e: afg_core::Effect) -> u8 {
    use afg_core::Effect::*;
    match e {
        Allow => 0,
        RequireApproval => 1,
        Route | Deny => 2,
    }
}

/// Conformance (ADR 0002, T9.3): for every fixture case, the decision that
/// the hook path (`Engine::evaluate_shell` on the quoted command string)
/// makes equals the `afg run` / `policy explain` decision whenever the
/// string tokenizes. When it doesn't, the hook path must never be weaker.
#[test]
fn hook_path_conforms_to_explain_on_every_fixture() {
    let root = repo_root();
    let scratch = std::env::temp_dir().join(format!("afg-conf-{}", std::process::id()));
    let home = scratch.join("home");
    let cwd = scratch.join("repo");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(home.join(".ssh/id_ed25519"), "FAKE").unwrap();
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(cwd.join("innocent.txt"));
        std::os::unix::fs::symlink(home.join(".ssh/id_ed25519"), cwd.join("innocent.txt")).unwrap();
    }
    let home_s = home.display().to_string();
    let (mut exact, mut stricter, mut checked) = (0, 0, 0);
    let mut failures = Vec::new();
    for dir in ["tests/policy-fixtures", "tests/adversarial"] {
        let mut files: Vec<_> = std::fs::read_dir(root.join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for f in files {
            let fx = FixtureFile::from_yaml(&std::fs::read_to_string(&f).unwrap()).unwrap();
            let engine = Engine::new(
                Policy::from_yaml(&fx.policy_source().unwrap()).unwrap(),
                &cwd,
                Some(&home),
            );
            for case in fx.cases.iter().filter(|c| c.requested.is_none()) {
                let argv: Vec<String> = case
                    .argv
                    .iter()
                    .map(|a| a.replace("$HOME", &home_s))
                    .collect();
                let explain = engine.evaluate(&EvalRequest {
                    argv: &argv,
                    cwd: &cwd,
                    path_env: None,
                    requested_backend: None,
                });
                let hook = engine.evaluate_shell(&shell_quote(&argv), &cwd, None);
                checked += 1;
                let same = hook.unparseable.is_none()
                    && hook.parts.len() == 1
                    && hook.effect == explain.effect
                    && hook.parts[0].backend == explain.backend
                    && hook.parts[0].rule_id == explain.rule_id;
                if same {
                    exact += 1;
                } else if hook.unparseable.is_some()
                    && hook_rank(hook.effect) >= hook_rank(explain.effect)
                {
                    stricter += 1;
                } else {
                    failures.push(format!(
                        "{}: {:?}: explain={} ({}) hook={} {:?}",
                        f.file_name().unwrap().to_string_lossy(),
                        case.argv,
                        explain.effect,
                        explain.rule_id,
                        hook.effect,
                        hook.unparseable
                    ));
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        failures.is_empty(),
        "{} non-conforming cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked > 100 && exact > 100,
        "checked {checked}, exact {exact}, stricter {stricter}"
    );
}
