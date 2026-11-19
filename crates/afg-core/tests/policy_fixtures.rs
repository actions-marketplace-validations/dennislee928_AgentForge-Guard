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
