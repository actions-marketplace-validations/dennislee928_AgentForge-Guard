//! Live toolchain tests: the examples' own tests, run through `afg run`.
//! Each test skips (and says so) when its toolchain is not installed. CI
//! installs Go and Zig, so the tests run there (T10.5).

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn have(tool: &str, arg: &str) -> bool {
    std::process::Command::new(tool)
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

fn example(name: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap().join(name);
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name),
        &root,
    );
    (tmp, root)
}

fn afg_run(cwd: &Path, argv: &[&str]) -> std::process::Output {
    Command::cargo_bin("afg")
        .unwrap()
        .current_dir(cwd)
        .env("AFG_NO_TTY", "1")
        .arg("run")
        .arg("--")
        .args(argv)
        .output()
        .unwrap()
}

#[test]
fn go_example_tests_pass_under_afg() {
    if !have("go", "version") {
        eprintln!("skipping: go is not installed");
        return;
    }
    let (_t, root) = example("polyglot-monorepo");
    let out = afg_run(&root.join("services/go-api"), &["go", "test", "./..."]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rust_example_tests_pass_under_afg() {
    let (_t, root) = example("polyglot-monorepo");
    let out = afg_run(&root.join("services/rust-service"), &["cargo", "test"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn zig_example_tests_pass_under_afg() {
    if !have("zig", "version") {
        eprintln!("skipping: zig is not installed");
        return;
    }
    let (_t, root) = example("zig-project");
    let out = afg_run(&root, &["zig", "build", "test"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Fetching dependencies is T2 and must not run locally without approval.
    assert_eq!(
        afg_run(&root, &["zig", "build", "--fetch"]).status.code(),
        Some(126)
    );
}
