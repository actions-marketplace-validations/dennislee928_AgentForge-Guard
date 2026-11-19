//! End-to-end CLI tests: init → doctor → run → audit, on a temporary copy
//! of the polyglot fixture. `AFG_NO_TTY` is always set, so approval prompts
//! can never block a test run.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

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

struct Repo {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Repo {
    fn polyglot() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("polyglot");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/language-detection/polyglot");
        copy_tree(&fixture, &root);
        Self { _tmp: tmp, root }
    }

    fn initialized() -> Self {
        let r = Self::polyglot();
        r.afg().arg("init").assert().success();
        r
    }

    fn afg(&self) -> Command {
        let mut c = Command::cargo_bin("afg").unwrap();
        c.current_dir(&self.root).env("AFG_NO_TTY", "1");
        c
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        let out = self
            .afg()
            .args(["audit", "tail", "--json", "-n", "1000"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn last_audit(&self) -> serde_json::Value {
        self.audit().pop().expect("an audit record")
    }
}

#[test]
fn init_writes_policy_and_refuses_to_overwrite() {
    let r = Repo::polyglot();
    r.afg()
        .arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote"));
    let yaml = std::fs::read_to_string(r.root.join("agentforge.yaml")).unwrap();
    assert!(yaml.contains("name: \"polyglot\""));
    r.afg()
        .arg("init")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--force"));
    r.afg()
        .args(["init", "--force", "--template", "strict"])
        .assert()
        .success();
    assert!(
        std::fs::read_to_string(r.root.join("agentforge.yaml"))
            .unwrap()
            .contains("strict policy")
    );
}

#[test]
fn commands_without_a_policy_fail_with_guidance() {
    let r = Repo::polyglot();
    r.afg()
        .args(["run", "--", "ls"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("afg init"));
}

#[test]
fn doctor_reports_projects_and_decisions() {
    let r = Repo::initialized();
    let out = r.afg().args(["doctor", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<&str> = v["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["go", "rust", "node"]);
    let cmds = v["commands"].as_array().unwrap();
    assert!(
        cmds.iter()
            .all(|c| c["tier"] != "T2" || c["effect"] == "require-approval")
    );
    assert!(
        cmds.iter()
            .filter(|c| c["tier"] == "T1")
            .all(|c| c["effect"] == "allow")
    );
}

#[test]
fn explain_does_not_execute_or_audit() {
    let r = Repo::initialized();
    let out = r
        .afg()
        .args(["policy", "explain", "--json", "--", "terraform", "destroy"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["effect"], "deny");
    assert_eq!(v["ruleId"], "destructive-operations");
    assert!(r.audit().is_empty());
}

#[test]
fn allowed_command_runs_locally_and_is_audited() {
    let r = Repo::initialized();
    r.afg()
        .args(["run", "--", "ls", "services"])
        .assert()
        .success()
        .stdout(predicate::str::contains("api"));
    let a = r.last_audit();
    assert_eq!(a["decision"]["effect"], "allow");
    assert_eq!(a["decision"]["backend"], "local");
    assert_eq!(a["execution"]["exitCode"], 0);
    assert!(a["policy"]["hash"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn exit_codes_pass_through() {
    let r = Repo::initialized();
    let out = r
        .afg()
        .args(["run", "--", "ls", "/definitely/not/here"])
        .output()
        .unwrap();
    let code = out.status.code().unwrap();
    assert!(code != 0 && code != 126, "got {code}");
}

#[test]
fn terraform_destroy_is_denied_with_audit_evidence() {
    let r = Repo::initialized();
    r.afg()
        .args(["run", "--", "terraform", "destroy", "-auto-approve"])
        .assert()
        .code(126)
        .stderr(predicate::str::contains("destructive-operations"));
    let a = r.last_audit();
    assert_eq!(a["decision"]["effect"], "deny");
    assert_eq!(a["decision"]["ruleId"], "destructive-operations");
    assert!(a.get("execution").is_none());
}

#[test]
fn unknown_and_disguised_commands_fail_closed() {
    let r = Repo::initialized();
    for argv in [
        &["curl", "https://example.com"][..],
        &["env", "GIT_EXTERNAL_DIFF=/tmp/x", "git", "diff"],
        &["sudo", "ls"],
        &["cat", ".env"],
        &["git", "-c", "core.pager=sh", "log"],
    ] {
        let mut c = r.afg();
        c.arg("run").arg("--").args(argv);
        c.assert().code(126);
    }
    assert_eq!(r.audit().len(), 5);
}

#[test]
fn approval_without_a_terminal_is_refused() {
    let r = Repo::initialized();
    r.afg()
        .args(["run", "--", "kubectl", "apply", "-f", "x.yaml"])
        .write_stdin("yes\n")
        .assert()
        .code(126)
        .stderr(predicate::str::contains("not approved"));
    let a = r.last_audit();
    assert_eq!(a["decision"]["effect"], "require-approval");
    assert_eq!(a["approval"]["approved"], false);
    assert!(a.get("execution").is_none());
}

#[test]
fn secrets_in_argv_are_redacted_in_the_audit_log() {
    let r = Repo::initialized();
    let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
    r.afg()
        .args([
            "run",
            "--",
            "curl",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "x",
        ])
        .assert()
        .code(126);
    r.afg()
        .args(["run", "--", "cat", "--password", "hunter2hunter2"])
        .assert()
        .failure();
    let raw: String = std::fs::read_dir(r.root.join(".agentforge/audit"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!raw.contains(token));
    assert!(!raw.contains("hunter2hunter2"));
    assert!(raw.contains("[REDACTED"));
}

#[test]
fn isolation_flag_cannot_weaken_policy() {
    let r = Repo::initialized();
    let out = r
        .afg()
        .args([
            "policy",
            "explain",
            "--json",
            "--isolation",
            "local",
            "--",
            "sh",
            "x.sh",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["backend"], "container");
}

#[test]
#[ignore = "requires Docker"]
fn untrusted_script_runs_in_container_without_host_secrets_or_network() {
    let r = Repo::initialized();
    std::fs::write(r.root.join(".env"), "AWS_SECRET_ACCESS_KEY=FAKEFAKEFAKE\n").unwrap();
    std::fs::create_dir_all(r.root.join("scripts")).unwrap();
    std::fs::write(
        r.root.join("scripts/untrusted.sh"),
        "set -u\n\
         if cat /workspace/.env 2>/dev/null; then echo LEAK-ENV; fi\n\
         if [ -e \"$HOME/.ssh\" ] || [ -e /root/.ssh ]; then echo LEAK-SSH; fi\n\
         if [ -S /var/run/docker.sock ]; then echo LEAK-DOCKER; fi\n\
         if bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo LEAK-NET; fi\n\
         echo done\n",
    )
    .unwrap();
    let out = r
        .afg()
        .args(["run", "--", "sh", "scripts/untrusted.sh"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("done"));
    assert!(!stdout.contains("LEAK"), "{stdout}");
    let a = r.last_audit();
    assert_eq!(a["decision"]["backend"], "container");
    assert!(
        a["execution"]["details"]
            .to_string()
            .contains("snapshotManifest")
    );
}
