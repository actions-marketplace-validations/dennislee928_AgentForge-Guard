//! Risky files in the workspace.
//!
//! The scan reports files only. It does not read their contents.

use std::path::{Path, PathBuf};

use afg_core::paths::{DEFAULT_GLOBS, glob_match};
use serde::Serialize;

use crate::{MAX_DEPTH, SKIP_DIRS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Info,
    Low,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Risk {
    pub level: RiskLevel,
    pub kind: &'static str,
    pub path: PathBuf,
    pub message: String,
}

/// Example files that are protected but usually hold no real secrets.
const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist"];

const CI_FILES: &[&str] = &[
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/config.yml",
    "azure-pipelines.yml",
];

pub fn detect_risks(root: &Path) -> Vec<Risk> {
    let mut out = Vec::new();
    let gitignore = std::fs::read_to_string(root.join(".gitignore")).ok();
    if gitignore.is_none() {
        out.push(Risk {
            level: RiskLevel::Low,
            kind: "no-gitignore",
            path: PathBuf::from(".gitignore"),
            message: "no .gitignore; generated files and secrets are easy to commit".into(),
        });
    }
    let ignores_env = gitignore.as_deref().is_some_and(|g| {
        g.lines()
            .any(|l| matches!(l.trim(), ".env" | ".env*" | ".env.*" | "/.env" | "*.env"))
    });

    scan(root, Path::new(""), 0, &mut |rel, name| {
        let lower = name.to_ascii_lowercase();
        if DEFAULT_GLOBS.iter().any(|g| glob_match(g, name)) {
            let template = TEMPLATE_SUFFIXES.iter().any(|s| lower.ends_with(s));
            let (kind, level) = if lower.ends_with(".tfstate") || lower.ends_with(".tfstate.backup")
            {
                ("terraform-state", RiskLevel::High)
            } else if lower.contains("kubeconfig") {
                ("kubeconfig", RiskLevel::High)
            } else if template {
                ("secret-template", RiskLevel::Info)
            } else {
                ("secret-file", RiskLevel::High)
            };
            let mut message = format!(
                "`{}` looks like a credential file. afg denies commands that name it, but an agent's own file tools can still read it",
                rel.display()
            );
            if kind == "secret-file" && lower.starts_with(".env") && !ignores_env {
                message.push_str("; .gitignore does not exclude .env files");
            }
            out.push(Risk {
                level,
                kind,
                path: rel.to_path_buf(),
                message,
            });
        }
    });

    for f in CI_FILES {
        if root.join(f).is_file() {
            out.push(ci_risk(PathBuf::from(f)));
        }
    }
    if let Ok(entries) = std::fs::read_dir(root.join(".github/workflows")) {
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
            .collect();
        files.sort();
        out.extend(
            files
                .into_iter()
                .map(|n| ci_risk(Path::new(".github/workflows").join(n))),
        );
    }
    out.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.path.cmp(&b.path)));
    out
}

fn ci_risk(path: PathBuf) -> Risk {
    Risk {
        level: RiskLevel::Info,
        kind: "ci-config",
        message: format!(
            "`{}` defines CI scripts; run them locally only in a container (T2), and remember that a sandbox cannot reproduce CI-only features such as OIDC",
            path.display()
        ),
        path,
    }
}

fn scan(dir: &Path, rel: &Path, depth: usize, f: &mut dyn FnMut(&Path, &str)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(ft) = e.file_type() else { continue };
        let child = rel.join(&name);
        if ft.is_dir() {
            if depth < MAX_DEPTH && !SKIP_DIRS.contains(&name.as_str()) {
                scan(&e.path(), &child, depth + 1, f);
            }
        } else {
            f(&child, &name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;

    fn kinds(t: &Tree) -> Vec<(String, &'static str, RiskLevel)> {
        detect_risks(t.path())
            .into_iter()
            .map(|r| (r.path.display().to_string(), r.kind, r.level))
            .collect()
    }

    #[test]
    fn finds_secrets_state_kubeconfig_and_ci() {
        let t = Tree::new("risks");
        t.file(".gitignore", "target\n")
            .file(".env", "FAKE=1")
            .file(".env.example", "FAKE=")
            .file("infra/terraform.tfstate", "{}")
            .file("deploy/kubeconfig", "")
            .file("certs/server.pem", "")
            .file("node_modules/x/.env", "")
            .file(".github/workflows/ci.yml", "")
            .file("src/main.rs", "");
        let k = kinds(&t);
        assert!(k.contains(&(".env".into(), "secret-file", RiskLevel::High)));
        assert!(k.contains(&(".env.example".into(), "secret-template", RiskLevel::Info)));
        assert!(k.contains(&(
            "infra/terraform.tfstate".into(),
            "terraform-state",
            RiskLevel::High
        )));
        assert!(k.contains(&("deploy/kubeconfig".into(), "kubeconfig", RiskLevel::High)));
        assert!(k.contains(&("certs/server.pem".into(), "secret-file", RiskLevel::High)));
        assert!(k.contains(&(
            ".github/workflows/ci.yml".into(),
            "ci-config",
            RiskLevel::Info
        )));
        assert!(!k.iter().any(|(p, ..)| p.starts_with("node_modules")));
        assert_eq!(k[0].2, RiskLevel::High, "sorted by severity");

        let env = detect_risks(t.path())
            .into_iter()
            .find(|r| r.path == Path::new(".env"))
            .unwrap();
        assert!(env.message.contains("does not exclude"));
    }

    #[test]
    fn missing_gitignore() {
        let t = Tree::new("risks-nogi");
        assert!(kinds(&t).iter().any(|(_, k, _)| *k == "no-gitignore"));
    }

    #[test]
    fn ignored_env_has_no_gitignore_warning() {
        let t = Tree::new("risks-gi");
        t.file(".gitignore", ".env*\n").file(".env", "");
        let env = detect_risks(t.path())
            .into_iter()
            .find(|r| r.path == Path::new(".env"))
            .unwrap();
        assert!(!env.message.contains("does not exclude"));
    }
}
