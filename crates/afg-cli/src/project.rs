//! Finding the project and loading its policy.

use std::path::{Path, PathBuf};

use afg_core::validate::{Severity, validate};
use afg_core::{Engine, Policy};
use anyhow::{Context, bail};

use crate::POLICY_FILE;

pub struct Project {
    pub root: PathBuf,
    pub policy_path: PathBuf,
    pub engine: Engine,
    pub warnings: Vec<String>,
    pub trust: crate::trust::Status,
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::home_dir().and_then(|h| h.canonicalize().ok())
}

/// Walk up from `start` to the nearest directory that holds agentforge.yaml.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| d.join(POLICY_FILE).is_file())
        .map(Path::to_path_buf)
}

/// Load and validate the project policy. Validation errors are fatal.
pub fn load(cwd: &Path) -> anyhow::Result<Project> {
    let cwd = cwd
        .canonicalize()
        .context("resolving the working directory")?;
    let Some(root) = find_root(&cwd) else {
        bail!(
            "no {POLICY_FILE} found in {} or any parent; run `afg init`",
            cwd.display()
        );
    };
    let policy_path = root.join(POLICY_FILE);
    let src = std::fs::read_to_string(&policy_path)
        .with_context(|| format!("reading {}", policy_path.display()))?;
    let policy =
        Policy::from_yaml(&src).with_context(|| format!("parsing {}", policy_path.display()))?;
    let issues = validate(&policy);
    let errors: Vec<String> = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| i.to_string())
        .collect();
    if !errors.is_empty() {
        bail!(
            "invalid policy {}:\n  {}",
            policy_path.display(),
            errors.join("\n  ")
        );
    }
    let warnings = issues
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .map(|i| i.to_string())
        .collect();
    let project_root = root.join(&policy.project.root);
    let project_root = project_root.canonicalize().unwrap_or(root.clone());
    let home = home_dir();
    let engine = Engine::new(policy, &project_root, home.as_deref());
    let trust = crate::trust::status(home.as_deref(), &policy_path, engine.policy_hash());
    Ok(Project {
        root: project_root,
        policy_path,
        engine,
        warnings,
        trust,
    })
}

impl Project {
    /// The reason every decision must be denied, if the pinned policy changed.
    pub fn untrusted_reason(&self) -> Option<String> {
        match &self.trust {
            crate::trust::Status::Changed { pinned } => Some(format!(
                "{} changed since it was trusted ({pinned}); a human must review it and run `afg policy trust`",
                self.policy_path.display()
            )),
            _ => None,
        }
    }

    /// Print a warning when the policy has never been pinned.
    pub fn warn_if_unpinned(&self) {
        if self.trust == crate::trust::Status::Unpinned {
            eprintln!(
                "afg: warning: policy is not pinned; run `afg policy trust` so that edits to it are detected"
            );
        }
    }
}
