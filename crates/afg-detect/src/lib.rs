//! Technology stack, agent and risk detection.
//!
//! Detection only reads files. It never runs a toolchain, a package manager
//! or a project script.

use std::path::{Path, PathBuf};

use serde::Serialize;

pub mod go;

/// Trust tier of a suggested command (docs/threat-model.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    /// Read-only.
    T0,
    /// Local workspace mutation and validation.
    T1,
    /// Untrusted execution (installs, scripts); runs in a container.
    T2,
    /// Infrastructure mutation.
    T3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StackKind {
    Go,
    Rust,
    Node,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuggestedCommand {
    pub argv: Vec<String>,
    pub tier: Tier,
    pub purpose: String,
}

impl SuggestedCommand {
    pub fn new(argv: &[&str], tier: Tier, purpose: &str) -> Self {
        Self {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            tier,
            purpose: purpose.into(),
        }
    }
}

/// A detected project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Project {
    pub kind: StackKind,
    /// The directory, relative to the scan root (`.` for the root itself).
    pub dir: PathBuf,
    /// The files that identified the project.
    pub markers: Vec<String>,
    /// Extra facts, for example `typescript`, `nextjs`, `workspace`, `pnpm`.
    pub traits: Vec<String>,
    pub commands: Vec<SuggestedCommand>,
}

/// Detects one kind of project in one directory.
pub trait Detector {
    fn kind(&self) -> StackKind;
    /// Inspect `dir`, which is at `rel` relative to the scan root.
    fn detect(&self, dir: &Path, rel: &Path) -> Option<Project>;
    /// Whether a project found at `dir` covers its subdirectories too, as a
    /// Cargo workspace covers its member crates. Nested matches under such a
    /// project are dropped.
    fn covers_children(&self, _project: &Project) -> bool {
        false
    }
}

/// Directories that are never scanned.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".next",
    ".agentforge",
    ".venv",
    "venv",
    "__pycache__",
    ".turbo",
    ".cache",
    "zig-cache",
    ".zig-cache",
    "zig-out",
];

/// The maximum directory depth that is scanned.
pub const MAX_DEPTH: usize = 6;

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![Box::new(go::GoDetector)]
}

/// Walk `root` and run every detector in every directory.
pub fn detect_projects(root: &Path, detectors: &[Box<dyn Detector>]) -> Vec<Project> {
    let mut out: Vec<Project> = Vec::new();
    let mut covered: Vec<(StackKind, PathBuf)> = Vec::new();
    walk(root, Path::new("."), 0, &mut |dir, rel| {
        for d in detectors {
            if covered
                .iter()
                .any(|(k, p)| *k == d.kind() && is_strictly_under(rel, p))
            {
                continue;
            }
            if let Some(p) = d.detect(dir, rel) {
                if d.covers_children(&p) {
                    covered.push((p.kind, p.dir.clone()));
                }
                out.push(p);
            }
        }
    });
    out.sort_by(|a, b| (a.kind, &a.dir).cmp(&(b.kind, &b.dir)));
    out
}

/// Whether `rel` is a proper descendant of `ancestor` (both relative to the
/// scan root, where `.` is the root).
fn is_strictly_under(rel: &Path, ancestor: &Path) -> bool {
    if rel == ancestor {
        return false;
    }
    ancestor == Path::new(".") || rel.starts_with(ancestor)
}

fn walk(dir: &Path, rel: &Path, depth: usize, f: &mut dyn FnMut(&Path, &Path)) {
    f(dir, rel);
    if depth >= MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<_> = entries
        .filter_map(Result::ok)
        // Never follow symlinks out of the tree.
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| !SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
        .map(|e| e.file_name())
        .collect();
    subdirs.sort();
    for name in subdirs {
        let child_rel = if rel == Path::new(".") {
            PathBuf::from(&name)
        } else {
            rel.join(&name)
        };
        walk(&dir.join(&name), &child_rel, depth + 1, f);
    }
}

/// Test helpers that build throwaway directory trees.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};

    pub struct Tree(pub PathBuf);

    impl Tree {
        pub fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("afg-detect-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tree(p)
        }
        pub fn file(&self, rel: &str, content: &str) -> &Self {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
            self
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testutil::Tree;

    #[test]
    fn skips_vendored_and_build_dirs() {
        let t = Tree::new("skip");
        t.file("go.mod", "module a\n")
            .file("node_modules/x/go.mod", "module x\n")
            .file("vendor/y/go.mod", "module y\n")
            .file("svc/go.mod", "module svc\n");
        let p = detect_projects(t.path(), &default_detectors());
        let dirs: Vec<_> = p.iter().map(|p| p.dir.display().to_string()).collect();
        assert_eq!(dirs, vec![".", "svc"]);
    }
}
