//! Cargo packages and workspaces.

use std::path::Path;

use crate::{Detector, Project, StackKind, SuggestedCommand, Tier};

pub struct RustDetector;

impl Detector for RustDetector {
    fn kind(&self) -> StackKind {
        StackKind::Rust
    }

    fn detect(&self, dir: &Path, rel: &Path) -> Option<Project> {
        let manifest = dir.join("Cargo.toml");
        let src = std::fs::read_to_string(&manifest).ok()?;
        // An unparsable manifest is still a Rust project; report it without traits.
        let doc: Option<toml::Table> = src.parse().ok();
        let mut traits = Vec::new();
        let is_workspace = doc.as_ref().is_some_and(|d| d.contains_key("workspace"));
        if is_workspace {
            traits.push("workspace".into());
        }
        if doc.as_ref().is_some_and(|d| d.contains_key("package")) {
            traits.push("package".into());
        }
        if doc.is_none() {
            traits.push("unparsable-manifest".into());
        }
        let mut markers = vec!["Cargo.toml".to_string()];
        if dir.join("Cargo.lock").is_file() {
            markers.push("Cargo.lock".into());
        }
        if dir.join("build.rs").is_file() {
            // A build script runs arbitrary code at build time.
            traits.push("build-script".into());
        }
        let ws: &[&str] = if is_workspace { &["--workspace"] } else { &[] };
        let with = |base: &[&str], extra: &[&str]| -> Vec<String> {
            base.iter()
                .chain(ws)
                .chain(extra)
                .map(|s| s.to_string())
                .collect()
        };
        Some(Project {
            kind: StackKind::Rust,
            dir: rel.to_path_buf(),
            markers,
            traits,
            commands: vec![
                SuggestedCommand::new(
                    &["cargo", "metadata", "--format-version", "1"],
                    Tier::T0,
                    "metadata",
                ),
                SuggestedCommand {
                    argv: with(&["cargo", "check"], &[]),
                    tier: Tier::T1,
                    purpose: "type check".into(),
                },
                SuggestedCommand {
                    argv: with(&["cargo", "clippy"], &["--all-targets"]),
                    tier: Tier::T1,
                    purpose: "lints".into(),
                },
                SuggestedCommand {
                    argv: with(&["cargo", "test"], &[]),
                    tier: Tier::T1,
                    purpose: "tests".into(),
                },
                SuggestedCommand::new(&["cargo", "fetch"], Tier::T2, "fetch dependencies"),
            ],
        })
    }

    fn covers_children(&self, p: &Project) -> bool {
        p.traits.iter().any(|t| t == "workspace")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;
    use crate::{default_detectors, detect_projects};

    #[test]
    fn detects_package() {
        let t = Tree::new("rs-pkg");
        t.file(
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .file("build.rs", "fn main(){}");
        let p = RustDetector.detect(t.path(), Path::new(".")).unwrap();
        assert_eq!(p.traits, vec!["package", "build-script"]);
        assert!(p.commands.iter().any(|c| c.argv == ["cargo", "test"]));
    }

    #[test]
    fn workspace_covers_members_and_adds_flag() {
        let t = Tree::new("rs-ws");
        t.file("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n")
            .file("crates/a/Cargo.toml", "[package]\nname = \"a\"\n")
            .file("crates/b/Cargo.toml", "[package]\nname = \"b\"\n");
        let p = detect_projects(t.path(), &default_detectors());
        let rust: Vec<_> = p.iter().filter(|p| p.kind == StackKind::Rust).collect();
        assert_eq!(rust.len(), 1);
        assert!(
            rust[0]
                .commands
                .iter()
                .any(|c| c.argv == ["cargo", "test", "--workspace"])
        );
    }

    #[test]
    fn unparsable_manifest_still_detected() {
        let t = Tree::new("rs-bad");
        t.file("Cargo.toml", "[package\n");
        let p = RustDetector.detect(t.path(), Path::new(".")).unwrap();
        assert!(p.traits.contains(&"unparsable-manifest".to_string()));
    }
}
