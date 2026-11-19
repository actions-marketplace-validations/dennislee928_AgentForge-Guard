//! Go modules and workspaces.

use std::path::Path;

use crate::{Detector, Project, StackKind, SuggestedCommand, Tier};

pub struct GoDetector;

impl Detector for GoDetector {
    fn kind(&self) -> StackKind {
        StackKind::Go
    }

    fn detect(&self, dir: &Path, rel: &Path) -> Option<Project> {
        let has_mod = dir.join("go.mod").is_file();
        let has_work = dir.join("go.work").is_file();
        if !has_mod && !has_work {
            return None;
        }
        let mut markers = Vec::new();
        let mut traits = Vec::new();
        if has_mod {
            markers.push("go.mod".into());
        }
        if has_work {
            markers.push("go.work".into());
            traits.push("workspace".into());
        }
        Some(Project {
            kind: StackKind::Go,
            dir: rel.to_path_buf(),
            markers,
            traits,
            commands: vec![
                SuggestedCommand::new(&["go", "list", "./..."], Tier::T0, "list packages"),
                SuggestedCommand::new(&["go", "build", "./..."], Tier::T1, "build"),
                SuggestedCommand::new(&["go", "vet", "./..."], Tier::T1, "static checks"),
                SuggestedCommand::new(&["go", "test", "./..."], Tier::T1, "tests"),
                SuggestedCommand::new(&["go", "mod", "download"], Tier::T2, "fetch dependencies"),
            ],
        })
    }

    fn covers_children(&self, p: &Project) -> bool {
        // A go.work workspace lists its modules; report them only once.
        p.traits.iter().any(|t| t == "workspace")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;
    use crate::{default_detectors, detect_projects};

    #[test]
    fn detects_module() {
        let t = Tree::new("go-mod");
        t.file("go.mod", "module example.com/api\n\ngo 1.24\n");
        let p = GoDetector.detect(t.path(), Path::new(".")).unwrap();
        assert_eq!(p.markers, vec!["go.mod"]);
        assert!(
            p.commands
                .iter()
                .any(|c| c.argv == ["go", "test", "./..."] && c.tier == Tier::T1)
        );
        assert!(
            p.commands
                .iter()
                .any(|c| c.argv[..2] == ["go", "mod"] && c.tier == Tier::T2)
        );
    }

    #[test]
    fn workspace_covers_members() {
        let t = Tree::new("go-work");
        t.file("go.work", "go 1.24\nuse (./a ./b)\n")
            .file("a/go.mod", "module a\n")
            .file("b/go.mod", "module b\n");
        let p = detect_projects(t.path(), &default_detectors());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].traits, vec!["workspace"]);
    }

    #[test]
    fn nothing_without_markers() {
        let t = Tree::new("go-none");
        t.file("main.go", "package main\n");
        assert!(GoDetector.detect(t.path(), Path::new(".")).is_none());
    }
}
