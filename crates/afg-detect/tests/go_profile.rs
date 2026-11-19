//! The Go detector, now driven by language-profiles/go.yaml (T10.1). These
//! are the original Go detector tests, kept unchanged in intent.

use std::path::{Path, PathBuf};

use afg_detect::{StackKind, Tier, default_detectors, detect_projects};

struct Tree(PathBuf);
impl Tree {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("afg-goprof-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tree(p)
    }
    fn file(&self, rel: &str, c: &str) -> &Self {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, c).unwrap();
        self
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn go(t: &Tree) -> Vec<afg_detect::Project> {
    detect_projects(t.path(), &default_detectors())
        .into_iter()
        .filter(|p| p.kind == StackKind::Go)
        .collect()
}

#[test]
fn detects_module() {
    let t = Tree::new("mod");
    t.file("go.mod", "module example.com/api\n\ngo 1.24\n");
    let p = &go(&t)[0];
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
    let t = Tree::new("work");
    t.file("go.work", "go 1.24\nuse (./a ./b)\n")
        .file("a/go.mod", "module a\n")
        .file("b/go.mod", "module b\n");
    let p = go(&t);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].traits, vec!["workspace"]);
}

#[test]
fn nothing_without_markers() {
    let t = Tree::new("none");
    t.file("main.go", "package main\n");
    assert!(go(&t).is_empty());
}
