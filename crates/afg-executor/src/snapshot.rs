//! Workspace snapshots for isolated backends.
//!
//! A container never sees the live tree. It gets a copy, built from a
//! manifest:
//! - files ignored by `.gitignore` are excluded;
//! - protected credential files (afg-core `ProtectedPaths`) are excluded;
//! - symlinks are skipped, so the copy cannot point back at the host;
//! - `.git` and `.agentforge` are excluded.
//!
//! The walk never runs `git`, because a repository's config can make git
//! execute programs (fsmonitor, hooks).

use std::path::{Path, PathBuf};

use afg_core::paths::ProtectedPaths;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::pin::hash_file;
use crate::sha256_hex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestEntry {
    /// The relative path, with `/` separators.
    pub path: String,
    pub len: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
    pub skipped: Vec<Skipped>,
    pub total_bytes: u64,
    /// The SHA-256 over every `path\tlen\tsha256` line.
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotOptions {
    pub protected: ProtectedPaths,
    pub max_total_bytes: u64,
    pub max_files: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("workspace exceeds the snapshot limit ({0})")]
    TooLarge(String),
    #[error("snapshot walk failed: {0}")]
    Walk(#[from] ignore::Error),
    #[error("snapshot i/o failed: {0}")]
    Io(#[from] std::io::Error),
}

/// A snapshot copy. The directory is deleted on drop.
#[derive(Debug)]
pub struct Snapshot {
    dir: tempfile::TempDir,
    pub manifest: Manifest,
}

impl Snapshot {
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

const ALWAYS_SKIP: &[&str] = &[".git", ".agentforge"];

/// Build the manifest for `root`, without copying anything.
pub fn build_manifest(root: &Path, opts: &SnapshotOptions) -> Result<Manifest, SnapshotError> {
    walk(root, opts, None)
}

/// Copy `root` into a fresh temporary directory, following the manifest rules.
pub fn build_snapshot(root: &Path, opts: &SnapshotOptions) -> Result<Snapshot, SnapshotError> {
    let dir = tempfile::Builder::new().prefix("afg-snapshot-").tempdir()?;
    let manifest = walk(root, opts, Some(dir.path()))?;
    Ok(Snapshot { dir, manifest })
}

fn walk(
    root: &Path,
    opts: &SnapshotOptions,
    dest: Option<&Path>,
) -> Result<Manifest, SnapshotError> {
    let root = root.canonicalize()?;
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let mut total: u64 = 0;

    let walker = ignore::WalkBuilder::new(&root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .ignore(false)
        .parents(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|e| !(e.depth() == 1 && ALWAYS_SKIP.iter().any(|s| e.file_name() == *s)))
        .build();

    for item in walker {
        let item = item?;
        if item.depth() == 0 {
            continue;
        }
        let rel = item.path().strip_prefix(&root).expect("under root");
        let rel_s = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let Some(ft) = item.file_type() else { continue };
        if ft.is_symlink() {
            skipped.push(Skipped {
                path: rel_s,
                reason: "symlink",
            });
            continue;
        }
        if opts.protected.check_path(rel, &root).is_some() {
            skipped.push(Skipped {
                path: rel_s,
                reason: "protected",
            });
            continue;
        }
        if ft.is_dir() {
            if let Some(d) = dest {
                std::fs::create_dir_all(d.join(rel))?;
            }
            continue;
        }
        if !ft.is_file() {
            skipped.push(Skipped {
                path: rel_s,
                reason: "special file",
            });
            continue;
        }
        let len = item.metadata()?.len();
        total += len;
        if total > opts.max_total_bytes {
            return Err(SnapshotError::TooLarge(format!(
                "more than {} bytes",
                opts.max_total_bytes
            )));
        }
        if entries.len() >= opts.max_files {
            return Err(SnapshotError::TooLarge(format!(
                "more than {} files",
                opts.max_files
            )));
        }
        let sha256 = hash_file(item.path())?;
        if let Some(d) = dest {
            let target = d.join(rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(item.path(), &target)?;
        }
        entries.push(ManifestEntry {
            path: rel_s,
            len,
            sha256,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    let mut h = Sha256::new();
    for e in &entries {
        h.update(format!("{}\t{}\t{}\n", e.path, e.len, e.sha256));
    }
    Ok(Manifest {
        entries,
        skipped,
        total_bytes: total,
        hash: sha256_hex(&h.finalize()),
    })
}

/// The location inside a snapshot of a host path under `root`.
pub fn snapshot_path(snapshot: &Path, root: &Path, host: &Path) -> Option<PathBuf> {
    let root = root.canonicalize().ok()?;
    let host = host.canonicalize().ok()?;
    host.strip_prefix(&root).ok().map(|rel| snapshot.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ws(PathBuf);
    impl Ws {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("afg-snap-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Ws(p.canonicalize().unwrap())
        }
        fn file(&self, rel: &str, c: &str) -> &Self {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, c).unwrap();
            self
        }
    }
    impl Drop for Ws {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn opts(ws: &Ws) -> SnapshotOptions {
        SnapshotOptions {
            protected: ProtectedPaths::new(
                Some(Path::new("/nonexistent-home")),
                &ws.0,
                &["private/".into()],
            ),
            max_total_bytes: 1 << 20,
            max_files: 1000,
        }
    }

    #[test]
    fn excludes_ignored_protected_git_and_symlinks() {
        let ws = Ws::new("excl");
        ws.file(".gitignore", "target/\n*.log\n")
            .file("src/main.rs", "fn main(){}")
            .file("scripts/check.sh", "echo ok")
            .file("target/debug/x", "bin")
            .file("app.log", "log")
            .file(".env", "SECRET=FAKE")
            .file("config/.env.local", "SECRET=FAKE")
            .file("certs/tls.key", "FAKE")
            .file("private/notes.txt", "x")
            .file(".git/config", "[core]\n\tfsmonitor = evil\n")
            .file(".agentforge/audit/x.jsonl", "{}");
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", ws.0.join("passwd")).unwrap();

        let snap = build_snapshot(&ws.0, &opts(&ws)).unwrap();
        let paths: Vec<_> = snap
            .manifest
            .entries
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(paths, vec![".gitignore", "scripts/check.sh", "src/main.rs"]);
        let skipped: Vec<_> = snap
            .manifest
            .skipped
            .iter()
            .map(|s| (s.path.as_str(), s.reason))
            .collect();
        assert!(skipped.contains(&(".env", "protected")));
        assert!(skipped.contains(&("certs/tls.key", "protected")));
        assert!(skipped.contains(&("private", "protected")));
        #[cfg(unix)]
        assert!(skipped.contains(&("passwd", "symlink")));
        assert!(snap.path().join("src/main.rs").is_file());
        assert!(!snap.path().join(".env").exists());
        assert!(!snap.path().join(".git").exists());
        assert!(!snap.path().join("target").exists());
    }

    #[test]
    fn manifest_hash_is_deterministic_and_content_sensitive() {
        let ws = Ws::new("hash");
        ws.file("a.txt", "1");
        let a = build_manifest(&ws.0, &opts(&ws)).unwrap();
        let b = build_manifest(&ws.0, &opts(&ws)).unwrap();
        assert_eq!(a.hash, b.hash);
        ws.file("a.txt", "2");
        assert_ne!(a.hash, build_manifest(&ws.0, &opts(&ws)).unwrap().hash);
    }

    #[test]
    fn size_limit() {
        let ws = Ws::new("big");
        ws.file("big.bin", &"x".repeat(2048));
        let mut o = opts(&ws);
        o.max_total_bytes = 1024;
        assert!(matches!(
            build_snapshot(&ws.0, &o),
            Err(SnapshotError::TooLarge(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let ws = Ws::new("exec");
        ws.file("run.sh", "echo");
        std::fs::set_permissions(ws.0.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let snap = build_snapshot(&ws.0, &opts(&ws)).unwrap();
        let mode = std::fs::metadata(snap.path().join("run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
    }

    #[test]
    fn snapshot_dir_removed_on_drop() {
        let ws = Ws::new("drop");
        ws.file("a", "1");
        let p = {
            let s = build_snapshot(&ws.0, &opts(&ws)).unwrap();
            s.path().to_path_buf()
        };
        assert!(!p.exists());
    }
}
