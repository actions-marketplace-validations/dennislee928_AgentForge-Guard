//! TOCTOU protection: files are pinned when the decision is made and
//! re-verified immediately before the process is spawned.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ExecutionError, sha256_hex};

/// Files up to this size are content-hashed; larger ones (such as compiler
/// binaries) are pinned by metadata only.
pub const HASH_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnedFile {
    pub path: PathBuf,
    pub len: u64,
    pub modified_ns: Option<u128>,
    #[cfg_attr(not(unix), serde(skip))]
    pub inode: Option<u64>,
    pub sha256: Option<String>,
}

impl PinnedFile {
    /// Pin the regular file at `path`, following symlinks.
    pub fn pin(path: &Path) -> std::io::Result<Self> {
        let canonical = path.canonicalize()?;
        let meta = std::fs::metadata(&canonical)?;
        if !meta.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        let sha256 = if meta.len() <= HASH_LIMIT {
            Some(hash_file(&canonical)?)
        } else {
            None
        };
        Ok(Self {
            path: canonical,
            len: meta.len(),
            modified_ns: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos()),
            inode: inode(&meta),
            sha256,
        })
    }

    /// Check that the file at `self.path` is still the pinned file.
    pub fn verify(&self) -> Result<(), ExecutionError> {
        self.verify_at(&self.path)
    }

    /// Check that `path` (for example a snapshot copy) has the pinned
    /// content. Metadata other than size is not compared, because copies get
    /// new inodes and timestamps.
    pub fn verify_copy(&self, path: &Path) -> Result<(), ExecutionError> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| self.fail(&format!("{e}")))?;
        if !meta.is_file() || meta.len() != self.len {
            return Err(self.fail("size or type changed"));
        }
        match &self.sha256 {
            Some(h) if *h != hash_file(path).map_err(|e| self.fail(&e.to_string()))? => {
                Err(self.fail("content changed"))
            }
            _ => Ok(()),
        }
    }

    fn verify_at(&self, path: &Path) -> Result<(), ExecutionError> {
        let canonical = path.canonicalize().map_err(|e| self.fail(&e.to_string()))?;
        if canonical != self.path {
            return Err(self.fail("path now resolves elsewhere"));
        }
        let now = Self::pin(&canonical).map_err(|e| self.fail(&e.to_string()))?;
        if now.len != self.len || now.inode != self.inode || now.modified_ns != self.modified_ns {
            return Err(self.fail("metadata changed"));
        }
        if now.sha256 != self.sha256 {
            return Err(self.fail("content changed"));
        }
        Ok(())
    }

    fn fail(&self, why: &str) -> ExecutionError {
        ExecutionError::Integrity(format!(
            "{}: {why} since the policy decision",
            self.path.display()
        ))
    }
}

#[cfg(unix)]
fn inode(m: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(m.ino())
}

#[cfg(not(unix))]
fn inode(_: &std::fs::Metadata) -> Option<u64> {
    None
}

pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(sha256_hex(&h.finalize()))
}

/// Pin the program and every argument that names an existing regular file
/// inside `workspace` (scripts, for example).
pub fn pin_request_files(
    program: Option<&Path>,
    args: &[String],
    cwd: &Path,
    workspace: &Path,
) -> Vec<PinnedFile> {
    let mut out = Vec::new();
    if let Some(p) = program
        && let Ok(pin) = PinnedFile::pin(p)
    {
        out.push(pin);
    }
    let ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    for a in args {
        if a.starts_with('-') {
            continue;
        }
        let p = cwd.join(a);
        if let Ok(c) = p.canonicalize()
            && c.starts_with(&ws)
            && c.is_file()
            && !out.iter().any(|x: &PinnedFile| x.path == c)
            && let Ok(pin) = PinnedFile::pin(&c)
        {
            out.push(pin);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("afg-pin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn unchanged_file_verifies() {
        let d = tmp("ok");
        std::fs::write(d.join("s.sh"), "echo hi\n").unwrap();
        let p = PinnedFile::pin(&d.join("s.sh")).unwrap();
        assert!(p.sha256.as_deref().unwrap().starts_with("sha256:"));
        p.verify().unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn modified_file_fails() {
        let d = tmp("mod");
        std::fs::write(d.join("s.sh"), "echo hi\n").unwrap();
        let p = PinnedFile::pin(&d.join("s.sh")).unwrap();
        std::fs::write(d.join("s.sh"), "rm -rf /\n").unwrap();
        assert!(matches!(p.verify(), Err(ExecutionError::Integrity(_))));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn same_size_swap_detected() {
        let d = tmp("swap");
        std::fs::write(d.join("s.sh"), "echo aa\n").unwrap();
        let p = PinnedFile::pin(&d.join("s.sh")).unwrap();
        std::fs::write(d.join("other"), "echo bb\n").unwrap();
        std::fs::rename(d.join("other"), d.join("s.sh")).unwrap();
        assert!(p.verify().is_err());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_retarget_detected() {
        let d = tmp("link");
        std::fs::write(d.join("a"), "echo a\n").unwrap();
        std::fs::write(d.join("b"), "echo a\n").unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("run")).unwrap();
        let p = PinnedFile::pin(&d.join("run")).unwrap();
        std::fs::remove_file(d.join("run")).unwrap();
        std::os::unix::fs::symlink(d.join("b"), d.join("run")).unwrap();
        // The pin stores the canonical target, so the original target still
        // verifies; callers must run the pinned path, not the link.
        p.verify().unwrap();
        assert_eq!(p.path, d.join("a"));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn copy_verification() {
        let d = tmp("copy");
        std::fs::write(d.join("s.sh"), "echo hi\n").unwrap();
        let p = PinnedFile::pin(&d.join("s.sh")).unwrap();
        std::fs::write(d.join("copy.sh"), "echo hi\n").unwrap();
        p.verify_copy(&d.join("copy.sh")).unwrap();
        std::fs::write(d.join("copy.sh"), "echo ho\n").unwrap();
        assert!(p.verify_copy(&d.join("copy.sh")).is_err());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pins_scripts_inside_workspace_only() {
        let d = tmp("req");
        std::fs::create_dir_all(d.join("ws/scripts")).unwrap();
        std::fs::write(d.join("ws/scripts/check.sh"), "x").unwrap();
        std::fs::write(d.join("outside.sh"), "x").unwrap();
        let args = vec![
            "scripts/check.sh".into(),
            "../outside.sh".into(),
            "--flag".into(),
            "missing".into(),
        ];
        let pins = pin_request_files(None, &args, &d.join("ws"), &d.join("ws"));
        assert_eq!(pins.len(), 1);
        assert!(pins[0].path.ends_with("scripts/check.sh"));
        std::fs::remove_dir_all(d).unwrap();
    }
}
