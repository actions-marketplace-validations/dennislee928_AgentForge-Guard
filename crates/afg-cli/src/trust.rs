//! Policy trust pinning (T13.2 review).
//!
//! `afg init` and `afg policy trust` (run by a human) record the policy's
//! hash in `~/.config/agentforge/trusted/`, a protected path. When a pin
//! exists and the policy no longer matches it, every decision is denied: an
//! agent that edits `agentforge.yaml` cannot loosen it. afg can never run
//! itself, so an agent confined to afg cannot re-pin.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pin {
    pub policy_path: String,
    pub hash: String,
    pub trusted_unix: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Trusted,
    /// No pin yet (a warning, for compatibility).
    Unpinned,
    /// The policy changed since it was pinned; everything is denied.
    Changed {
        pinned: String,
    },
}

fn pin_path(home: &Path, policy_path: &Path) -> PathBuf {
    let id = Sha256::digest(policy_path.display().to_string().as_bytes());
    let hex: String = id.iter().take(16).map(|b| format!("{b:02x}")).collect();
    home.join(".config/agentforge/trusted")
        .join(format!("{hex}.json"))
}

pub fn status(home: Option<&Path>, policy_path: &Path, hash: &str) -> Status {
    let Some(home) = home else {
        return Status::Unpinned;
    };
    let Ok(bytes) = std::fs::read(pin_path(home, policy_path)) else {
        return Status::Unpinned;
    };
    match serde_json::from_slice::<Pin>(&bytes) {
        Ok(p) if p.hash == hash => Status::Trusted,
        Ok(p) => Status::Changed { pinned: p.hash },
        Err(_) => Status::Changed {
            pinned: "unreadable pin".into(),
        },
    }
}

pub fn pin(home: &Path, policy_path: &Path, hash: &str) -> anyhow::Result<PathBuf> {
    let p = pin_path(home, policy_path);
    let dir = p.parent().expect("has parent");
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            home.join(".config/agentforge"),
            std::fs::Permissions::from_mode(0o700),
        )?;
    }
    let pin = Pin {
        policy_path: policy_path.display().to_string(),
        hash: hash.to_owned(),
        trusted_unix: crate::tokens::now_unix(),
    };
    std::fs::write(&p, serde_json::to_vec_pretty(&pin)?)
        .with_context(|| format!("writing {}", p.display()))?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_then_change() {
        let h = tempfile::tempdir().unwrap();
        let policy = Path::new("/w/agentforge.yaml");
        assert_eq!(status(Some(h.path()), policy, "sha256:a"), Status::Unpinned);
        pin(h.path(), policy, "sha256:a").unwrap();
        assert_eq!(status(Some(h.path()), policy, "sha256:a"), Status::Trusted);
        assert_eq!(
            status(Some(h.path()), policy, "sha256:b"),
            Status::Changed {
                pinned: "sha256:a".into()
            }
        );
        assert_eq!(
            status(
                Some(h.path()),
                Path::new("/other/agentforge.yaml"),
                "sha256:b"
            ),
            Status::Unpinned
        );
    }
}
