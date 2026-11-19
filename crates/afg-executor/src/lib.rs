//! Execution backends (local, Docker).
//!
//! Executors run only requests that `afg-core` has already decided on. They
//! make no policy decisions of their own (ADR 0002). Every backend uses a
//! structured argv; none of them ever adds a shell.

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

pub mod capture;
pub mod docker;
pub mod local;
pub mod pin;
pub mod process;
pub mod snapshot;

pub use docker::{DockerConfig, DockerExecutor};
pub use local::LocalExecutor;
pub use pin::PinnedFile;

/// The network access a sandboxed run gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    None,
    Bridge,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLimits {
    pub memory_mb: u64,
    pub cpus: f64,
    pub pids: u64,
}

/// One approved command.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    /// A unique id, used in audit records and container names.
    pub id: String,
    /// The argv to run. For the local backend `argv[0]` is the resolved
    /// absolute program path. For containers it is the name as given.
    pub argv: Vec<String>,
    /// The `argv[0]` the child sees. The local backend executes the canonical
    /// program path (so a symlink can't be retargeted after the decision) but
    /// shows the name as invoked, which multicall binaries such as rustup
    /// need.
    pub arg0: Option<String>,
    /// The working directory on the host.
    pub cwd: PathBuf,
    /// The project root; containers mount a snapshot of it.
    pub workspace_root: PathBuf,
    /// The complete environment of the child process. Nothing is inherited.
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    /// Files pinned at decision time, re-verified just before spawning (TOCTOU).
    pub pinned: Vec<PinnedFile>,
    /// Whether to forward output to this process's stdout and stderr as it
    /// arrives.
    pub stream: bool,
    /// The maximum number of bytes kept for each of stdout and stderr.
    pub capture_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Captured {
    /// The first `capture_limit` bytes.
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub total_len: u64,
    pub truncated: bool,
    /// The SHA-256 of the complete stream, as `sha256:<hex>`.
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResult {
    /// `None` if the process was killed by a signal.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: Captured,
    pub stderr: Captured,
    /// Backend-specific facts, for example the container image or the snapshot manifest hash.
    pub details: Vec<(String, String)>,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("failed to start `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("integrity check failed: {0}")]
    Integrity(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// An execution backend.
pub trait Executor: Send + Sync {
    /// A short backend name, such as `local` or `container`.
    fn name(&self) -> &'static str;

    /// Run the request to completion, or until its timeout.
    fn execute(
        &self,
        request: ExecutionRequest,
    ) -> impl std::future::Future<Output = Result<ExecutionResult, ExecutionError>> + Send;

    /// Release anything left over from a request (containers, snapshots).
    /// This must be idempotent.
    fn cleanup(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<(), ExecutionError>> + Send;
}

/// Format a digest as `sha256:<hex>`.
pub fn sha256_hex(digest: &[u8]) -> String {
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Re-verify every pinned file on the host, immediately before spawning.
pub(crate) fn verify_pins(req: &ExecutionRequest) -> Result<(), ExecutionError> {
    for p in &req.pinned {
        p.verify()?;
    }
    Ok(())
}

/// Re-verify pinned workspace files against their snapshot copies, so that
/// the container runs exactly the content that was decided on. Pins outside
/// the workspace (such as a host program) do not apply inside a container.
pub(crate) fn verify_pins_in_snapshot(
    req: &ExecutionRequest,
    root: &std::path::Path,
    snapshot: &std::path::Path,
) -> Result<(), ExecutionError> {
    for p in &req.pinned {
        let Ok(rel) = p.path.strip_prefix(root) else {
            continue;
        };
        let copy = snapshot.join(rel);
        if !copy.exists() {
            return Err(ExecutionError::Integrity(format!(
                "{} is not in the snapshot (it is gitignored, protected or a symlink)",
                rel.display()
            )));
        }
        p.verify_copy(&copy)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(pins: Vec<PinnedFile>) -> ExecutionRequest {
        ExecutionRequest {
            id: "t".into(),
            argv: vec!["sh".into()],
            arg0: None,
            cwd: std::env::temp_dir(),
            workspace_root: std::env::temp_dir(),
            env: vec![],
            timeout: Duration::from_secs(1),
            pinned: pins,
            stream: false,
            capture_limit: 10,
        }
    }

    #[test]
    fn snapshot_pin_verification() {
        let base = std::env::temp_dir().join(format!("afg-snappin-{}", std::process::id()));
        let root = base.join("ws");
        let snap = base.join("snap");
        std::fs::create_dir_all(root.join("scripts")).unwrap();
        std::fs::create_dir_all(snap.join("scripts")).unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::write(root.join("scripts/a.sh"), "echo a").unwrap();
        let pin = PinnedFile::pin(&root.join("scripts/a.sh")).unwrap();
        let host_prog = PinnedFile::pin(std::path::Path::new("/bin/sh")).unwrap();
        let r = req_with(vec![pin, host_prog]);

        // The file is missing from the snapshot.
        assert!(matches!(
            verify_pins_in_snapshot(&r, &root, &snap),
            Err(ExecutionError::Integrity(_))
        ));
        // The snapshot has different content.
        std::fs::write(snap.join("scripts/a.sh"), "echo b").unwrap();
        assert!(verify_pins_in_snapshot(&r, &root, &snap).is_err());
        // The snapshot has the same content. The host program pin is skipped.
        std::fs::write(snap.join("scripts/a.sh"), "echo a").unwrap();
        verify_pins_in_snapshot(&r, &root, &snap).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }
}
