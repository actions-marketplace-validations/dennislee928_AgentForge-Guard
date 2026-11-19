//! The Cloudflare backend: sends an approved request to the Worker in
//! `packages/cloudflare-adapter`, which runs it in a throwaway container.
//!
//! - The policy decision is made locally. The Worker only checks the HMAC
//!   signature and the request's structure (ADR 0002).
//! - The workspace is uploaded as a tar archive of the manifest-filtered
//!   snapshot. Gitignored and protected files and symlinks are never included.
//! - Cost and safety caps: a maximum upload size and a timeout, here; at the
//!   Worker, a per-request container that is always destroyed, plus a TTL alarm.
//! - Cleanup is attempted after every failure (T11.4).

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::snapshot::{SnapshotOptions, build_snapshot};
use crate::{Captured, ExecutionError, ExecutionRequest, ExecutionResult, Executor, NetworkPolicy};

type HmacSha256 = hmac::Hmac<Sha256>;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone)]
pub struct CloudflareConfig {
    /// The Worker base URL, without a trailing slash.
    pub endpoint: String,
    /// The HMAC key, at least 32 bytes.
    pub key: Vec<u8>,
    pub network: NetworkPolicy,
    pub max_upload_bytes: u64,
    pub snapshot: SnapshotOptions,
}

impl std::fmt::Debug for CloudflareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareConfig")
            .field("endpoint", &self.endpoint)
            .field("key", &"[REDACTED]")
            .field("network", &self.network)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct CloudflareExecutor {
    cfg: CloudflareConfig,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteWire<'a> {
    version: u32,
    kind: &'static str,
    id: &'a str,
    issued_at: u64,
    argv: &'a [String],
    cwd: String,
    env: std::collections::BTreeMap<&'a str, &'a str>,
    timeout_seconds: u64,
    network: &'static str,
    archive: String,
    manifest_hash: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupWire<'a> {
    version: u32,
    kind: &'static str,
    id: &'a str,
    issued_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteResponse {
    exit_code: i32,
    timed_out: bool,
    duration_ms: u64,
    stdout: WireStream,
    stderr: WireStream,
    manifest_hash: String,
}

#[derive(Debug, Deserialize)]
struct WireStream {
    data: String,
    len: u64,
    truncated: bool,
    sha256: String,
}

/// The `X-AFG-Signature` header value for `body`.
pub fn sign(key: &[u8], body: &str) -> String {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("any key length");
    m.update(body.as_bytes());
    let hex: String = m
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("v1={hex}")
}

/// Parse a hex key (whitespace is trimmed).
pub fn parse_key(hex: &str) -> Result<Vec<u8>, ExecutionError> {
    let h = hex.trim();
    let bad = || {
        ExecutionError::InvalidRequest(
            "the Cloudflare signing key must be at least 64 hex characters".into(),
        )
    };
    if h.len() < 64 || !h.len().is_multiple_of(2) {
        return Err(bad());
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| bad()))
        .collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A tar archive of the snapshot directory (regular files and directories only).
pub fn tar_snapshot(dir: &Path) -> std::io::Result<Vec<u8>> {
    let mut b = tar::Builder::new(Vec::new());
    b.follow_symlinks(false);
    b.mode(tar::HeaderMode::Deterministic);
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(dir.join(&rel))?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let ft = e.file_type()?;
            let r = rel.join(e.file_name());
            if ft.is_dir() {
                b.append_dir(&r, e.path())?;
                stack.push(r);
            } else if ft.is_file() {
                b.append_path_with_name(e.path(), &r)?;
            }
        }
    }
    b.into_inner()
}

fn decode_stream(s: WireStream) -> Result<Captured, ExecutionError> {
    let bytes = B64.decode(s.data).map_err(|e| {
        ExecutionError::Io(std::io::Error::other(format!("bad output encoding: {e}")))
    })?;
    Ok(Captured {
        bytes,
        total_len: s.len,
        truncated: s.truncated,
        sha256: s.sha256,
    })
}

impl CloudflareExecutor {
    pub fn new(cfg: CloudflareConfig) -> Result<Self, ExecutionError> {
        let e = &cfg.endpoint;
        let loopback = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"]
            .iter()
            .any(|p| e.starts_with(p));
        if !(e.starts_with("https://") || loopback) {
            return Err(ExecutionError::InvalidRequest(
                "the Cloudflare endpoint must be https".into(),
            ));
        }
        if cfg.key.len() < 32 {
            return Err(ExecutionError::InvalidRequest(
                "the Cloudflare signing key is too short".into(),
            ));
        }
        Ok(Self {
            cfg: CloudflareConfig {
                endpoint: e.trim_end_matches('/').to_owned(),
                ..cfg
            },
        })
    }

    fn post(
        &self,
        path: &str,
        body: &str,
        timeout: Duration,
    ) -> Result<(u16, String), ExecutionError> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build()
            .into();
        let url = format!("{}{path}", self.cfg.endpoint);
        let mut resp = agent
            .post(&url)
            .header("content-type", "application/json")
            .header("x-afg-signature", sign(&self.cfg.key, body))
            .send(body)
            .map_err(|e| ExecutionError::Unavailable(format!("cloudflare backend: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().map_err(|e| {
            ExecutionError::Unavailable(format!("cloudflare backend response: {e}"))
        })?;
        Ok((status, text))
    }

    /// Build the signed request body (exposed for contract tests).
    pub fn request_body(
        &self,
        req: &ExecutionRequest,
        archive: &[u8],
        manifest_hash: &str,
    ) -> Result<String, ExecutionError> {
        let root = req.workspace_root.canonicalize()?;
        let cwd = req.cwd.canonicalize()?;
        let rel = cwd.strip_prefix(&root).map_err(|_| {
            ExecutionError::InvalidRequest("working directory is outside the workspace".into())
        })?;
        let wire = ExecuteWire {
            version: PROTOCOL_VERSION,
            kind: "execute",
            id: &req.id,
            issued_at: now_unix(),
            argv: &req.argv,
            cwd: rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
            env: req
                .env
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            timeout_seconds: req.timeout.as_secs().max(1),
            network: match self.cfg.network {
                NetworkPolicy::None => "none",
                NetworkPolicy::Bridge => "bridge",
            },
            archive: B64.encode(archive),
            manifest_hash,
        };
        serde_json::to_string(&wire).map_err(|e| ExecutionError::Io(std::io::Error::other(e)))
    }

    fn execute_blocking(&self, req: ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        if req.argv.first().is_none_or(|a| a.is_empty()) {
            return Err(ExecutionError::InvalidRequest("empty argv".into()));
        }
        let root = req.workspace_root.canonicalize()?;
        let snapshot = build_snapshot(&root, &self.cfg.snapshot)
            .map_err(|e| ExecutionError::InvalidRequest(e.to_string()))?;
        crate::verify_pins_in_snapshot(&req, &root, snapshot.path())?;
        let archive = tar_snapshot(snapshot.path())?;
        if archive.len() as u64 > self.cfg.max_upload_bytes {
            return Err(ExecutionError::InvalidRequest(format!(
                "snapshot archive is {} bytes, over the {}-byte upload cap",
                archive.len(),
                self.cfg.max_upload_bytes
            )));
        }
        let body = self.request_body(&req, &archive, &snapshot.manifest.hash)?;
        let (status, text) =
            self.post("/v1/execute", &body, req.timeout + Duration::from_secs(120))?;
        if status != 200 {
            return Err(ExecutionError::Unavailable(format!(
                "cloudflare backend returned {status}: {text}"
            )));
        }
        let r: ExecuteResponse = serde_json::from_str(&text).map_err(|e| {
            ExecutionError::Unavailable(format!("cloudflare backend: invalid response: {e}"))
        })?;
        if r.manifest_hash != snapshot.manifest.hash {
            return Err(ExecutionError::Integrity(
                "the backend ran a different snapshot".into(),
            ));
        }
        let stdout = decode_stream(r.stdout)?;
        let stderr = decode_stream(r.stderr)?;
        if req.stream {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&stdout.bytes);
            let _ = std::io::stderr().write_all(&stderr.bytes);
        }
        Ok(ExecutionResult {
            exit_code: if r.timed_out { None } else { Some(r.exit_code) },
            timed_out: r.timed_out,
            duration_ms: r.duration_ms,
            stdout,
            stderr,
            details: vec![
                ("endpoint".into(), self.cfg.endpoint.clone()),
                ("snapshotManifest".into(), snapshot.manifest.hash.clone()),
                (
                    "snapshotFiles".into(),
                    snapshot.manifest.entries.len().to_string(),
                ),
                ("uploadBytes".into(), archive.len().to_string()),
            ],
        })
    }

    fn cleanup_blocking(&self, id: &str) -> Result<(), ExecutionError> {
        let body = serde_json::to_string(&CleanupWire {
            version: PROTOCOL_VERSION,
            kind: "cleanup",
            id,
            issued_at: now_unix(),
        })
        .map_err(|e| ExecutionError::Io(std::io::Error::other(e)))?;
        let (status, text) = self.post("/v1/cleanup", &body, Duration::from_secs(30))?;
        if status != 200 {
            return Err(ExecutionError::Unavailable(format!(
                "cleanup returned {status}: {text}"
            )));
        }
        Ok(())
    }
}

impl Executor for CloudflareExecutor {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        let this = self.clone();
        let id = req.id.clone();
        let res = tokio::task::spawn_blocking(move || this.execute_blocking(req))
            .await
            .map_err(|e| ExecutionError::Io(std::io::Error::other(e)))?;
        if res.is_err() {
            // Best effort; the Worker's TTL alarm is the backstop.
            let _ = self.cleanup(&id).await;
        }
        res
    }

    async fn cleanup(&self, id: &str) -> Result<(), ExecutionError> {
        let this = self.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || this.cleanup_blocking(&id))
            .await
            .map_err(|e| ExecutionError::Io(std::io::Error::other(e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        key_hex: String,
        body: String,
        header: String,
    }

    /// The Rust signer and the Worker verifier share this vector
    /// (tests/cloudflare-contract/vector.json).
    #[test]
    fn signer_matches_shared_vector() {
        let v: Vector = serde_json::from_str(include_str!(
            "../../../tests/cloudflare-contract/vector.json"
        ))
        .unwrap();
        assert_eq!(sign(&parse_key(&v.key_hex).unwrap(), &v.body), v.header);
    }

    #[test]
    fn keys_must_be_long_hex() {
        assert!(parse_key("abcd").is_err());
        assert!(parse_key(&"zz".repeat(32)).is_err());
        assert_eq!(
            parse_key(&format!("{}\n", "ab".repeat(32))).unwrap().len(),
            32
        );
    }

    #[test]
    fn tar_contains_regular_files_only() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("src")).unwrap();
        std::fs::write(d.path().join("src/a.txt"), "a").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("link")).unwrap();
        let bytes = tar_snapshot(d.path()).unwrap();
        let mut ar = tar::Archive::new(&bytes[..]);
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "src/a.txt"), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("link")));
    }

    #[test]
    fn config_debug_redacts_key_and_requires_https() {
        let cfg = CloudflareConfig {
            endpoint: "http://example.com".into(),
            key: vec![7; 32],
            network: NetworkPolicy::None,
            max_upload_bytes: 1,
            snapshot: SnapshotOptions {
                protected: afg_core::paths::ProtectedPaths::new(None, Path::new("/"), &[]),
                max_total_bytes: 1,
                max_files: 1,
            },
        };
        assert!(format!("{cfg:?}").contains("[REDACTED]"));
        assert!(CloudflareExecutor::new(cfg.clone()).is_err());
        assert!(
            CloudflareExecutor::new(CloudflareConfig {
                endpoint: "https://x.workers.dev/".into(),
                ..cfg
            })
            .is_ok()
        );
    }
}
