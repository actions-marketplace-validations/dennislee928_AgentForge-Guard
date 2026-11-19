//! The container backend: runs an approved argv in a throwaway Docker
//! container (ADR 0004).
//!
//! - It uses the `docker` CLI with a structured argv, so no SDK and no shell.
//! - The container gets a manifest-filtered *snapshot* of the workspace,
//!   never the live tree, `$HOME` or the Docker socket. Changes made in the
//!   container are discarded.
//! - Every run uses `--network none` (unless the policy says `bridge`),
//!   `--read-only`, `--cap-drop ALL`, `no-new-privileges`, a non-root user
//!   and memory, CPU and pids limits.
//! - `--entrypoint` is set to `argv[0]`, so an image's ENTRYPOINT cannot wrap
//!   the command in a shell.
//! - Environment values reach the container through the docker CLI's own
//!   environment (`--env NAME`), never on its command line, where `ps` would
//!   show them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::process::{Spawn, run};
use crate::snapshot::{SnapshotOptions, build_snapshot, snapshot_path};
use crate::{
    ExecutionError, ExecutionRequest, ExecutionResult, Executor, NetworkPolicy, ResourceLimits,
};

/// Where the snapshot is mounted inside the container.
pub const WORKSPACE_MOUNT: &str = "/workspace";

/// Host variables that the docker CLI itself may need. They are never passed
/// into the container.
pub const DOCKER_CLI_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
];

#[derive(Debug, Clone)]
pub struct DockerConfig {
    /// The absolute path of the docker CLI.
    pub docker: PathBuf,
    /// The docker CLI's environment.
    pub docker_env: Vec<(String, String)>,
    pub image: String,
    pub network: NetworkPolicy,
    pub read_only_rootfs: bool,
    pub limits: ResourceLimits,
    /// `uid:gid` for the container user. It is always non-root.
    pub user: (u32, u32),
    pub snapshot: SnapshotOptions,
}

#[derive(Debug, Clone)]
pub struct DockerExecutor {
    cfg: DockerConfig,
}

impl DockerExecutor {
    pub fn new(cfg: DockerConfig) -> Result<Self, ExecutionError> {
        if cfg.image.is_empty()
            || cfg.image.starts_with('-')
            || cfg.image.contains(char::is_whitespace)
        {
            return Err(ExecutionError::InvalidRequest(format!(
                "invalid image `{}`",
                cfg.image
            )));
        }
        if cfg.user.0 == 0 {
            return Err(ExecutionError::InvalidRequest(
                "containers never run as root (uid 0)".into(),
            ));
        }
        if !cfg.docker.is_absolute() {
            return Err(ExecutionError::InvalidRequest(
                "the docker CLI path must be absolute".into(),
            ));
        }
        Ok(Self { cfg })
    }

    /// The current user, or `65534:65534` (nobody) if afg itself runs as root.
    pub fn default_user() -> (u32, u32) {
        #[cfg(unix)]
        {
            let uid = rustix::process::getuid().as_raw();
            let gid = rustix::process::getgid().as_raw();
            if uid == 0 { (65534, 65534) } else { (uid, gid) }
        }
        #[cfg(not(unix))]
        {
            (65534, 65534)
        }
    }

    pub fn container_name(id: &str) -> String {
        let clean: String = id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(48)
            .collect();
        format!("afg-{clean}")
    }

    /// Check that the docker daemon answers, and return its version.
    pub async fn check_available(&self) -> Result<String, ExecutionError> {
        let f = run(Spawn {
            program: &self.cfg.docker.to_string_lossy(),
            args: &[
                "version".into(),
                "--format".into(),
                "{{.Server.Version}}".into(),
            ],
            cwd: Path::new("/"),
            env: &self.cfg.docker_env,
            timeout: Duration::from_secs(15),
            stream: false,
            capture_limit: 4096,
        })
        .await
        .map_err(|e| ExecutionError::Unavailable(format!("docker CLI: {e}")))?;
        if f.exit_code != Some(0) {
            return Err(ExecutionError::Unavailable(format!(
                "docker daemon not reachable: {}",
                String::from_utf8_lossy(&f.stderr.bytes).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&f.stdout.bytes).trim().to_owned())
    }

    /// The complete `docker` argv for a request (without the program).
    pub fn docker_args(
        &self,
        req: &ExecutionRequest,
        snapshot_dir: &Path,
        workdir: &str,
    ) -> Vec<String> {
        let c = &self.cfg;
        let mut a: Vec<String> = ["run", "--rm", "--init", "--interactive=false"]
            .map(String::from)
            .to_vec();
        a.push(format!("--name={}", Self::container_name(&req.id)));
        a.push(format!("--label=dev.agentforge.run={}", req.id));
        a.push(format!(
            "--network={}",
            match c.network {
                NetworkPolicy::None => "none",
                NetworkPolicy::Bridge => "bridge",
            }
        ));
        if c.read_only_rootfs {
            a.push("--read-only".into());
        }
        a.push("--tmpfs=/tmp:rw,nosuid,nodev,size=256m".into());
        a.push(format!("--memory={}m", c.limits.memory_mb));
        a.push(format!("--memory-swap={}m", c.limits.memory_mb));
        a.push(format!("--cpus={}", c.limits.cpus));
        a.push(format!("--pids-limit={}", c.limits.pids));
        a.push("--cap-drop=ALL".into());
        a.push("--security-opt=no-new-privileges".into());
        a.push(format!("--user={}:{}", c.user.0, c.user.1));
        a.push(format!(
            "--mount=type=bind,source={},target={WORKSPACE_MOUNT}",
            snapshot_dir.display()
        ));
        a.push(format!("--workdir={workdir}"));
        a.push("--env=HOME=/tmp".into());
        for (k, _) in &req.env {
            a.push(format!("--env={k}"));
        }
        a.push(format!("--entrypoint={}", req.argv[0]));
        a.push(c.image.clone());
        a.extend(req.argv[1..].iter().cloned());
        a
    }
}

fn validate_env_name(k: &str) -> Result<(), ExecutionError> {
    let ok = !k.is_empty()
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !k.starts_with(|c: char| c.is_ascii_digit())
        && !k.starts_with("DOCKER_");
    if ok {
        Ok(())
    } else {
        Err(ExecutionError::InvalidRequest(format!(
            "invalid container env name `{k}`"
        )))
    }
}

impl Executor for DockerExecutor {
    fn name(&self) -> &'static str {
        "container"
    }

    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        if req.argv.first().is_none_or(|a| a.is_empty()) {
            return Err(ExecutionError::InvalidRequest("empty argv".into()));
        }
        for (k, _) in &req.env {
            validate_env_name(k)?;
        }
        let root = req.workspace_root.canonicalize()?;
        let cwd = req.cwd.canonicalize()?;
        let rel = cwd.strip_prefix(&root).map_err(|_| {
            ExecutionError::InvalidRequest(format!(
                "working directory {} is outside the workspace {}",
                cwd.display(),
                root.display()
            ))
        })?;
        let workdir = if rel.as_os_str().is_empty() {
            WORKSPACE_MOUNT.to_owned()
        } else {
            format!("{WORKSPACE_MOUNT}/{}", rel.display())
        };

        let opts = self.cfg.snapshot.clone();
        let root2 = root.clone();
        let snapshot = tokio::task::spawn_blocking(move || build_snapshot(&root2, &opts))
            .await
            .map_err(|e| ExecutionError::Io(std::io::Error::other(e)))?
            .map_err(|e| ExecutionError::InvalidRequest(e.to_string()))?;
        crate::verify_pins_in_snapshot(&req, &root, snapshot.path())?;

        let args = self.docker_args(&req, snapshot.path(), &workdir);
        let mut env = self.cfg.docker_env.clone();
        env.extend(req.env.iter().cloned());
        let docker = self.cfg.docker.to_string_lossy().into_owned();
        let result = run(Spawn {
            program: &docker,
            args: &args,
            cwd: &root,
            env: &env,
            timeout: req.timeout,
            stream: req.stream,
            capture_limit: req.capture_limit,
        })
        .await;
        // Covers timeouts, where `--rm` never happens because the CLI was killed.
        let _ = self.cleanup(&req.id).await;
        let f = result?;
        Ok(ExecutionResult {
            exit_code: f.exit_code,
            timed_out: f.timed_out,
            duration_ms: f.duration_ms,
            stdout: f.stdout,
            stderr: f.stderr,
            details: vec![
                ("image".into(), self.cfg.image.clone()),
                ("container".into(), Self::container_name(&req.id)),
                ("snapshotManifest".into(), snapshot.manifest.hash.clone()),
                (
                    "snapshotFiles".into(),
                    snapshot.manifest.entries.len().to_string(),
                ),
            ],
        })
    }

    async fn cleanup(&self, id: &str) -> Result<(), ExecutionError> {
        let f = run(Spawn {
            program: &self.cfg.docker.to_string_lossy(),
            args: &["rm".into(), "--force".into(), Self::container_name(id)],
            cwd: Path::new("/"),
            env: &self.cfg.docker_env,
            timeout: Duration::from_secs(30),
            stream: false,
            capture_limit: 4096,
        })
        .await?;
        // A container that no longer exists is fine.
        let _ = f;
        Ok(())
    }
}

/// The location inside the container of a host path under the workspace.
pub fn container_path(root: &Path, host: &Path) -> Option<String> {
    snapshot_path(Path::new(WORKSPACE_MOUNT), root, host).map(|p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use afg_core::paths::ProtectedPaths;

    fn exec() -> DockerExecutor {
        DockerExecutor::new(DockerConfig {
            docker: "/usr/local/bin/docker".into(),
            docker_env: vec![],
            image: "debian:stable-slim".into(),
            network: NetworkPolicy::None,
            read_only_rootfs: true,
            limits: ResourceLimits {
                memory_mb: 512,
                cpus: 1.5,
                pids: 64,
            },
            user: (501, 20),
            snapshot: SnapshotOptions {
                protected: ProtectedPaths::new(None, Path::new("/"), &[]),
                max_total_bytes: 1 << 20,
                max_files: 10,
            },
        })
        .unwrap()
    }

    fn req() -> ExecutionRequest {
        ExecutionRequest {
            id: "run-1".into(),
            argv: vec!["sh".into(), "./check.sh".into(), "$(x)".into()],
            cwd: "/w".into(),
            workspace_root: "/w".into(),
            env: vec![("CI".into(), "true".into())],
            timeout: Duration::from_secs(5),
            pinned: vec![],
            stream: false,
            capture_limit: 100,
        }
    }

    #[test]
    fn hardened_argv() {
        let a = exec().docker_args(&req(), Path::new("/tmp/snap"), "/workspace/sub");
        let has = |s: &str| a.iter().any(|x| x == s);
        for flag in [
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=1.5",
            "--pids-limit=64",
            "--user=501:20",
            "--mount=type=bind,source=/tmp/snap,target=/workspace",
            "--workdir=/workspace/sub",
            "--env=CI",
            "--entrypoint=sh",
            "--name=afg-run-1",
        ] {
            assert!(has(flag), "missing {flag}: {a:?}");
        }
        assert!(
            !a.iter().any(|x| x.contains("CI=true")),
            "env values never on the command line"
        );
        assert!(!a.iter().any(|x| x.contains("docker.sock")));
        assert!(!a.iter().any(|x| x == "--privileged"));
        let img = a.iter().position(|x| x == "debian:stable-slim").unwrap();
        assert_eq!(
            &a[img + 1..],
            &["./check.sh".to_string(), "$(x)".to_string()]
        );
    }

    #[test]
    fn bridge_network_when_configured() {
        let mut e = exec();
        e.cfg.network = NetworkPolicy::Bridge;
        e.cfg.read_only_rootfs = false;
        let a = e.docker_args(&req(), Path::new("/s"), "/workspace");
        assert!(a.contains(&"--network=bridge".to_string()));
        assert!(!a.contains(&"--read-only".to_string()));
    }

    #[test]
    fn rejects_root_bad_image_and_relative_cli() {
        let mut cfg = exec().cfg;
        cfg.user = (0, 0);
        assert!(DockerExecutor::new(cfg.clone()).is_err());
        cfg.user = (1000, 1000);
        cfg.image = "--privileged".into();
        assert!(DockerExecutor::new(cfg.clone()).is_err());
        cfg.image = "alpine".into();
        cfg.docker = "docker".into();
        assert!(DockerExecutor::new(cfg).is_err());
    }

    #[test]
    fn env_names_validated() {
        assert!(validate_env_name("CI").is_ok());
        assert!(validate_env_name("DOCKER_HOST").is_err());
        assert!(validate_env_name("A=B").is_err());
        assert!(validate_env_name("1X").is_err());
    }

    #[test]
    fn container_names_are_sanitized() {
        assert_eq!(DockerExecutor::container_name("a/b c;d"), "afg-abcd");
    }
}
