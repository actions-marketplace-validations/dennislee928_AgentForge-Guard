//! The local backend: runs an approved argv directly on the host.
//!
//! - There is no shell. `argv[0]` must be an absolute path that `afg-core`
//!   resolved.
//! - The environment is cleared; only `ExecutionRequest::env` is set.
//! - stdin is closed.
//! - On Unix the child leads its own process group. When it exits or times
//!   out the whole group is killed, so background grandchildren cannot
//!   outlive the run.

use std::path::Path;

use crate::process::{Spawn, run};
use crate::{ExecutionError, ExecutionRequest, ExecutionResult, Executor};

#[derive(Debug, Default, Clone)]
pub struct LocalExecutor;

impl Executor for LocalExecutor {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        let Some(program) = req.argv.first() else {
            return Err(ExecutionError::InvalidRequest("empty argv".into()));
        };
        if !Path::new(program).is_absolute() {
            return Err(ExecutionError::InvalidRequest(format!(
                "program `{program}` must be resolved to an absolute path before execution"
            )));
        }
        crate::verify_pins(&req)?;
        let f = run(Spawn {
            program,
            args: &req.argv[1..],
            cwd: &req.cwd,
            env: &req.env,
            timeout: req.timeout,
            stream: req.stream,
            capture_limit: req.capture_limit,
        })
        .await?;
        Ok(ExecutionResult {
            exit_code: f.exit_code,
            timed_out: f.timed_out,
            duration_ms: f.duration_ms,
            stdout: f.stdout,
            stderr: f.stderr,
            details: vec![("program".into(), program.clone())],
        })
    }

    async fn cleanup(&self, _id: &str) -> Result<(), ExecutionError> {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn req(argv: &[&str]) -> ExecutionRequest {
        ExecutionRequest {
            id: "t".into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: std::env::temp_dir(),
            workspace_root: std::env::temp_dir(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            timeout: Duration::from_secs(10),
            pinned: vec![],
            stream: false,
            capture_limit: 1 << 20,
        }
    }

    #[tokio::test]
    async fn runs_and_captures() {
        let r = LocalExecutor
            .execute(req(&["/bin/echo", "hello", "$(id)"]))
            .await
            .unwrap();
        assert!(r.success());
        assert_eq!(r.stdout.bytes, b"hello $(id)\n", "no shell expansion");
    }

    #[tokio::test]
    async fn exit_code_passes_through() {
        let r = LocalExecutor
            .execute(req(&["/bin/sh", "-c", "exit 7"]))
            .await
            .unwrap();
        assert_eq!(r.exit_code, Some(7));
    }

    #[tokio::test]
    async fn environment_is_cleared() {
        let r = LocalExecutor.execute(req(&["/usr/bin/env"])).await.unwrap();
        let env = String::from_utf8_lossy(&r.stdout.bytes);
        assert_eq!(env.trim(), "PATH=/usr/bin:/bin");
    }

    #[tokio::test]
    async fn relative_program_rejected() {
        let e = LocalExecutor
            .execute(req(&["echo", "x"]))
            .await
            .unwrap_err();
        assert!(matches!(e, ExecutionError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn timeout_kills_process_group() {
        let marker = std::env::temp_dir().join(format!("afg-local-timeout-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!("(sleep 2; touch {}) & sleep 30", marker.display());
        let mut r = req(&["/bin/sh", "-c", &script]);
        r.timeout = Duration::from_millis(300);
        let start = Instant::now();
        let res = LocalExecutor.execute(r).await.unwrap();
        assert!(res.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!marker.exists(), "background child survived the group kill");
    }

    #[tokio::test]
    async fn background_children_do_not_hang_the_run() {
        let mut r = req(&["/bin/sh", "-c", "sleep 30 & echo done"]);
        r.timeout = Duration::from_secs(20);
        let start = Instant::now();
        let res = LocalExecutor.execute(r).await.unwrap();
        assert!(res.success());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn stdin_is_closed() {
        let r = LocalExecutor.execute(req(&["/bin/cat"])).await.unwrap();
        assert!(r.success());
        assert!(r.stdout.bytes.is_empty());
    }

    #[tokio::test]
    async fn modified_script_is_not_run() {
        let dir = std::env::temp_dir().join(format!("afg-local-toctou-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("check.sh");
        let marker = dir.join("ran");
        std::fs::write(&script, "echo safe\n").unwrap();
        let pin = crate::PinnedFile::pin(&script).unwrap();
        // The agent swaps the script after the decision.
        std::fs::write(&script, format!("touch {}\n", marker.display())).unwrap();
        let mut r = req(&["/bin/sh", script.to_str().unwrap()]);
        r.pinned = vec![pin];
        let e = LocalExecutor.execute(r).await.unwrap_err();
        assert!(matches!(e, ExecutionError::Integrity(_)), "{e}");
        assert!(!marker.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn unchanged_pins_run() {
        let dir = std::env::temp_dir().join(format!("afg-local-pinok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("ok.sh");
        std::fs::write(&script, "echo ok\n").unwrap();
        let mut r = req(&["/bin/sh", script.to_str().unwrap()]);
        r.pinned = vec![
            crate::PinnedFile::pin(&script).unwrap(),
            crate::PinnedFile::pin(std::path::Path::new("/bin/sh")).unwrap(),
        ];
        assert!(LocalExecutor.execute(r).await.unwrap().success());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
