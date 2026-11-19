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
use std::process::Stdio;
use std::time::Instant;

use crate::capture::capture;
use crate::{ExecutionError, ExecutionRequest, ExecutionResult, Executor};

#[derive(Debug, Default, Clone)]
pub struct LocalExecutor;

/// How long to wait for output pipes to drain after the process exits.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

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

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(&req.argv[1..])
            .current_dir(&req.cwd)
            .env_clear()
            .envs(req.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|source| ExecutionError::Spawn {
            program: program.clone(),
            source,
        })?;
        let pid = child.id();

        let out = child.stdout.take().expect("piped");
        let err = child.stderr.take().expect("piped");
        let limit = req.capture_limit;
        let (tee_out, tee_err) = if req.stream {
            (Some(tokio::io::stdout()), Some(tokio::io::stderr()))
        } else {
            (None, None)
        };
        let out_task = tokio::spawn(capture(out, limit, tee_out));
        let err_task = tokio::spawn(capture(err, limit, tee_err));

        let (status, timed_out) = match tokio::time::timeout(req.timeout, child.wait()).await {
            Ok(status) => (Some(status?), false),
            Err(_) => {
                kill_group(pid);
                let _ = child.kill().await;
                (child.wait().await.ok(), true)
            }
        };
        // Reap any background processes that the command left behind.
        kill_group(pid);

        let stdout = join_capture(out_task).await?;
        let stderr = join_capture(err_task).await?;
        Ok(ExecutionResult {
            exit_code: status.and_then(|s| s.code()),
            timed_out,
            duration_ms: start.elapsed().as_millis() as u64,
            stdout,
            stderr,
            details: vec![("program".into(), program.clone())],
        })
    }

    async fn cleanup(&self, _id: &str) -> Result<(), ExecutionError> {
        Ok(())
    }
}

async fn join_capture(
    task: tokio::task::JoinHandle<std::io::Result<crate::Captured>>,
) -> Result<crate::Captured, ExecutionError> {
    match tokio::time::timeout(DRAIN_GRACE, task).await {
        Ok(Ok(r)) => Ok(r?),
        Ok(Err(e)) => Err(ExecutionError::Io(std::io::Error::other(e))),
        Err(_) => Err(ExecutionError::Io(std::io::Error::other(
            "output pipe did not close",
        ))),
    }
}

#[cfg(unix)]
fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|p| rustix::process::Pid::from_raw(p as i32)) {
        // ESRCH (the group is already gone) is expected.
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
