//! Process spawning shared by every backend: no shell, a cleared
//! environment, closed stdin, bounded capture and a process-group kill.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::capture::capture;
use crate::{Captured, ExecutionError};

pub struct Spawn<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub cwd: &'a Path,
    pub env: &'a [(String, String)],
    pub timeout: Duration,
    pub stream: bool,
    pub capture_limit: usize,
}

pub struct Finished {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: Captured,
    pub stderr: Captured,
}

/// How long to wait for output pipes to drain after the process exits.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

pub async fn run(s: Spawn<'_>) -> Result<Finished, ExecutionError> {
    let mut cmd = tokio::process::Command::new(s.program);
    cmd.args(s.args)
        .current_dir(s.cwd)
        .env_clear()
        .envs(s.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(|source| ExecutionError::Spawn {
        program: s.program.to_owned(),
        source,
    })?;
    let pid = child.id();

    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let (tee_out, tee_err) = if s.stream {
        (Some(tokio::io::stdout()), Some(tokio::io::stderr()))
    } else {
        (None, None)
    };
    let out_task = tokio::spawn(capture(out, s.capture_limit, tee_out));
    let err_task = tokio::spawn(capture(err, s.capture_limit, tee_err));

    let (status, timed_out) = match tokio::time::timeout(s.timeout, child.wait()).await {
        Ok(status) => (Some(status?), false),
        Err(_) => {
            kill_group(pid);
            let _ = child.kill().await;
            (child.wait().await.ok(), true)
        }
    };
    // Reap any background processes that the command left behind.
    kill_group(pid);

    Ok(Finished {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        timed_out,
        duration_ms: start.elapsed().as_millis() as u64,
        stdout: join_capture(out_task).await?,
        stderr: join_capture(err_task).await?,
    })
}

async fn join_capture(
    task: tokio::task::JoinHandle<std::io::Result<Captured>>,
) -> Result<Captured, ExecutionError> {
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
