//! `afg run`: managed-mode execution.
//!
//! The steps are evaluate → (approve) → route → pin → execute → audit. Every
//! outcome is audited, including denials and errors. Execution never starts
//! unless the audit log can be opened.

use std::process::ExitCode;
use std::time::Duration;

use afg_core::{BackendKind, Decision, Effect, EvalRequest};
use afg_executor::pin::pin_request_files;
use afg_executor::{
    Captured, ExecutionError, ExecutionRequest, ExecutionResult, Executor, LocalExecutor,
};
use afg_report::audit::{ExecutionRecord, StreamRecord, new_id};
use afg_report::{AuditLog, AuditRecord};
use anyhow::Context;

use crate::backends::{docker_executor, host_env};
use crate::policy_cmd::{Isolation, quote_argv};
use crate::project::{self, home_dir};
use crate::{EXIT_DENIED, EXIT_EXEC_ERROR, EXIT_TIMEOUT};

/// Exit code when the executable does not exist (shell convention).
pub const EXIT_NOT_FOUND: u8 = 127;

/// The maximum number of output bytes kept in memory for each stream.
const CAPTURE_LIMIT: usize = 64 * 1024;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// The isolation to request. It can make isolation stronger, never weaker.
    #[arg(long, value_enum)]
    pub isolation: Option<Isolation>,
    /// Don't print the decision summary on stderr.
    #[arg(long, short)]
    pub quiet: bool,
    /// The command to run, after `--`.
    #[arg(last = true, required = true)]
    pub argv: Vec<String>,
}

pub async fn run(a: RunArgs) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let p = project::load(&cwd)?;
    let policy = p.engine.policy();
    let audit_dir = p.root.join(&policy.audit.dir);
    let audit = AuditLog::open(&audit_dir, policy.audit.redact_secrets)
        .with_context(|| format!("opening the audit log at {}", audit_dir.display()))?;

    let path = std::env::var_os("PATH");
    let d = p.engine.evaluate(&EvalRequest {
        argv: &a.argv,
        cwd: &cwd,
        path_env: path.as_deref(),
        requested_backend: a.isolation.map(Into::into),
    });
    let mut rec = AuditRecord::from_decision(new_id(), "run", &cwd, &d);

    match d.effect {
        Effect::Deny => {
            eprintln!(
                "afg: denied by `{}`: {}",
                d.rule_id,
                quote_argv(&d.normalized.original)
            );
            for r in &d.reasons {
                eprintln!("  - {r}");
            }
            audit.append(&rec)?;
            return Ok(ExitCode::from(EXIT_DENIED));
        }
        Effect::RequireApproval => {
            let outcome = crate::approval::request(&d, &cwd);
            rec.approval = Some(outcome.record());
            if !outcome.approved() {
                eprintln!("afg: not approved: {}", outcome.reason());
                audit.append(&rec)?;
                return Ok(ExitCode::from(EXIT_DENIED));
            }
        }
        Effect::Allow | Effect::Route => {}
    }
    let backend = d.backend.expect("non-deny decisions carry a backend");
    if !a.quiet {
        eprintln!("afg: {} by `{}` → {backend}", d.effect, d.rule_id);
    }

    let outcome = execute(&p, &d, backend, &cwd, &rec.id).await;
    let code = match &outcome {
        Ok(r) => {
            rec.execution = Some(execution_record(r));
            if r.timed_out {
                eprintln!("afg: timed out");
                EXIT_TIMEOUT
            } else {
                r.exit_code
                    .map(|c| c.clamp(0, 255) as u8)
                    .unwrap_or(EXIT_EXEC_ERROR)
            }
        }
        Err(e) => {
            rec.error = Some(e.to_string());
            eprintln!("afg: {e}");
            match e {
                RunError::NotFound(_) => EXIT_NOT_FOUND,
                RunError::Exec(ExecutionError::Integrity(_)) => EXIT_DENIED,
                _ => EXIT_EXEC_ERROR,
            }
        }
    };
    audit.append(&rec).context("writing the audit record")?;
    Ok(ExitCode::from(code))
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error("executable `{0}` not found on PATH")]
    NotFound(String),
    #[error(transparent)]
    Exec(#[from] ExecutionError),
    #[error("{0:#}")]
    Setup(anyhow::Error),
}

async fn execute(
    p: &project::Project,
    d: &Decision,
    backend: BackendKind,
    cwd: &std::path::Path,
    id: &str,
) -> Result<ExecutionResult, RunError> {
    let policy = p.engine.policy();
    let n = &d.normalized;
    match backend {
        BackendKind::Local => {
            let Some(program) = &n.program else {
                return Err(RunError::NotFound(n.name.clone()));
            };
            let local = &policy.execution.backends.local;
            let req = ExecutionRequest {
                id: id.to_owned(),
                argv: n.exec_argv.clone(),
                cwd: n.cwd.clone(),
                workspace_root: p.root.clone(),
                env: host_env(&local.env),
                timeout: Duration::from_secs(local.timeout_seconds),
                pinned: pin_request_files(Some(program), &n.args, cwd, &p.root),
                stream: true,
                capture_limit: CAPTURE_LIMIT,
            };
            Ok(LocalExecutor.execute(req).await?)
        }
        BackendKind::Container => {
            let docker =
                docker_executor(policy, &p.root, home_dir().as_deref()).map_err(RunError::Setup)?;
            let c = &policy.execution.backends.container;
            let req = ExecutionRequest {
                id: id.to_owned(),
                argv: n.inner_argv.clone(),
                cwd: n.cwd.clone(),
                workspace_root: p.root.clone(),
                env: host_env(&c.env),
                timeout: Duration::from_secs(c.timeout_seconds),
                // The host program does not apply inside the container; pin
                // only the workspace files.
                pinned: pin_request_files(None, &n.args, cwd, &p.root),
                stream: true,
                capture_limit: CAPTURE_LIMIT,
            };
            Ok(docker.execute(req).await?)
        }
        BackendKind::Cloudflare => Err(RunError::Exec(ExecutionError::Unavailable(
            "the cloudflare backend is not implemented in this version".into(),
        ))),
    }
}

fn stream_record(c: &Captured) -> StreamRecord {
    StreamRecord {
        len: c.total_len,
        sha256: c.sha256.clone(),
        truncated: c.truncated,
    }
}

fn execution_record(r: &ExecutionResult) -> ExecutionRecord {
    ExecutionRecord {
        exit_code: r.exit_code,
        timed_out: r.timed_out,
        duration_ms: r.duration_ms,
        stdout: stream_record(&r.stdout),
        stderr: stream_record(&r.stderr),
        details: r.details.clone(),
    }
}
