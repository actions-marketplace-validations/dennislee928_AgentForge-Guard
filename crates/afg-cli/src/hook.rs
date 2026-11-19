//! `afg hook claude-pretool`: Claude Code PreToolUse integration
//! (integration mode; docs/security-boundaries.md).
//!
//! It reads the hook JSON on stdin. For `Bash` calls it evaluates
//! `tool_input.command` with the same engine as `afg run`
//! (`Engine::evaluate_shell`) and prints a `hookSpecificOutput` decision:
//!
//! | afg effect         | Claude Code decision                                   |
//! |--------------------|--------------------------------------------------------|
//! | `deny`             | `deny`                                                 |
//! | `require-approval` | `ask`                                                  |
//! | `route`            | `deny`, with guidance to use `afg run -- <command>`    |
//! | `allow`            | no output, so Claude Code's own permissions decide (`--allow-mode defer`, the default), or `allow` with `--allow-mode allow` |
//!
//! Errors fail closed: a missing or invalid policy, unreadable input or an
//! audit failure all produce `deny`. Other tools produce no output.

use std::io::Read;
use std::process::ExitCode;

use afg_core::{Effect, ShellDecision};
use afg_report::audit::new_id;
use afg_report::{AuditLog, AuditRecord};
use serde::Deserialize;
use serde_json::json;

use crate::project;

/// The maximum hook input size that is accepted.
const MAX_INPUT: u64 = 1 << 20;

#[derive(Debug, clap::Subcommand)]
pub enum HookCommand {
    /// The Claude Code PreToolUse hook for the Bash tool.
    ClaudePretool {
        /// What to do when afg allows the command.
        #[arg(long, value_enum, default_value_t = AllowMode::Defer)]
        allow_mode: AllowMode,
    },
    /// The Claude Code PostToolUse hook: format files after Edit/Write.
    ClaudePosttoolFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AllowMode {
    /// Print nothing, so Claude Code's own permission rules decide.
    Defer,
    /// Grant the call (`permissionDecision: allow`).
    Allow,
}

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
    #[serde(default)]
    cwd: Option<String>,
}

pub async fn run(cmd: HookCommand) -> anyhow::Result<ExitCode> {
    let allow_mode = match cmd {
        HookCommand::ClaudePretool { allow_mode } => allow_mode,
        HookCommand::ClaudePosttoolFormat => {
            let mut buf = String::new();
            let _ = std::io::stdin().take(MAX_INPUT).read_to_string(&mut buf);
            return Ok(posttool_format(&buf).await);
        }
    };
    let mut buf = String::new();
    if std::io::stdin()
        .take(MAX_INPUT)
        .read_to_string(&mut buf)
        .is_err()
    {
        emit("deny", "afg: could not read hook input");
        return Ok(ExitCode::SUCCESS);
    }
    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(i) => i,
        Err(e) => {
            emit("deny", &format!("afg: invalid hook input: {e}"));
            return Ok(ExitCode::SUCCESS);
        }
    };
    if input.tool_name != "Bash" {
        return Ok(ExitCode::SUCCESS);
    }
    let Some(command) = input.tool_input.get("command").and_then(|c| c.as_str()) else {
        emit("deny", "afg: Bash call without a command");
        return Ok(ExitCode::SUCCESS);
    };
    match decide(command, input.cwd.as_deref()) {
        Ok((d, reason)) => match (d.effect, allow_mode) {
            (Effect::Allow, AllowMode::Defer) => {}
            (Effect::Allow, AllowMode::Allow) => emit("allow", &reason),
            (Effect::RequireApproval, _) => emit("ask", &reason),
            (Effect::Deny | Effect::Route, _) => emit("deny", &reason),
        },
        Err(e) => emit("deny", &format!("afg: {e:#} (failing closed)")),
    }
    Ok(ExitCode::SUCCESS)
}

/// Evaluate a command string and audit every part. Returns the decision and
/// a reason for the agent.
pub fn decide(command: &str, cwd: Option<&str>) -> anyhow::Result<(ShellDecision, String)> {
    let cwd = match cwd {
        Some(c) => std::path::PathBuf::from(c),
        None => std::env::current_dir()?,
    };
    let cwd = cwd.canonicalize()?;
    let p = project::load(&cwd)?;
    if let Some(why) = p.untrusted_reason() {
        anyhow::bail!("{why}");
    }
    let path = std::env::var_os("PATH");
    let d = p.engine.evaluate_shell(command, &cwd, path.as_deref());

    let policy = p.engine.policy();
    let log = AuditLog::open(&p.root.join(&policy.audit.dir), policy.audit.redact_secrets)?;
    for part in &d.parts {
        log.append(&AuditRecord::from_decision(
            new_id(),
            "hook:claude-code",
            &cwd,
            part,
        ))?;
    }

    let reason = match (d.effect, d.decisive()) {
        (Effect::Route, Some(x)) => format!(
            "afg: `{}` must run in an isolated {} backend (rule `{}`). Run it through afg instead: afg run -- <command>",
            x.normalized.original.join(" "),
            x.backend.map(|b| b.to_string()).unwrap_or_default(),
            x.rule_id
        ),
        (e, Some(x)) => format!(
            "afg: {e} by rule `{}` for `{}`: {}",
            x.rule_id,
            x.normalized.original.join(" "),
            x.reasons.join("; ")
        ),
        (e, None) => format!(
            "afg: {e}: {}",
            d.unparseable.as_deref().unwrap_or("no command")
        ),
    };
    Ok((d, reason))
}

fn emit(decision: &str, reason: &str) {
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    println!("{out}");
}

/// The formatter argv for a file, chosen by extension. `None` means the
/// file type has no built-in formatter.
pub fn formatter_for(path: &std::path::Path) -> Option<Vec<String>> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let file = path.to_string_lossy().into_owned();
    let argv: Vec<&str> = match ext.as_str() {
        "rs" => vec!["rustfmt", "--edition", "2024"],
        "go" => vec!["gofmt", "-w"],
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "css" | "scss" | "json" | "md" | "yaml"
        | "yml" => {
            vec!["pnpm", "prettier", "--write"]
        }
        _ => return None,
    };
    Some(
        argv.into_iter()
            .map(String::from)
            .chain(std::iter::once(file))
            .collect(),
    )
}

/// `afg hook claude-posttool-format`: run after Claude Code finishes an
/// Edit or Write tool operation (not an editor "on save" event). The
/// formatter command is itself evaluated by the policy and runs only if it
/// is allowed on the local backend. A PostToolUse hook cannot undo the edit,
/// so this hook never blocks; problems are reported on stderr.
pub async fn posttool_format(buf: &str) -> ExitCode {
    let Ok(input) = serde_json::from_str::<HookInput>(buf) else {
        return ExitCode::SUCCESS;
    };
    if !matches!(input.tool_name.as_str(), "Edit" | "Write" | "MultiEdit") {
        return ExitCode::SUCCESS;
    }
    let Some(file) = input.tool_input.get("file_path").and_then(|f| f.as_str()) else {
        return ExitCode::SUCCESS;
    };
    if let Err(e) = format_file(file, input.cwd.as_deref()).await {
        eprintln!("afg: formatter skipped for {file}: {e:#}");
    }
    ExitCode::SUCCESS
}

async fn format_file(file: &str, cwd: Option<&str>) -> anyhow::Result<()> {
    use afg_core::{BackendKind, EvalRequest};
    use afg_executor::{ExecutionRequest, Executor, LocalExecutor};

    let cwd = match cwd {
        Some(c) => std::path::PathBuf::from(c),
        None => std::env::current_dir()?,
    }
    .canonicalize()?;
    let p = project::load(&cwd)?;
    let path = cwd.join(file).canonicalize()?;
    anyhow::ensure!(path.starts_with(&p.root), "file is outside the project");
    let Some(argv) = formatter_for(&path) else {
        return Ok(());
    };
    let path_env = std::env::var_os("PATH");
    let d = p.engine.evaluate(&EvalRequest {
        argv: &argv,
        cwd: &cwd,
        path_env: path_env.as_deref(),
        requested_backend: None,
    });
    let policy = p.engine.policy();
    let log = AuditLog::open(&p.root.join(&policy.audit.dir), policy.audit.redact_secrets)?;
    let mut rec = AuditRecord::from_decision(new_id(), "hook:claude-code:format", &cwd, &d);
    if d.effect != Effect::Allow || d.backend != Some(BackendKind::Local) {
        log.append(&rec)?;
        anyhow::bail!("`{}` is {} by rule `{}`", argv[0], d.effect, d.rule_id);
    }
    let Some(program) = d.normalized.program.clone() else {
        log.append(&rec)?;
        anyhow::bail!("`{}` is not installed", argv[0]);
    };
    let local = &policy.execution.backends.local;
    let res = LocalExecutor
        .execute(ExecutionRequest {
            id: rec.id.clone(),
            argv: d.normalized.exec_argv.clone(),
            arg0: d.normalized.inner_argv.first().cloned(),
            cwd: cwd.clone(),
            workspace_root: p.root.clone(),
            env: crate::backends::host_env(&local.env),
            timeout: std::time::Duration::from_secs(60.min(local.timeout_seconds)),
            pinned: afg_executor::pin::pin_request_files(Some(&program), &[], &cwd, &p.root),
            stream: false,
            capture_limit: 16 * 1024,
        })
        .await;
    match res {
        Ok(r) => {
            rec.execution = Some(crate::run::execution_record(&r));
            log.append(&rec)?;
            if !r.success() {
                anyhow::bail!("{}", String::from_utf8_lossy(&r.stderr.bytes).trim());
            }
        }
        Err(e) => {
            rec.error = Some(e.to_string());
            log.append(&rec)?;
            return Err(e.into());
        }
    }
    Ok(())
}
