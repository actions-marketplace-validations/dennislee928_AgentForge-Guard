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

pub fn run(cmd: HookCommand) -> anyhow::Result<ExitCode> {
    let HookCommand::ClaudePretool { allow_mode } = cmd;
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
