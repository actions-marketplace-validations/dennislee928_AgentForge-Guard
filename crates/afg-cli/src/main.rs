//! `afg`: the AgentForge Guard command-line interface.
//!
//! Exit codes:
//! - `0`: success, or the command's own exit code for `afg run`.
//! - `2`: usage or configuration error.
//! - `124`: `afg run` timed out.
//! - `125`: afg failed to execute an approved command (for example, Docker is missing).
//! - `126`: denied by policy, or approval was refused.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod agents;
mod approval;
mod audit_cmd;
mod backends;
mod doctor;
mod hook;
mod init;
mod policy_cmd;
mod project;
mod run;

pub const POLICY_FILE: &str = "agentforge.yaml";

pub const EXIT_CONFIG: u8 = 2;
pub const EXIT_TIMEOUT: u8 = 124;
pub const EXIT_EXEC_ERROR: u8 = 125;
pub const EXIT_DENIED: u8 = 126;

#[derive(Debug, Parser)]
#[command(
    name = "afg",
    version,
    about = "Policy-driven execution guard for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create agentforge.yaml for this repository from detection results.
    Init(init::InitArgs),
    /// Show detected projects, policy decisions, backend status and risks.
    Doctor(doctor::DoctorArgs),
    /// Explain decisions, validate a policy or print its schema.
    #[command(subcommand)]
    Policy(policy_cmd::PolicyCommand),
    /// Run a command under the policy (managed mode).
    Run(run::RunArgs),
    /// Read the audit log.
    #[command(subcommand)]
    Audit(audit_cmd::AuditCommand),
    /// Agent integration hooks (integration mode).
    #[command(subcommand)]
    Hook(hook::HookCommand),
    /// Generate coding-agent configuration from the policy.
    #[command(subcommand)]
    Agents(agents::AgentsCommand),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("afg: error: starting runtime: {e}");
            return ExitCode::from(EXIT_EXEC_ERROR);
        }
    };
    let result = match cli.command {
        Command::Init(a) => init::run(a),
        Command::Doctor(a) => rt.block_on(doctor::run(a)),
        Command::Policy(c) => policy_cmd::run(c),
        Command::Run(a) => rt.block_on(run::run(a)),
        Command::Audit(c) => audit_cmd::run(c),
        Command::Hook(c) => rt.block_on(hook::run(c)),
        Command::Agents(c) => agents::run(c),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("afg: error: {e:#}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}
