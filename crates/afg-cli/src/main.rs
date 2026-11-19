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

mod init;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init(a) => init::run(a),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("afg: error: {e:#}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}
