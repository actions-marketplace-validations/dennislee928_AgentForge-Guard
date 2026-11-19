//! `afg audit tail | show`.

use std::process::ExitCode;

use afg_report::{AuditLog, AuditRecord};
use anyhow::bail;

use crate::policy_cmd::quote_argv;
use crate::project;

#[derive(Debug, clap::Subcommand)]
pub enum AuditCommand {
    /// Show the most recent records.
    Tail {
        /// The number of records to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Print JSON lines.
        #[arg(long)]
        json: bool,
    },
    /// Show one record in full, by id or unique id prefix.
    Show { id: String },
    /// Summarize the audit log as JSON, or as SARIF 2.1.0 for code scanning.
    Report {
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
        /// Write to this file instead of stdout.
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ReportFormat {
    Json,
    Sarif,
}

pub fn run(cmd: AuditCommand) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let p = project::load(&cwd)?;
    let policy = p.engine.policy();
    let log = AuditLog::open(&p.root.join(&policy.audit.dir), policy.audit.redact_secrets)?;
    match cmd {
        AuditCommand::Tail { lines, json } => {
            for r in log.tail(lines)? {
                if json {
                    println!("{}", serde_json::to_string(&r)?);
                } else {
                    println!("{}", summary(&r));
                }
            }
        }
        AuditCommand::Report { format, output } => {
            let records = log.read_all()?;
            let v = match format {
                ReportFormat::Json => afg_report::sarif::summary(&records),
                ReportFormat::Sarif => {
                    let text = std::fs::read_to_string(&p.policy_path).unwrap_or_default();
                    let uri = p
                        .policy_path
                        .strip_prefix(&p.root)
                        .map(|r| r.display().to_string())
                        .unwrap_or_else(|_| crate::POLICY_FILE.to_owned());
                    afg_report::sarif::sarif(&records, &text, &uri)
                }
            };
            let s = serde_json::to_string_pretty(&v)? + "\n";
            match output {
                Some(path) => std::fs::write(&path, s)?,
                None => print!("{s}"),
            }
        }
        AuditCommand::Show { id } => match log.find(&id)? {
            Some(r) => println!("{}", serde_json::to_string_pretty(&r)?),
            None => bail!("no single audit record matches `{id}`"),
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn summary(r: &AuditRecord) -> String {
    let outcome = match (&r.execution, &r.error, &r.approval) {
        (Some(x), _, _) if x.timed_out => "timeout".to_owned(),
        (Some(x), _, _) => format!(
            "exit {}",
            x.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into())
        ),
        (None, Some(_), _) => "error".to_owned(),
        (None, None, Some(a)) if !a.approved => "not approved".to_owned(),
        _ => "-".to_owned(),
    };
    let backend = r
        .decision
        .backend
        .map(|b| b.to_string())
        .unwrap_or_else(|| "-".into());
    format!(
        "{}  {}  {:<16} {:<9} {:<13} {:<26} {}",
        &r.id[..r.id.len().min(12)],
        r.timestamp,
        r.decision.effect.to_string(),
        backend,
        outcome,
        r.decision.rule_id,
        quote_argv(&r.argv)
    )
}
