//! `afg policy explain | validate | schema`.

use std::path::PathBuf;
use std::process::ExitCode;

use afg_core::validate::{Severity, validate};
use afg_core::{BackendKind, Decision, EvalRequest, Policy};
use anyhow::Context;

use crate::project;

#[derive(Debug, clap::Subcommand)]
pub enum PolicyCommand {
    /// Show the decision for a command without running it.
    Explain(ExplainArgs),
    /// Check a policy file for errors and warnings.
    Validate(ValidateArgs),
    /// Print the JSON Schema for agentforge.yaml.
    Schema,
    /// Pin the current policy (run by a human after reviewing it). Later
    /// edits to the policy deny every command until it is trusted again.
    Trust,
    /// Upgrade agentforge.yaml to the latest apiVersion (agentforge.dev/v1).
    Migrate {
        /// Write the file. Without this, the migrated policy is printed.
        #[arg(long)]
        write: bool,
    },
}

#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Print the decision as JSON.
    #[arg(long)]
    pub json: bool,
    /// The isolation to request. It can only make isolation stronger.
    #[arg(long, value_enum)]
    pub isolation: Option<Isolation>,
    /// The command to explain, after `--`.
    #[arg(last = true, required = true)]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Isolation {
    Local,
    Container,
}

impl From<Isolation> for BackendKind {
    fn from(i: Isolation) -> Self {
        match i {
            Isolation::Local => BackendKind::Local,
            Isolation::Container => BackendKind::Container,
        }
    }
}

#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// The policy file (default: the nearest agentforge.yaml).
    #[arg(long)]
    pub file: Option<PathBuf>,
}

pub fn run(cmd: PolicyCommand) -> anyhow::Result<ExitCode> {
    match cmd {
        PolicyCommand::Explain(a) => explain(a),
        PolicyCommand::Validate(a) => validate_cmd(a),
        PolicyCommand::Trust => {
            let cwd = std::env::current_dir()?.canonicalize()?;
            let p = project::load(&cwd)?;
            let home = project::home_dir().context("no home directory")?;
            let path = crate::trust::pin(&home, &p.policy_path, p.engine.policy_hash())?;
            eprintln!(
                "afg: trusted {} ({}) -> {}",
                p.policy_path.display(),
                p.engine.policy_hash(),
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommand::Migrate { write } => migrate(write),
        PolicyCommand::Schema => {
            print!("{}", afg_core::schema::policy_schema_json());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn explain(a: ExplainArgs) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let p = project::load(&cwd)?;
    let path = std::env::var_os("PATH");
    let d = p.engine.evaluate(&EvalRequest {
        argv: &a.argv,
        cwd: &cwd,
        path_env: path.as_deref(),
        requested_backend: a.isolation.map(Into::into),
    });
    if a.json {
        println!("{}", serde_json::to_string_pretty(&d)?);
    } else {
        print_decision(&d);
    }
    Ok(ExitCode::SUCCESS)
}

/// Print a decision for people. Arguments are quoted with `{:?}` so that
/// control characters and escape sequences cannot mislead the reader.
pub fn print_decision(d: &Decision) {
    println!("decision  {}", d.effect);
    println!(
        "backend   {}",
        d.backend
            .map(|b| b.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!("rule      {}", d.rule_id);
    println!("argv      {}", quote_argv(&d.normalized.original));
    if let Some(p) = &d.normalized.program {
        println!("program   {}", p.display());
    }
    if !d.normalized.wrappers.is_empty() {
        println!("wrappers  {}", d.normalized.wrappers.join(", "));
    }
    println!("policy    {} {}", d.policy_version, d.policy_hash);
    for r in &d.reasons {
        println!("  - {r}");
    }
}

pub fn quote_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_cmd(a: ValidateArgs) -> anyhow::Result<ExitCode> {
    let path = match a.file {
        Some(f) => f,
        None => {
            let cwd = std::env::current_dir()?.canonicalize()?;
            project::find_root(&cwd)
                .map(|r| r.join(crate::POLICY_FILE))
                .context("no agentforge.yaml found; pass --file")?
        }
    };
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let policy = match Policy::from_yaml(&src) {
        Ok(p) => p,
        Err(e) => {
            println!("{}: error: {e}", path.display());
            return Ok(ExitCode::from(1));
        }
    };
    let issues = validate(&policy);
    for i in &issues {
        println!("{}: {i}", path.display());
    }
    if issues.iter().any(|i| i.severity == Severity::Error) {
        return Ok(ExitCode::from(1));
    }
    println!("{}: ok ({} warnings)", path.display(), issues.len());
    Ok(ExitCode::SUCCESS)
}

fn migrate(write: bool) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let root = project::find_root(&cwd).context("no agentforge.yaml found")?;
    let path = root.join(crate::POLICY_FILE);
    let src = std::fs::read_to_string(&path)?;
    let Some(new) = afg_core::policy::migrate_text(&src) else {
        eprintln!(
            "afg: {} is already at {}",
            path.display(),
            afg_core::policy::ApiVersion::LATEST.as_str()
        );
        return Ok(ExitCode::SUCCESS);
    };
    let old_policy = Policy::from_yaml(&src)?;
    let new_policy = Policy::from_yaml(&new).context("migrated policy does not parse")?;
    let issues = validate(&new_policy);
    if issues.iter().any(|i| i.severity == Severity::Error) {
        anyhow::bail!("migrated policy is invalid: {issues:?}");
    }
    if !write {
        print!("{new}");
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::write(&path, &new)?;
    eprintln!(
        "afg: migrated {} to {}",
        path.display(),
        afg_core::policy::ApiVersion::LATEST.as_str()
    );
    // Re-pin only if the policy was trusted before; the change was mechanical.
    let home = project::home_dir();
    let old_hash = afg_core::eval::policy_hash(&old_policy);
    if let Some(h) = home.as_deref()
        && crate::trust::status(Some(h), &path, &old_hash) == crate::trust::Status::Trusted
    {
        crate::trust::pin(h, &path, &afg_core::eval::policy_hash(&new_policy))?;
        eprintln!("  the policy was trusted, so the migrated version is trusted too");
    }
    Ok(ExitCode::SUCCESS)
}
