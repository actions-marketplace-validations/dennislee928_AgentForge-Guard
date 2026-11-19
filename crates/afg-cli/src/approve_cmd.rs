//! `afg approve`: a human approves a pending request from their own terminal.
//! afg refuses to run itself, so an agent confined to afg cannot reach this
//! command.

use std::io::{BufRead, BufReader, Write};
use std::process::ExitCode;

use anyhow::{Context, bail};

use crate::policy_cmd::quote_argv;
use crate::project::{self, home_dir};
use crate::tokens;

#[derive(Debug, clap::Args)]
pub struct ApproveArgs {
    /// The pending request id that `afg run` printed. Omit it to list
    /// pending requests.
    pub id: Option<String>,
    /// Approve without the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(a: ApproveArgs) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let p = project::load(&cwd)?;
    let dir = tokens::approvals_dir(&p.root, &p.engine.policy().audit.dir);
    let pending = tokens::list_pending(&dir);
    let Some(id) = a.id else {
        if pending.is_empty() {
            println!("no pending approvals");
        }
        for r in &pending {
            println!(
                "{}  {:<22} {:<9} {}",
                r.id,
                r.rule_id,
                r.backend,
                quote_argv(&r.argv)
            );
        }
        return Ok(ExitCode::SUCCESS);
    };
    let Some(req) = pending.iter().find(|r| r.id == id) else {
        bail!("no pending approval `{id}` (see `afg approve`)");
    };
    if !a.yes {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("confirmation needs a terminal; pass --yes to skip it")?;
        let mut out = tty.try_clone()?;
        write!(
            out,
            "approve {}\n  rule     {}\n  cwd      {:?}\n  backend  {}\nType `yes` to approve: ",
            quote_argv(&req.argv),
            req.rule_id,
            req.cwd,
            req.backend
        )?;
        out.flush()?;
        let mut line = String::new();
        BufReader::new(tty).read_line(&mut line)?;
        if !crate::approval::is_yes(&line) {
            bail!("not approved");
        }
    }
    let home = home_dir().context("no home directory for the approval key")?;
    tokens::approve(&dir, &home, &id)?;
    eprintln!(
        "afg: approved {id}; the token is valid for {} minutes and can be used once",
        tokens::TOKEN_TTL_SECS / 60
    );
    Ok(ExitCode::SUCCESS)
}
