//! Human approval for `require-approval` decisions.
//!
//! The answer is read only from the controlling terminal (`/dev/tty`), never
//! from stdin, so piped input cannot approve anything. With no terminal the
//! request is refused. Only the exact word `yes` approves.
//!
//! `AFG_NO_TTY` (any value) forces a refusal. Because it can only refuse,
//! setting it is never a bypass. CI and tests use it.
//!
//! Limitation (docs/security-boundaries.md): if an agent drives its own
//! pseudo-terminal, it controls `/dev/tty` too. Signed out-of-band approval
//! tokens are planned for v0.2.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use afg_core::Decision;
use afg_report::audit::ApprovalRecord;

use crate::policy_cmd::quote_argv;

pub enum Outcome {
    Approved,
    Refused {
        reason: String,
        channel: &'static str,
    },
}

impl Outcome {
    pub fn approved(&self) -> bool {
        matches!(self, Outcome::Approved)
    }

    pub fn reason(&self) -> &str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Refused { reason, .. } => reason,
        }
    }

    pub fn record(&self) -> ApprovalRecord {
        match self {
            Outcome::Approved => ApprovalRecord {
                approved: true,
                channel: "tty".into(),
            },
            Outcome::Refused { channel, .. } => ApprovalRecord {
                approved: false,
                channel: (*channel).into(),
            },
        }
    }
}

/// Only the exact word `yes` approves.
pub fn is_yes(answer: &str) -> bool {
    answer.trim_end_matches(['\r', '\n']).trim() == "yes"
}

pub fn prompt_text(d: &Decision, cwd: &Path) -> String {
    let mut s = String::new();
    s.push_str("\n=== afg: approval required ===\n");
    s.push_str(&format!("rule     {}\n", d.rule_id));
    s.push_str(&format!(
        "command  {}\n",
        quote_argv(&d.normalized.original)
    ));
    if let Some(p) = &d.normalized.program {
        s.push_str(&format!("program  {:?}\n", p.display().to_string()));
    }
    s.push_str(&format!("cwd      {:?}\n", cwd.display().to_string()));
    s.push_str(&format!(
        "backend  {}\n",
        d.backend
            .map(|b| b.to_string())
            .unwrap_or_else(|| "-".into())
    ));
    for r in &d.reasons {
        let clean: String = r.chars().filter(|c| !c.is_control()).collect();
        s.push_str(&format!("  - {clean}\n"));
    }
    s.push_str("Type `yes` to run it, anything else to refuse: ");
    s
}

pub fn request(d: &Decision, cwd: &Path) -> Outcome {
    if std::env::var_os("AFG_NO_TTY").is_some() {
        return Outcome::Refused {
            reason: "AFG_NO_TTY is set; approval needs a human".into(),
            channel: "none",
        };
    }
    let tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(t) => t,
        Err(_) => {
            return Outcome::Refused {
                reason: "no controlling terminal; approval needs a human at a terminal".into(),
                channel: "none",
            };
        }
    };
    let mut out = match tty.try_clone() {
        Ok(o) => o,
        Err(e) => {
            return Outcome::Refused {
                reason: format!("terminal error: {e}"),
                channel: "tty",
            };
        }
    };
    if out
        .write_all(prompt_text(d, cwd).as_bytes())
        .and_then(|_| out.flush())
        .is_err()
    {
        return Outcome::Refused {
            reason: "could not write to the terminal".into(),
            channel: "tty",
        };
    }
    let mut line = String::new();
    match BufReader::new(tty).read_line(&mut line) {
        Ok(_) if is_yes(&line) => Outcome::Approved,
        Ok(_) => Outcome::Refused {
            reason: "refused at the terminal".into(),
            channel: "tty",
        },
        Err(e) => Outcome::Refused {
            reason: format!("terminal read failed: {e}"),
            channel: "tty",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afg_core::{Engine, EvalRequest, Policy};

    #[test]
    fn only_exact_yes() {
        assert!(is_yes("yes\n"));
        assert!(is_yes("  yes \r\n"));
        for no in ["y", "Yes", "YES", "yes please", "", "\n", "no", "yess"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn prompt_escapes_control_characters() {
        let p = Policy::from_yaml(afg_core::builtin::policy_source("default").unwrap()).unwrap();
        let e = Engine::new(p, &std::env::temp_dir(), None);
        let argv: Vec<String> = vec![
            "kubectl".into(),
            "apply".into(),
            "-f".into(),
            "x\u{1b}[2Ky".into(),
        ];
        let cwd = std::env::temp_dir();
        let d = e.evaluate(&EvalRequest {
            argv: &argv,
            cwd: &cwd,
            path_env: None,
            requested_backend: None,
        });
        let text = prompt_text(&d, &cwd);
        assert!(
            !text.contains('\u{1b}'),
            "raw escape sequences must not reach the terminal"
        );
        assert!(text.contains("\"kubectl\" \"apply\""));
    }
}
