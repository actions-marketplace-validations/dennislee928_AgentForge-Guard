//! Append-only JSONL audit records.
//!
//! There is one file per UTC day (`<dir>/YYYY-MM-DD.jsonl`). Files are
//! created with mode 0600 inside a 0700 directory. Each record is a single
//! line, written while holding an exclusive file lock, so concurrent `afg`
//! processes never interleave lines.

use std::collections::hash_map::RandomState;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use afg_core::{BackendKind, Decision, Effect};
use serde::{Deserialize, Serialize};

pub const AUDIT_SCHEMA: &str = "agentforge.dev/audit/v1alpha1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRef {
    pub version: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionRecord {
    pub effect: Effect,
    pub backend: Option<BackendKind>,
    pub rule_id: String,
    pub reasons: Vec<String>,
    /// The program that was run, as a canonical path, if it was resolved.
    pub program: Option<String>,
    pub opaque: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    pub approved: bool,
    /// Where the answer came from. Only `tty` is accepted.
    pub channel: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamRecord {
    pub len: u64,
    pub sha256: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRecord {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: StreamRecord,
    pub stderr: StreamRecord,
    #[serde(default)]
    pub details: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub schema: String,
    pub id: String,
    /// The time, in RFC 3339 UTC.
    pub timestamp: String,
    pub afg_version: String,
    /// `run`, `explain` or `hook`.
    pub source: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub policy: PolicyRef,
    pub decision: DecisionRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditRecord {
    /// Start a record from a decision.
    pub fn from_decision(id: String, source: &str, cwd: &Path, d: &Decision) -> Self {
        Self {
            schema: AUDIT_SCHEMA.into(),
            id,
            timestamp: now_rfc3339(),
            afg_version: env!("CARGO_PKG_VERSION").into(),
            source: source.into(),
            argv: d.normalized.original.clone(),
            cwd: cwd.display().to_string(),
            policy: PolicyRef {
                version: d.policy_version.into(),
                hash: d.policy_hash.clone(),
            },
            decision: DecisionRecord {
                effect: d.effect,
                backend: d.backend,
                rule_id: d.rule_id.clone(),
                reasons: d.reasons.clone(),
                program: d
                    .normalized
                    .program
                    .as_ref()
                    .map(|p| p.display().to_string()),
                opaque: d.normalized.is_opaque(),
            },
            approval: None,
            execution: None,
            error: None,
        }
    }
}

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting")
}

fn today() -> String {
    let d = time::OffsetDateTime::now_utc().date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// A unique, roughly time-ordered id, for example `0193a1b2c3d4-5f3e2a1b9c8d7e6f`.
pub fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(ms);
    h.write_u32(std::process::id());
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    format!("{ms:012x}-{:016x}", h.finish())
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("audit serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    dir: PathBuf,
    redactor: Option<crate::redact::Redactor>,
}

impl AuditLog {
    /// Open the log directory, creating it with mode 0700. When `redact` is
    /// true, every record is redacted before it is written.
    pub fn open(dir: &Path, redact: bool) -> Result<Self, AuditError> {
        let io = |source| AuditError::Io {
            path: dir.to_path_buf(),
            source,
        };
        std::fs::create_dir_all(dir).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            redactor: redact.then(crate::redact::Redactor::new),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Append one record and return the path of the file it went to.
    pub fn append(&self, record: &AuditRecord) -> Result<PathBuf, AuditError> {
        let mut record = record.clone();
        if let Some(r) = &self.redactor {
            r.redact_record(&mut record);
        }
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let path = self.dir.join(format!("{}.jsonl", today()));
        let io = |source| AuditError::Io {
            path: path.clone(),
            source,
        };
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(io)?;
        f.lock().map_err(io)?;
        let res = f.write_all(&line).and_then(|_| f.flush());
        let _ = f.unlock();
        res.map_err(io)?;
        Ok(path)
    }

    /// Every record, oldest first. Lines that do not parse are skipped.
    pub fn read_all(&self) -> Result<Vec<AuditRecord>, AuditError> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .map_err(|source| AuditError::Io {
                path: self.dir.clone(),
                source,
            })?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        files.sort();
        let mut out = Vec::new();
        for p in files {
            let f = File::open(&p).map_err(|source| AuditError::Io {
                path: p.clone(),
                source,
            })?;
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(r) = serde_json::from_str::<AuditRecord>(&line) {
                    out.push(r);
                }
            }
        }
        Ok(out)
    }

    /// The last `n` records.
    pub fn tail(&self, n: usize) -> Result<Vec<AuditRecord>, AuditError> {
        let all = self.read_all()?;
        let skip = all.len().saturating_sub(n);
        Ok(all.into_iter().skip(skip).collect())
    }

    /// The number of executed records on `backend` within the last `window`.
    /// Used for the Cloudflare per-hour run cap (T11.4).
    pub fn executions_since(
        &self,
        backend: BackendKind,
        window: std::time::Duration,
    ) -> Result<usize, AuditError> {
        let cutoff = time::OffsetDateTime::now_utc() - window;
        let fmt = &time::format_description::well_known::Rfc3339;
        Ok(self
            .read_all()?
            .iter()
            .filter(|r| {
                r.decision.backend == Some(backend) && (r.execution.is_some() || r.error.is_some())
            })
            .filter(|r| time::OffsetDateTime::parse(&r.timestamp, fmt).is_ok_and(|t| t >= cutoff))
            .count())
    }

    /// Find a record by id, or by a unique id prefix.
    pub fn find(&self, id: &str) -> Result<Option<AuditRecord>, AuditError> {
        let matches: Vec<_> = self
            .read_all()?
            .into_iter()
            .filter(|r| r.id.starts_with(id))
            .collect();
        Ok(if matches.len() == 1 {
            matches.into_iter().next()
        } else {
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afg_core::{Engine, EvalRequest, Policy};

    fn decision(argv: &[&str]) -> Decision {
        let p = Policy::from_yaml(afg_core::builtin::policy_source("default").unwrap()).unwrap();
        let e = Engine::new(p, &std::env::temp_dir(), None);
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let cwd = std::env::temp_dir();
        e.evaluate(&EvalRequest {
            argv: &argv,
            cwd: &cwd,
            path_env: None,
            requested_backend: None,
        })
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("afg-audit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_and_read_back() {
        let d = dir("rw");
        let log = AuditLog::open(&d, false).unwrap();
        let rec = AuditRecord::from_decision(
            new_id(),
            "run",
            Path::new("/w"),
            &decision(&["terraform", "destroy"]),
        );
        let path = log.append(&rec).unwrap();
        log.append(&AuditRecord::from_decision(
            new_id(),
            "run",
            Path::new("/w"),
            &decision(&["git", "status"]),
        ))
        .unwrap();
        let all = log.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], rec);
        assert_eq!(all[0].decision.effect, Effect::Deny);
        assert_eq!(all[0].decision.rule_id, "destructive-operations");
        assert!(all[0].policy.hash.starts_with("sha256:"));
        assert_eq!(log.tail(1).unwrap()[0].argv, ["git", "status"]);
        assert_eq!(log.find(&rec.id[..20]).unwrap().unwrap().id, rec.id);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn concurrent_writers_never_interleave() {
        let d = dir("conc");
        let log = AuditLog::open(&d, false).unwrap();
        let rec = AuditRecord::from_decision(
            new_id(),
            "run",
            Path::new("/w"),
            &decision(&["git", "status"]),
        );
        std::thread::scope(|s| {
            for _ in 0..8 {
                let log = log.clone();
                let rec = rec.clone();
                s.spawn(move || {
                    for _ in 0..50 {
                        log.append(&rec).unwrap();
                    }
                });
            }
        });
        assert_eq!(log.read_all().unwrap().len(), 400, "every line parses");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn counts_recent_executions_per_backend() {
        let d = dir("count");
        let log = AuditLog::open(&d, false).unwrap();
        let mut rec = AuditRecord::from_decision(
            new_id(),
            "run",
            Path::new("/w"),
            &decision(&["bash", "x.sh"]),
        );
        rec.error = Some("boom".into());
        log.append(&rec).unwrap();
        log.append(&rec).unwrap();
        let mut old = rec.clone();
        old.timestamp = "2020-01-01T00:00:00Z".into();
        log.append(&old).unwrap();
        let hour = std::time::Duration::from_secs(3600);
        assert_eq!(
            log.executions_since(BackendKind::Container, hour).unwrap(),
            2
        );
        assert_eq!(
            log.executions_since(BackendKind::Cloudflare, hour).unwrap(),
            0
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn ids_are_unique() {
        let ids: std::collections::HashSet<_> = (0..1000).map(|_| new_id()).collect();
        assert_eq!(ids.len(), 1000);
    }
}
