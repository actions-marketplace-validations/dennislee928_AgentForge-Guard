//! Human approval for `require-approval` decisions (completed in T5.5).

use std::path::Path;

use afg_core::Decision;
use afg_report::audit::ApprovalRecord;

pub enum Outcome {
    Refused(String),
}

impl Outcome {
    pub fn approved(&self) -> bool {
        false
    }
    pub fn reason(&self) -> &str {
        match self {
            Outcome::Refused(r) => r,
        }
    }
    pub fn record(&self) -> ApprovalRecord {
        ApprovalRecord {
            approved: false,
            channel: "none".into(),
        }
    }
}

/// Approval is not implemented yet, so the request fails closed.
pub fn request(_d: &Decision, _cwd: &Path) -> Outcome {
    Outcome::Refused("interactive approval is not available yet".into())
}
