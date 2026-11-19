//! Secret redaction (completed in T4.2).

use crate::audit::AuditRecord;

#[derive(Debug, Clone, Default)]
pub struct Redactor;

impl Redactor {
    pub fn new() -> Self {
        Self
    }

    pub fn redact_record(&self, _record: &mut AuditRecord) {}
}
