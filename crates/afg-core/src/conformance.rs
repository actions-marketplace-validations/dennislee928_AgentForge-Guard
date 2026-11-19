//! Policy conformance fixtures (`tests/policy-fixtures/*.yaml`).
//!
//! Every entry point that makes or relays decisions (the CLI, agent hooks and
//! remote adapters) must produce these decisions exactly (ADR 0002).

use serde::Deserialize;

use crate::policy::{BackendKind, Effect};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureFile {
    /// `builtin:<name>` or inline policy YAML.
    pub policy: String,
    pub cases: Vec<Case>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub argv: Vec<String>,
    pub expect: Effect,
    #[serde(default)]
    pub backend: Option<BackendKind>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub requested: Option<BackendKind>,
    #[serde(default)]
    pub note: Option<String>,
}

impl FixtureFile {
    pub fn from_yaml(src: &str) -> Result<Self, serde_norway::Error> {
        serde_norway::from_str(src)
    }

    /// The YAML source of the policy under test.
    pub fn policy_source(&self) -> Option<String> {
        match self.policy.strip_prefix("builtin:") {
            Some(name) => crate::builtin::policy_source(name).map(str::to_owned),
            None => Some(self.policy.clone()),
        }
    }
}

impl Case {
    /// Compare a decision with this case, and describe the first mismatch.
    pub fn check(
        &self,
        effect: Effect,
        backend: Option<BackendKind>,
        rule_id: &str,
    ) -> Result<(), String> {
        if effect != self.expect {
            return Err(format!(
                "expected {}, got {effect} (rule {rule_id})",
                self.expect
            ));
        }
        if let Some(b) = self.backend
            && backend != Some(b)
        {
            return Err(format!("expected backend {b}, got {backend:?}"));
        }
        if let Some(r) = &self.rule
            && r != rule_id
        {
            return Err(format!("expected rule {r}, got {rule_id}"));
        }
        Ok(())
    }
}
