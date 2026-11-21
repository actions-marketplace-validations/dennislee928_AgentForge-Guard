//! Audit reports: a JSON summary and SARIF 2.1.0 (for GitHub Code Scanning).
//!
//! Denials, refused approvals, approval-gated runs and execution errors
//! become SARIF results. Each one is located at the line in agentforge.yaml
//! that defines the deciding rule, so it is anchored in the repository.
//! Records are already redacted when they are written.

use std::collections::BTreeMap;

use afg_core::Effect;
use serde_json::{Value, json};

use crate::audit::AuditRecord;

pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// The 1-based line of `- id: <rule>` (or `id: <rule>`) in the policy text.
fn rule_line(policy_text: &str, rule_id: &str) -> Option<usize> {
    policy_text
        .lines()
        .position(|l| {
            let t = l.trim_start().trim_start_matches("- ").trim();
            t == format!("id: {rule_id}") || t == format!("id: \"{rule_id}\"")
        })
        .map(|i| i + 1)
}

fn is_finding(r: &AuditRecord) -> Option<(&'static str, &'static str)> {
    if r.error.is_some() {
        return Some(("error", "execution-error"));
    }
    match (r.decision.effect, &r.approval) {
        (Effect::Deny, _) => Some(("warning", "denied")),
        (Effect::RequireApproval, Some(a)) if !a.approved => Some(("note", "approval-refused")),
        (Effect::RequireApproval, Some(_)) => Some(("note", "approved")),
        _ => None,
    }
}

pub fn summary(records: &[AuditRecord]) -> Value {
    let mut by_effect: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    for r in records {
        *by_effect.entry(r.decision.effect.to_string()).or_default() += 1;
        *by_rule.entry(r.decision.rule_id.clone()).or_default() += 1;
        *by_source.entry(r.source.clone()).or_default() += 1;
    }
    json!({
        "total": records.len(),
        "byEffect": by_effect,
        "byRule": by_rule,
        "bySource": by_source,
        "findings": records.iter().filter(|r| is_finding(r).is_some()).count(),
        "first": records.first().map(|r| &r.timestamp),
        "last": records.last().map(|r| &r.timestamp),
    })
}

pub fn sarif(records: &[AuditRecord], policy_text: &str, policy_uri: &str) -> Value {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::new();
    for r in records {
        let Some((level, kind)) = is_finding(r) else {
            continue;
        };
        let rule_id = r.decision.rule_id.clone();
        rules.entry(rule_id.clone()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": rule_id.replace([':', '-'], "_"),
                "shortDescription": { "text": format!("AgentForge Guard policy rule `{rule_id}`") },
                "helpUri": "https://github.com/dennislee928/AgentForge-Guard/blob/main/docs/policy-reference.md",
            })
        });
        let argv = r
            .argv
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut text = format!(
            "{kind}: {argv} (effect {}, rule `{}`)",
            r.decision.effect, rule_id
        );
        if let Some(e) = &r.error {
            text.push_str(&format!(": {e}"));
        } else if let Some(reason) = r.decision.reasons.last() {
            text.push_str(&format!(": {reason}"));
        }
        let line = rule_line(policy_text, &rule_id).unwrap_or(1);
        results.push(json!({
            "ruleId": rule_id,
            "level": level,
            "message": { "text": text },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": policy_uri },
                    "region": { "startLine": line }
                }
            }],
            "partialFingerprints": { "afgAuditId": r.id },
            "properties": {
                "kind": kind,
                "source": r.source,
                "timestamp": r.timestamp,
                "cwd": r.cwd,
                "backend": r.decision.backend,
                "policyHash": r.policy.hash,
                "approval": r.approval,
            }
        }));
    }
    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "AgentForge Guard",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{ApprovalRecord, DecisionRecord, PolicyRef};

    fn rec(effect: Effect, rule: &str, approval: Option<bool>) -> AuditRecord {
        AuditRecord {
            schema: "s".into(),
            id: format!("id-{rule}"),
            timestamp: "2026-11-19T00:00:00Z".into(),
            afg_version: "0".into(),
            source: "run".into(),
            argv: vec!["terraform".into(), "destroy".into()],
            cwd: "/w".into(),
            policy: PolicyRef {
                version: "v".into(),
                hash: "sha256:x".into(),
            },
            decision: DecisionRecord {
                effect,
                backend: None,
                rule_id: rule.into(),
                reasons: vec!["matched".into()],
                program: None,
                opaque: false,
            },
            approval: approval.map(|a| ApprovalRecord {
                approved: a,
                channel: "tty".into(),
            }),
            execution: None,
            error: None,
        }
    }

    const POLICY: &str = "rules:\n  - id: read-only\n    effect: allow\n  - id: destructive-operations\n    effect: deny\n";

    #[test]
    fn sarif_contains_only_findings_located_at_rule_lines() {
        let records = vec![
            rec(Effect::Allow, "read-only", None),
            rec(Effect::Deny, "destructive-operations", None),
            rec(Effect::RequireApproval, "infra", Some(false)),
            rec(Effect::Deny, "builtin:fallback", None),
        ];
        let s = sarif(&records, POLICY, "agentforge.yaml");
        assert_eq!(s["version"], "2.1.0");
        let results = s["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["ruleId"], "destructive-operations");
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            4
        );
        assert_eq!(results[1]["level"], "note");
        assert_eq!(
            results[2]["locations"][0]["physicalLocation"]["region"]["startLine"], 1,
            "builtin rules fall back to line 1"
        );
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn summary_counts() {
        let records = vec![
            rec(Effect::Allow, "a", None),
            rec(Effect::Deny, "b", None),
            rec(Effect::Deny, "b", None),
        ];
        let v = summary(&records);
        assert_eq!(v["total"], 3);
        assert_eq!(v["byEffect"]["deny"], 2);
        assert_eq!(v["findings"], 2);
    }
}
