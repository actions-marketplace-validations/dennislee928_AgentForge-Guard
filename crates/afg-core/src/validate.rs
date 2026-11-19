//! Semantic validation of a parsed [`Policy`].
//!
//! The parser catches unknown fields and invalid values. This module catches
//! policies that are well-formed but unsafe or contradictory.

use std::collections::HashSet;

use crate::policy::{BackendKind, Effect, Fallback, Network, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Issue {
    pub severity: Severity,
    /// A dotted path into the document, for example `rules[2].backend`.
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{sev}: {}: {}", self.path, self.message)
    }
}

/// Backends that this build can execute.
pub const IMPLEMENTED_BACKENDS: &[BackendKind] = &[BackendKind::Local, BackendKind::Container];

/// Return every issue found. The policy is usable only if there are no
/// `Error` issues; see [`has_errors`].
pub fn validate(policy: &Policy) -> Vec<Issue> {
    let mut v = Validator::default();
    v.run(policy);
    v.issues
}

pub fn has_errors(issues: &[Issue]) -> bool {
    issues.iter().any(|i| i.severity == Severity::Error)
}

#[derive(Default)]
struct Validator {
    issues: Vec<Issue>,
}

impl Validator {
    fn err(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Error,
            path: path.into(),
            message: msg.into(),
        });
    }

    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Warning,
            path: path.into(),
            message: msg.into(),
        });
    }

    fn check_backend(&mut self, policy: &Policy, path: &str, kind: BackendKind) {
        if !IMPLEMENTED_BACKENDS.contains(&kind) {
            self.err(
                path,
                format!("backend `{kind}` is not implemented in this version"),
            );
        } else if !policy.execution.backends.is_enabled(kind) {
            self.err(
                path,
                format!("backend `{kind}` is referenced but not enabled"),
            );
        }
    }

    fn run(&mut self, p: &Policy) {
        if p.project.name.trim().is_empty() {
            self.err("project.name", "must not be empty");
        }

        let b = &p.execution.backends;
        if !b.local.enabled && !b.container.enabled {
            self.err("execution.backends", "at least one backend must be enabled");
        }
        if b.cloudflare.enabled {
            self.err(
                "execution.backends.cloudflare.enabled",
                "the cloudflare backend is not implemented in this version",
            );
        }
        self.check_backend(p, "execution.default", p.execution.default);
        if let Fallback::Route(kind) = p.execution.fallback {
            self.check_backend(p, "execution.fallback.route", kind);
        }

        let c = &b.container;
        if c.enabled {
            if c.memory_mb == 0 {
                self.err(
                    "execution.backends.container.memoryMB",
                    "must be greater than 0",
                );
            }
            if !(c.cpus.is_finite() && c.cpus > 0.0) {
                self.err(
                    "execution.backends.container.cpus",
                    "must be greater than 0",
                );
            }
            if c.pids_limit == 0 {
                self.err(
                    "execution.backends.container.pidsLimit",
                    "must be greater than 0",
                );
            }
            if c.timeout_seconds == 0 {
                self.err(
                    "execution.backends.container.timeoutSeconds",
                    "must be greater than 0",
                );
            }
            if c.image.trim().is_empty() {
                self.err("execution.backends.container.image", "must not be empty");
            }
            if c.network == Network::Bridge {
                self.warn(
                    "execution.backends.container.network",
                    "`bridge` gives sandboxed code network access",
                );
            }
            if !c.read_only_rootfs {
                self.warn(
                    "execution.backends.container.readOnlyRootfs",
                    "a writable root filesystem weakens isolation",
                );
            }
        }
        if b.local.enabled && b.local.timeout_seconds == 0 {
            self.err(
                "execution.backends.local.timeoutSeconds",
                "must be greater than 0",
            );
        }

        let mut ids = HashSet::new();
        for (i, rule) in p.rules.iter().enumerate() {
            let at = format!("rules[{i}]");
            if rule.id.trim().is_empty() {
                self.err(format!("{at}.id"), "must not be empty");
            } else if !ids.insert(rule.id.as_str()) {
                self.err(
                    format!("{at}.id"),
                    format!("duplicate rule id `{}`", rule.id),
                );
            }
            if rule.commands.is_empty() {
                self.err(format!("{at}.commands"), "must list at least one command");
            }
            for (j, cmd) in rule.commands.iter().enumerate() {
                match cmd.first() {
                    None => self.err(format!("{at}.commands[{j}]"), "must not be empty"),
                    Some(exe) if exe.trim().is_empty() || exe == "*" => self.err(
                        format!("{at}.commands[{j}][0]"),
                        "the executable must be a concrete name",
                    ),
                    Some(exe) => {
                        if rule.effect == Effect::Allow
                            && crate::normalize::is_opaque_name(&crate::normalize::exe_name(exe))
                        {
                            self.warn(
                                format!("{at}.commands[{j}][0]"),
                                format!(
                                    "`{exe}` is always opaque, so `allow` never applies to it; \
                                     use `route` to a container instead"
                                ),
                            );
                        }
                    }
                }
            }
            match rule.effect {
                Effect::Route => match rule.backend {
                    None => self.err(format!("{at}.backend"), "`route` rules must name a backend"),
                    Some(BackendKind::Local) => self.err(
                        format!("{at}.backend"),
                        "`route` must target an isolated backend; use `allow` for local",
                    ),
                    Some(k) => self.check_backend(p, &format!("{at}.backend"), k),
                },
                Effect::Deny => {
                    if rule.backend.is_some() {
                        self.warn(format!("{at}.backend"), "ignored on `deny` rules");
                    }
                }
                Effect::Allow | Effect::RequireApproval => {
                    if let Some(k) = rule.backend {
                        self.check_backend(p, &format!("{at}.backend"), k);
                    }
                }
            }
            if matches!(rule.effect, Effect::Deny | Effect::RequireApproval)
                && (!rule.deny_args.is_empty() || rule.allow_flags.is_some())
            {
                self.err(
                    at.clone(),
                    "`denyArgs`/`allowFlags` narrow a rule and would weaken a deny or approval rule; \
                     they are only allowed on `allow` and `route` rules",
                );
            }
        }

        if !p.audit.redact_secrets {
            self.warn("audit.redactSecrets", "audit records may contain secrets");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &str) -> Policy {
        let src = format!(
            "apiVersion: agentforge.dev/v1alpha1\nkind: AgentPolicy\nproject: {{ name: x }}\n{extra}"
        );
        Policy::from_yaml(&src).unwrap()
    }

    fn errors(p: &Policy) -> Vec<String> {
        validate(p)
            .into_iter()
            .filter(|i| i.severity == Severity::Error)
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect()
    }

    #[test]
    fn minimal_policy_is_valid() {
        assert!(errors(&parse("")).is_empty());
    }

    #[test]
    fn duplicate_ids() {
        let p = parse(
            "rules:\n  - { id: a, effect: allow, commands: [[ls]] }\n  - { id: a, effect: deny, commands: [[rm]] }\n",
        );
        assert!(
            errors(&p)
                .iter()
                .any(|e| e.contains("duplicate rule id `a`"))
        );
    }

    #[test]
    fn route_without_backend_or_to_local() {
        let p = parse("rules:\n  - { id: a, effect: route, commands: [[sh]] }\n");
        assert!(errors(&p).iter().any(|e| e.contains("must name a backend")));
        let p = parse("rules:\n  - { id: a, effect: route, backend: local, commands: [[sh]] }\n");
        assert!(errors(&p).iter().any(|e| e.contains("isolated backend")));
    }

    #[test]
    fn disabled_backend_referenced() {
        let p =
            parse("rules:\n  - { id: a, effect: route, backend: container, commands: [[sh]] }\n");
        assert!(errors(&p).iter().any(|e| e.contains("not enabled")));
        let p = parse("execution: { fallback: { route: container } }\n");
        assert!(
            errors(&p)
                .iter()
                .any(|e| e.starts_with("execution.fallback.route"))
        );
    }

    #[test]
    fn cloudflare_not_implemented() {
        let p = parse("execution: { backends: { cloudflare: { enabled: true } } }\n");
        assert!(errors(&p).iter().any(|e| e.contains("not implemented")));
    }

    #[test]
    fn constraints_on_deny_rules_rejected() {
        let p = parse(
            "rules:\n  - { id: a, effect: deny, commands: [[terraform, destroy]], denyArgs: [-target] }\n",
        );
        assert!(errors(&p).iter().any(|e| e.contains("weaken")));
    }

    #[test]
    fn empty_and_wildcard_executables_rejected() {
        let p = parse(
            "rules:\n  - { id: a, effect: allow, commands: [[]] }\n  - { id: b, effect: allow, commands: [['*']] }\n",
        );
        let e = errors(&p);
        assert!(e.iter().any(|e| e.starts_with("rules[0].commands[0]")));
        assert!(e.iter().any(|e| e.starts_with("rules[1].commands[0][0]")));
    }

    #[test]
    fn bad_container_limits() {
        let p = parse(
            "execution: { backends: { container: { enabled: true, memoryMB: 0, cpus: 0, network: bridge } } }\n",
        );
        let all = validate(&p);
        assert!(
            all.iter()
                .any(|i| i.path.ends_with("memoryMB") && i.severity == Severity::Error)
        );
        assert!(
            all.iter()
                .any(|i| i.path.ends_with("cpus") && i.severity == Severity::Error)
        );
        assert!(
            all.iter()
                .any(|i| i.path.ends_with("network") && i.severity == Severity::Warning)
        );
    }

    #[test]
    fn allow_on_opaque_executable_warns() {
        let p = parse("rules:\n  - { id: a, effect: allow, commands: [[bash]] }\n");
        let all = validate(&p);
        assert!(
            all.iter()
                .any(|i| i.severity == Severity::Warning && i.message.contains("always opaque"))
        );
        assert!(!has_errors(&all));
    }

    #[test]
    fn no_backend_enabled() {
        let p =
            parse("execution: { default: container, backends: { local: { enabled: false } } }\n");
        assert!(
            errors(&p)
                .iter()
                .any(|e| e.contains("at least one backend"))
        );
    }
}
