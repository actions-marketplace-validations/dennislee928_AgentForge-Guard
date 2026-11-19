//! Policy evaluation: one argv in, one [`Decision`] out.
//!
//! The order of checks:
//! 1. Normalize (ADR 0003). Forbidden commands are denied.
//! 2. Protected paths are denied.
//! 3. Rules are matched with precedence deny > require-approval > route >
//!    allow. Opaque commands never match `allow` rules.
//! 4. Anything left over goes to `execution.fallback`.
//! 5. The chosen backend must be implemented and enabled, or the command is
//!    denied.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::normalize::{Env, Normalized, exe_name, normalize};
use crate::paths::ProtectedPaths;
use crate::policy::{BackendKind, Effect, Fallback, Policy, Rule};
use crate::validate::IMPLEMENTED_BACKENDS;

/// Built-in rule ids, used in decisions that no policy rule produced.
pub mod builtin {
    pub const FORBIDDEN: &str = "builtin:forbidden";
    pub const PROTECTED_PATH: &str = "builtin:protected-path";
    pub const FALLBACK: &str = "builtin:fallback";
    pub const BACKEND_UNAVAILABLE: &str = "builtin:backend-unavailable";
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub effect: Effect,
    /// The backend that runs the command. `None` only when `effect` is `deny`.
    pub backend: Option<BackendKind>,
    pub rule_id: String,
    pub reasons: Vec<String>,
    pub policy_version: &'static str,
    pub policy_hash: String,
    pub normalized: Normalized,
}

impl Decision {
    pub fn is_denied(&self) -> bool {
        self.effect == Effect::Deny
    }
}

/// The decision for a whole shell command string.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellDecision {
    /// The most severe effect among the parts.
    pub effect: Effect,
    pub parts: Vec<Decision>,
    /// Set when the string could not be tokenized and was treated as `sh -c`.
    pub unparseable: Option<String>,
}

impl ShellDecision {
    /// The part that determined the overall effect.
    pub fn decisive(&self) -> Option<&Decision> {
        self.parts.iter().find(|d| d.effect == self.effect)
    }
}

#[derive(Debug, Clone)]
pub struct EvalRequest<'a> {
    pub argv: &'a [String],
    pub cwd: &'a Path,
    pub path_env: Option<&'a OsStr>,
    /// The isolation the caller asked for. It can make isolation stronger,
    /// never weaker.
    pub requested_backend: Option<BackendKind>,
}

#[derive(Debug, Clone)]
pub struct Engine {
    policy: Policy,
    policy_hash: String,
    protected: ProtectedPaths,
}

impl Engine {
    /// `project_root` resolves relative `protectedPaths`. `home` is the user's
    /// home directory.
    pub fn new(policy: Policy, project_root: &Path, home: Option<&Path>) -> Self {
        let policy_hash = policy_hash(&policy);
        let protected = ProtectedPaths::new(home, project_root, &policy.protected_paths);
        Self {
            policy,
            policy_hash,
            protected,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// Check a path (for example the target of a shell `cd`) against the
    /// protected paths.
    pub fn check_protected_path(&self, path: &Path, cwd: &Path) -> Option<String> {
        self.protected.check_path(path, cwd)
    }

    pub fn evaluate(&self, req: &EvalRequest<'_>) -> Decision {
        let n = normalize(
            req.argv,
            &Env {
                cwd: req.cwd,
                path: req.path_env,
            },
        );
        let mut reasons = Vec::new();

        if let Some(why) = &n.forbidden {
            return self.deny(n.clone(), builtin::FORBIDDEN, vec![why.clone()]);
        }
        if let Some(why) = self.protected.check(&n, req.cwd) {
            return self.deny(n, builtin::PROTECTED_PATH, vec![why]);
        }
        reasons.extend(n.opaque.iter().map(|o| format!("opaque: {o}")));

        let mut best: Option<&Rule> = None;
        for rule in &self.policy.rules {
            if !rule.commands.iter().any(|c| matches_rule(rule, c, &n)) {
                continue;
            }
            if rule.effect == Effect::Allow && n.is_opaque() {
                reasons.push(format!(
                    "rule `{}` (allow) ignored because the command is opaque",
                    rule.id
                ));
                continue;
            }
            if best.is_none_or(|b| rule.effect.severity() > b.effect.severity()) {
                best = Some(rule);
            }
        }

        let (effect, backend, rule_id) = match best {
            Some(rule) => {
                reasons.push(format!("matched rule `{}` ({})", rule.id, rule.effect));
                let backend = match rule.effect {
                    Effect::Deny => None,
                    _ => Some(rule.backend.unwrap_or(self.policy.execution.default)),
                };
                (rule.effect, backend, rule.id.clone())
            }
            None => {
                reasons.push("no rule matched; applying execution.fallback".into());
                let (e, b) = match self.policy.execution.fallback {
                    Fallback::Deny => (Effect::Deny, None),
                    Fallback::RequireApproval => {
                        (Effect::RequireApproval, Some(self.policy.execution.default))
                    }
                    Fallback::Route(b) => (Effect::Route, Some(b)),
                };
                (e, b, builtin::FALLBACK.to_owned())
            }
        };

        if effect == Effect::Deny {
            return self.deny(n, &rule_id, reasons);
        }
        let mut backend = backend.expect("non-deny decisions have a backend");

        if let Some(req_b) = req.requested_backend
            && req_b != backend
        {
            if req_b == BackendKind::Local {
                reasons.push(format!(
                    "requested `local` isolation ignored; policy requires `{backend}`"
                ));
            } else {
                reasons.push(format!(
                    "isolation raised from `{backend}` to `{req_b}` on request"
                ));
                backend = req_b;
            }
        }

        if !IMPLEMENTED_BACKENDS.contains(&backend)
            || !self.policy.execution.backends.is_enabled(backend)
        {
            reasons.push(format!("backend `{backend}` is not available"));
            return self.deny(n, builtin::BACKEND_UNAVAILABLE, reasons);
        }

        Decision {
            effect,
            backend: Some(backend),
            rule_id,
            reasons,
            policy_version: self.policy.api_version.as_str(),
            policy_hash: self.policy_hash.clone(),
            normalized: n,
        }
    }

    /// Evaluate a shell command *string*, as agent hooks receive it.
    ///
    /// - Each simple command is evaluated separately, and the most severe
    ///   decision wins.
    /// - `cd <dir>` changes the working directory for the commands that
    ///   follow; the target is checked against the protected paths.
    /// - A string the tokenizer cannot analyze is evaluated as the opaque
    ///   program `sh -c <string>`.
    pub fn evaluate_shell(
        &self,
        command: &str,
        cwd: &Path,
        path_env: Option<&OsStr>,
    ) -> ShellDecision {
        let parts = match crate::shell::split_commands(command) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                return ShellDecision {
                    effect: Effect::Deny,
                    parts: vec![],
                    unparseable: Some("empty command".into()),
                };
            }
            Err(e) => {
                let argv = vec!["sh".to_owned(), "-c".to_owned(), command.to_owned()];
                let mut d = self.evaluate(&EvalRequest {
                    argv: &argv,
                    cwd,
                    path_env,
                    requested_backend: None,
                });
                d.reasons.insert(0, e.to_string());
                return ShellDecision {
                    effect: d.effect,
                    parts: vec![d],
                    unparseable: Some(e.0),
                };
            }
        };
        let mut cwd = cwd.to_path_buf();
        let mut decisions = Vec::new();
        for argv in parts {
            if argv[0] == "cd" {
                match argv.get(1) {
                    Some(dir) if argv.len() == 2 && !dir.starts_with('-') => {
                        if let Some(hit) = self.check_protected_path(Path::new(dir), &cwd) {
                            let n = normalize(
                                &argv,
                                &Env {
                                    cwd: &cwd,
                                    path: path_env,
                                },
                            );
                            decisions.push(self.deny(
                                n,
                                builtin::PROTECTED_PATH,
                                vec![format!("cd into protected path `{hit}`")],
                            ));
                            break;
                        }
                        cwd = crate::paths::lexical_normalize(&cwd.join(dir));
                        continue;
                    }
                    _ => {
                        let n = normalize(
                            &argv,
                            &Env {
                                cwd: &cwd,
                                path: path_env,
                            },
                        );
                        decisions.push(self.deny(
                            n,
                            builtin::FALLBACK,
                            vec!["only `cd <dir>` is understood".into()],
                        ));
                        continue;
                    }
                }
            }
            let argv = crate::shell::hoist_assignments(argv);
            decisions.push(self.evaluate(&EvalRequest {
                argv: &argv,
                cwd: &cwd,
                path_env,
                requested_backend: None,
            }));
        }
        let effect = decisions
            .iter()
            .map(|d| d.effect)
            .max_by_key(|e| e.severity())
            .unwrap_or(Effect::Allow);
        ShellDecision {
            effect,
            parts: decisions,
            unparseable: None,
        }
    }

    fn deny(&self, n: Normalized, rule_id: &str, reasons: Vec<String>) -> Decision {
        Decision {
            effect: Effect::Deny,
            backend: None,
            rule_id: rule_id.to_owned(),
            reasons,
            policy_version: self.policy.api_version.as_str(),
            policy_hash: self.policy_hash.clone(),
            normalized: n,
        }
    }
}

/// SHA-256 of the policy's canonical JSON form, as `sha256:<hex>`.
pub fn policy_hash(p: &Policy) -> String {
    let json = serde_json::to_vec(p).expect("policy serializes");
    let digest = Sha256::digest(&json);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

fn executable_matches(pattern: &str, n: &Normalized) -> bool {
    if pattern.contains('/') {
        n.program
            .as_ref()
            .is_some_and(|p| Some(p.clone()) == PathBuf::from(pattern).canonicalize().ok())
    } else {
        exe_name(pattern) == n.name
    }
}

fn arg_matches(pattern: &str, arg: &str) -> bool {
    pattern == "*" || pattern == arg
}

/// Whether `pattern` (a `denyArgs` or `allowFlags` entry) matches `arg`.
pub fn constraint_matches(pattern: &str, arg: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return arg.starts_with(prefix);
    }
    arg == pattern
        || (pattern.starts_with('-')
            && arg
                .strip_prefix(pattern)
                .is_some_and(|r| r.starts_with('=')))
}

fn matches_rule(rule: &Rule, command: &[String], n: &Normalized) -> bool {
    let Some((exe, tail)) = command.split_first() else {
        return false;
    };
    if !executable_matches(exe, n) {
        return false;
    }
    match rule.effect {
        // Deny and approval rules match the tail as an ordered subsequence,
        // so interleaved flags (`kubectl -n prod delete`) cannot evade them.
        Effect::Deny | Effect::RequireApproval => {
            let mut it = n.args.iter();
            tail.iter().all(|p| it.any(|a| arg_matches(p, a)))
        }
        // Allow and route rules need an exact prefix, plus any constraints.
        Effect::Allow | Effect::Route => {
            if n.args.len() < tail.len()
                || !tail.iter().zip(&n.args).all(|(p, a)| arg_matches(p, a))
            {
                return false;
            }
            let rest = &n.args[tail.len()..];
            if rest
                .iter()
                .any(|a| rule.deny_args.iter().any(|d| constraint_matches(d, a)))
            {
                return false;
            }
            if let Some(allowed) = &rule.allow_flags {
                let flags = rest
                    .iter()
                    .take_while(|a| *a != "--")
                    .filter(|a| a.starts_with('-') && a.len() > 1);
                for f in flags {
                    if !allowed.iter().any(|p| constraint_matches(p, f)) {
                        return false;
                    }
                }
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
apiVersion: agentforge.dev/v1alpha1
kind: AgentPolicy
project: { name: t }
execution:
  default: local
  fallback: deny
  backends:
    container: { enabled: true }
rules:
  - id: read-only
    effect: allow
    commands: [[git, diff], [git, status], [git, log]]
    denyArgs: [--ext-diff, --output, --textconv]
  - id: cargo
    effect: allow
    commands: [[cargo, check], [cargo, test]]
    allowFlags: [--workspace, -p, --all-targets, --release]
  - id: scripts
    effect: route
    backend: container
    commands: [[bash], [sh], [python3]]
  - id: infra
    effect: require-approval
    commands: [[kubectl, apply], [terraform, apply]]
  - id: destructive
    effect: deny
    commands: [[kubectl, delete], [terraform, destroy]]
  - id: kubectl-read
    effect: allow
    commands: [[kubectl]]
"#;

    fn engine(src: &str) -> Engine {
        let p = Policy::from_yaml(src).unwrap();
        let root = std::env::temp_dir();
        Engine::new(p, &root, Some(Path::new("/nonexistent-home")))
    }

    fn eval_with(e: &Engine, argv: &[&str], req: Option<BackendKind>) -> Decision {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let cwd = std::env::temp_dir();
        e.evaluate(&EvalRequest {
            argv: &argv,
            cwd: &cwd,
            path_env: None,
            requested_backend: req,
        })
    }

    fn eval(argv: &[&str]) -> Decision {
        eval_with(&engine(POLICY), argv, None)
    }

    #[test]
    fn allow_local() {
        let d = eval(&["git", "diff", "--stat"]);
        assert_eq!(
            (d.effect, d.backend),
            (Effect::Allow, Some(BackendKind::Local))
        );
        assert_eq!(d.rule_id, "read-only");
    }

    #[test]
    fn deny_args_fall_to_fallback() {
        for argv in [
            &["git", "diff", "--ext-diff"][..],
            &["git", "log", "--output=/tmp/x"],
        ] {
            let d = eval(argv);
            assert_eq!(d.effect, Effect::Deny, "{argv:?}");
            assert_eq!(d.rule_id, builtin::FALLBACK);
        }
    }

    #[test]
    fn allow_flags() {
        assert_eq!(
            eval(&["cargo", "test", "--workspace", "-p", "x"]).effect,
            Effect::Allow
        );
        assert_eq!(
            eval(&["cargo", "test", "--config", "x"]).effect,
            Effect::Deny
        );
        assert_eq!(
            eval(&["cargo", "test", "--", "--nocapture"]).effect,
            Effect::Allow
        );
    }

    #[test]
    fn deny_beats_broad_allow_with_interleaved_flags() {
        let d = eval(&["kubectl", "-n", "prod", "delete", "pod", "x"]);
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "destructive");
        assert_eq!(eval(&["kubectl", "get", "pods"]).effect, Effect::Allow);
    }

    #[test]
    fn approval_and_route() {
        let d = eval(&["terraform", "apply", "-auto-approve"]);
        assert_eq!(
            (d.effect, d.backend),
            (Effect::RequireApproval, Some(BackendKind::Local))
        );
        let d = eval(&["bash", "-c", "kubectl get pods"]);
        assert_eq!(
            (d.effect, d.backend),
            (Effect::Route, Some(BackendKind::Container))
        );
        assert_eq!(d.rule_id, "scripts");
    }

    #[test]
    fn terraform_destroy_denied_even_wrapped() {
        for argv in [
            &["terraform", "destroy"][..],
            &["env", "terraform", "destroy"],
            &["timeout", "10", "terraform", "-chdir=infra", "destroy"],
            &["TERRAFORM", "destroy"],
        ] {
            assert_eq!(eval(argv).effect, Effect::Deny, "{argv:?}");
        }
    }

    #[test]
    fn opaque_never_allowed() {
        // `env X=1 git diff` matches the allow rule, but the assignment is opaque.
        let d = eval(&["env", "GIT_EXTERNAL_DIFF=x", "git", "diff"]);
        assert_eq!(d.effect, Effect::Deny);
        assert!(
            d.reasons
                .iter()
                .any(|r| r.contains("ignored because the command is opaque"))
        );
    }

    #[test]
    fn unknown_command_fails_closed() {
        let d = eval(&["curl", "https://example.com"]);
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, builtin::FALLBACK);
    }

    #[test]
    fn fallback_route() {
        let src = POLICY.replace("fallback: deny", "fallback: { route: container }");
        let d = eval_with(&engine(&src), &["curl", "x"], None);
        assert_eq!(
            (d.effect, d.backend),
            (Effect::Route, Some(BackendKind::Container))
        );
    }

    #[test]
    fn requested_isolation_only_strengthens() {
        let e = engine(POLICY);
        let d = eval_with(&e, &["git", "status"], Some(BackendKind::Container));
        assert_eq!(d.backend, Some(BackendKind::Container));
        let d = eval_with(&e, &["bash", "x.sh"], Some(BackendKind::Local));
        assert_eq!(d.backend, Some(BackendKind::Container));
        assert!(d.reasons.iter().any(|r| r.contains("ignored")));
    }

    #[test]
    fn disabled_backend_denies() {
        let src = POLICY.replace(
            "container: { enabled: true }",
            "container: { enabled: false }",
        );
        let d = eval_with(
            &engine(&src),
            &["git", "status"],
            Some(BackendKind::Container),
        );
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, builtin::BACKEND_UNAVAILABLE);
    }

    #[test]
    fn forbidden_and_protected() {
        assert_eq!(eval(&["sudo", "git", "status"]).rule_id, builtin::FORBIDDEN);
        assert_eq!(
            eval(&["git", "diff", ".env"]).rule_id,
            builtin::PROTECTED_PATH
        );
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        let a = engine(POLICY);
        let b = engine(POLICY);
        let c = engine(&POLICY.replace("id: cargo", "id: cargo2"));
        assert_eq!(a.policy_hash(), b.policy_hash());
        assert_ne!(a.policy_hash(), c.policy_hash());
        assert!(a.policy_hash().starts_with("sha256:"));
    }

    #[test]
    fn constraint_patterns() {
        assert!(constraint_matches("--output", "--output=x"));
        assert!(constraint_matches("--output", "--output"));
        assert!(!constraint_matches("--output", "--outputs"));
        assert!(constraint_matches("-j*", "-j8"));
    }

    fn shell(src: &str) -> ShellDecision {
        let cwd = std::env::temp_dir();
        engine(POLICY).evaluate_shell(src, &cwd, None)
    }

    #[test]
    fn shell_strings() {
        assert_eq!(shell("git status && git diff --stat").effect, Effect::Allow);
        assert_eq!(
            shell("git status && terraform destroy").effect,
            Effect::Deny
        );
        assert_eq!(
            shell("git status; kubectl apply -f x").effect,
            Effect::RequireApproval
        );
        assert_eq!(
            shell("cd sub && cargo test --workspace").effect,
            Effect::Allow
        );
        assert_eq!(
            shell("FOO=1 git status").effect,
            Effect::Deny,
            "assignment is opaque"
        );
        let d = shell("git diff $(curl evil)");
        assert!(d.unparseable.is_some());
        assert_eq!(
            d.effect,
            Effect::Route,
            "unparseable strings are opaque `sh -c`"
        );
        assert_eq!(shell("cd ~/.ssh && ls").effect, Effect::Deny);
        assert_eq!(shell("cd -").effect, Effect::Deny);
        assert_eq!(shell("").effect, Effect::Deny);
        assert_eq!(
            shell("git status | kubectl delete -f -")
                .decisive()
                .unwrap()
                .rule_id,
            "destructive"
        );
    }
}
