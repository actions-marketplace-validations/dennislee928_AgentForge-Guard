//! `agentforge.yaml` policy schema, version `agentforge.dev/v1alpha1`.
//!
//! Every struct uses `deny_unknown_fields`, so a typo in a security setting is
//! an error instead of being silently ignored.

use serde::{Deserialize, Serialize};

/// The policy API version that this build understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ApiVersion {
    #[serde(rename = "agentforge.dev/v1alpha1")]
    V1Alpha1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Kind {
    AgentPolicy,
}

/// The top-level policy document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub api_version: ApiVersion,
    pub kind: Kind,
    pub project: Project,
    #[serde(default)]
    pub agents: Vec<Agent>,
    #[serde(default)]
    pub execution: Execution,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Extra protected paths. These are added to the built-in list and can
    /// never remove entries from it. Entries are directories or files
    /// (`~` is expanded), or basename globs such as `*.secret`.
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub audit: Audit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub name: String,
    #[serde(default = "default_root")]
    pub root: String,
}

fn default_root() -> String {
    ".".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Agent {
    ClaudeCode,
    Codex,
}

/// The execution backends.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Local,
    Container,
    Cloudflare,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BackendKind::Local => "local",
            BackendKind::Container => "container",
            BackendKind::Cloudflare => "cloudflare",
        })
    }
}

/// What to do with a command that no rule matched, or an opaque command that
/// only `allow` rules matched.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(from = "FallbackRepr", into = "FallbackRepr")]
pub enum Fallback {
    #[default]
    Deny,
    RequireApproval,
    /// Run the command on an isolated backend, written `{ route: container }`.
    Route(BackendKind),
}

/// The YAML form of [`Fallback`]: the string `deny` or `require-approval`, or
/// the map `{ route: <backend> }`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum FallbackRepr {
    Simple(SimpleFallback),
    Route(RouteFallback),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum SimpleFallback {
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RouteFallback {
    route: BackendKind,
}

impl From<FallbackRepr> for Fallback {
    fn from(r: FallbackRepr) -> Self {
        match r {
            FallbackRepr::Simple(SimpleFallback::Deny) => Fallback::Deny,
            FallbackRepr::Simple(SimpleFallback::RequireApproval) => Fallback::RequireApproval,
            FallbackRepr::Route(RouteFallback { route }) => Fallback::Route(route),
        }
    }
}

impl From<Fallback> for FallbackRepr {
    fn from(f: Fallback) -> Self {
        match f {
            Fallback::Deny => FallbackRepr::Simple(SimpleFallback::Deny),
            Fallback::RequireApproval => FallbackRepr::Simple(SimpleFallback::RequireApproval),
            Fallback::Route(route) => FallbackRepr::Route(RouteFallback { route }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Execution {
    /// The backend used by `allow` and `require-approval` rules that do not
    /// name one.
    #[serde(default = "default_backend")]
    pub default: BackendKind,
    #[serde(default)]
    pub fallback: Fallback,
    #[serde(default)]
    pub backends: Backends,
}

fn default_backend() -> BackendKind {
    BackendKind::Local
}

impl Default for Execution {
    fn default() -> Self {
        Self {
            default: default_backend(),
            fallback: Fallback::default(),
            backends: Backends::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Backends {
    #[serde(default)]
    pub local: LocalBackend,
    #[serde(default)]
    pub container: ContainerBackend,
    #[serde(default)]
    pub cloudflare: CloudflareBackend,
}

impl Backends {
    pub fn is_enabled(&self, kind: BackendKind) -> bool {
        match kind {
            BackendKind::Local => self.local.enabled,
            BackendKind::Container => self.container.enabled,
            BackendKind::Cloudflare => self.cloudflare.enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalBackend {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Environment variables passed through from the host. Everything else is
    /// cleared.
    #[serde(default = "default_local_env")]
    pub env: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self {
            enabled: true,
            env: default_local_env(),
            timeout_seconds: default_timeout(),
        }
    }
}

fn default_local_env() -> Vec<String> {
    ["PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR"]
        .map(String::from)
        .to_vec()
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    #[default]
    None,
    Bridge,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerBackend {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default)]
    pub network: Network,
    #[serde(default = "yes")]
    pub read_only_rootfs: bool,
    #[serde(default = "default_memory", rename = "memoryMB")]
    pub memory_mb: u64,
    #[serde(default = "default_cpus")]
    pub cpus: f64,
    #[serde(default = "default_pids")]
    pub pids_limit: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Variables passed into the container. Values come from the host, and
    /// none are passed by default.
    #[serde(default)]
    pub env: Vec<String>,
}

impl Default for ContainerBackend {
    fn default() -> Self {
        Self {
            enabled: false,
            image: default_image(),
            network: Network::None,
            read_only_rootfs: true,
            memory_mb: default_memory(),
            cpus: default_cpus(),
            pids_limit: default_pids(),
            timeout_seconds: default_timeout(),
            env: Vec::new(),
        }
    }
}

fn default_image() -> String {
    "debian:stable-slim".into()
}
fn default_memory() -> u64 {
    2048
}
fn default_cpus() -> f64 {
    2.0
}
fn default_pids() -> u64 {
    256
}
fn default_timeout() -> u64 {
    300
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareBackend {
    #[serde(default)]
    pub enabled: bool,
    /// The Worker URL from `packages/cloudflare-adapter`. It must be https,
    /// except for loopback addresses during tests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The environment variable that holds the hex signing key. If it is
    /// unset, `~/.config/agentforge/cloudflare.key` is read.
    #[serde(default = "default_cf_key_env")]
    pub key_env: String,
    #[serde(default)]
    pub network: Network,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// The maximum size of the uploaded snapshot archive (a cost and safety cap).
    #[serde(default = "default_cf_upload")]
    pub max_upload_mb: u64,
    /// The maximum number of Cloudflare runs per rolling hour, counted from the audit log.
    #[serde(default = "default_cf_runs")]
    pub max_runs_per_hour: u64,
    /// Host variable names to pass into the sandbox.
    #[serde(default)]
    pub env: Vec<String>,
}

impl Default for CloudflareBackend {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            key_env: default_cf_key_env(),
            network: Network::None,
            timeout_seconds: default_timeout(),
            max_upload_mb: default_cf_upload(),
            max_runs_per_hour: default_cf_runs(),
            env: Vec::new(),
        }
    }
}

fn default_cf_key_env() -> String {
    "AFG_CLOUDFLARE_KEY".into()
}
fn default_cf_upload() -> u64 {
    64
}
fn default_cf_runs() -> u64 {
    60
}

/// The effect a rule has when it matches.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    Allow,
    Route,
    RequireApproval,
    Deny,
}

impl Effect {
    /// Precedence, highest first: deny > require-approval > route > allow.
    pub fn severity(self) -> u8 {
        match self {
            Effect::Allow => 0,
            Effect::Route => 1,
            Effect::RequireApproval => 2,
            Effect::Deny => 3,
        }
    }
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Effect::Allow => "allow",
            Effect::Route => "route",
            Effect::RequireApproval => "require-approval",
            Effect::Deny => "deny",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub effect: Effect,
    /// Required for `route`. Optional for `allow` and `require-approval`,
    /// which default to `execution.default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendKind>,
    /// Each entry is an argv prefix: the executable name, then leading
    /// arguments. The element `*` matches any single argument.
    pub commands: Vec<Vec<String>>,
    /// Only for `allow` and `route` rules. If any argument after the prefix
    /// matches, the rule does not apply. A pattern `--flag` also matches
    /// `--flag=value`, and a trailing `*` makes the pattern a prefix match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_args: Vec<String>,
    /// Only for `allow` and `route` rules. When this is set, every flag after
    /// the prefix must match an entry, or the rule does not apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_flags: Option<Vec<String>>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AuditFormat {
    #[default]
    Json,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Audit {
    #[serde(default)]
    pub format: AuditFormat,
    #[serde(default = "yes")]
    pub redact_secrets: bool,
    #[serde(default = "default_audit_dir")]
    pub dir: String,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            format: AuditFormat::Json,
            redact_secrets: true,
            dir: default_audit_dir(),
        }
    }
}

fn default_audit_dir() -> String {
    ".agentforge/audit".into()
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid policy YAML: {0}")]
    Yaml(#[from] serde_norway::Error),
}

impl Policy {
    /// Parse a policy from YAML. This checks the syntax only; see
    /// [`crate::validate`] for the semantic checks.
    pub fn from_yaml(src: &str) -> Result<Self, ParseError> {
        Ok(serde_norway::from_str(src)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    const REFERENCE: &str = indoc! {r#"
        apiVersion: agentforge.dev/v1alpha1
        kind: AgentPolicy
        project:
          name: my-project
          root: "."
        agents: [claude-code, codex]
        execution:
          default: local
          fallback: deny
          backends:
            local: { enabled: true }
            container:
              enabled: true
              network: none
              readOnlyRootfs: true
              memoryMB: 2048
              cpus: 2
              timeoutSeconds: 300
            cloudflare: { enabled: false }
        rules:
          - id: read-only
            effect: allow
            commands: [["git", "diff"], ["git", "status"]]
            denyArgs: ["--ext-diff", "--output"]
          - id: isolated-scripts
            effect: route
            backend: container
            commands: [["bash"], ["sh"]]
          - id: infra
            effect: require-approval
            commands: [["kubectl", "apply"]]
          - id: destructive
            effect: deny
            commands: [["terraform", "destroy"]]
        audit:
          format: json
          redactSecrets: true
    "#};

    #[test]
    fn parses_reference_policy() {
        let p = Policy::from_yaml(REFERENCE).unwrap();
        assert_eq!(p.api_version, ApiVersion::V1Alpha1);
        assert_eq!(p.agents, vec![Agent::ClaudeCode, Agent::Codex]);
        assert_eq!(p.execution.fallback, Fallback::Deny);
        assert!(p.execution.backends.container.enabled);
        assert_eq!(p.execution.backends.container.network, Network::None);
        assert_eq!(p.rules.len(), 4);
        assert_eq!(p.rules[0].deny_args, vec!["--ext-diff", "--output"]);
        assert_eq!(p.rules[1].backend, Some(BackendKind::Container));
        assert_eq!(p.rules[3].effect, Effect::Deny);
    }

    #[test]
    fn minimal_policy_gets_fail_closed_defaults() {
        let p = Policy::from_yaml(indoc! {"
            apiVersion: agentforge.dev/v1alpha1
            kind: AgentPolicy
            project: { name: x }
        "})
        .unwrap();
        assert_eq!(p.execution.fallback, Fallback::Deny);
        assert_eq!(p.execution.default, BackendKind::Local);
        assert!(!p.execution.backends.container.enabled);
        assert!(p.audit.redact_secrets);
        assert!(p.rules.is_empty());
    }

    #[test]
    fn route_fallback_form() {
        let p = Policy::from_yaml(indoc! {"
            apiVersion: agentforge.dev/v1alpha1
            kind: AgentPolicy
            project: { name: x }
            execution:
              fallback: { route: container }
        "})
        .unwrap();
        assert_eq!(
            p.execution.fallback,
            Fallback::Route(BackendKind::Container)
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = Policy::from_yaml(indoc! {"
            apiVersion: agentforge.dev/v1alpha1
            kind: AgentPolicy
            project: { name: x }
            execution:
              backends:
                container: { enabled: true, netwrok: bridge }
        "})
        .unwrap_err();
        assert!(err.to_string().contains("netwrok"), "{err}");
    }

    #[test]
    fn rejects_unknown_api_version_and_effect() {
        assert!(
            Policy::from_yaml(
                "apiVersion: agentforge.dev/v9\nkind: AgentPolicy\nproject: {name: x}\n"
            )
            .is_err()
        );
        assert!(
            Policy::from_yaml(indoc! {"
            apiVersion: agentforge.dev/v1alpha1
            kind: AgentPolicy
            project: { name: x }
            rules: [{ id: a, effect: maybe, commands: [[ls]] }]
        "})
            .is_err()
        );
    }
}
