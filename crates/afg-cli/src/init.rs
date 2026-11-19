//! `afg init`: write agentforge.yaml from a built-in policy plus rules for
//! the commands that detection found.
//!
//! Init only reads files. It never downloads, installs or runs anything.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use afg_core::{Effect, Engine, EvalRequest, Policy};
use afg_detect::agents::AgentKind;
use afg_detect::{Detection, Tier, detect_all};
use anyhow::{Context, bail};

use crate::POLICY_FILE;

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// The repository root (default: the current directory).
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// The built-in policy to start from.
    #[arg(long, default_value = "default", value_parser = ["default", "strict", "ci"])]
    pub template: String,
    /// Overwrite an existing agentforge.yaml.
    #[arg(long)]
    pub force: bool,
    /// Print the policy instead of writing it.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(a: InitArgs) -> anyhow::Result<ExitCode> {
    let dir = match a.dir {
        Some(d) => d,
        None => std::env::current_dir()?,
    };
    let dir = dir
        .canonicalize()
        .with_context(|| format!("resolving {}", dir.display()))?;
    let target = dir.join(POLICY_FILE);
    if target.exists() && !a.force && !a.dry_run {
        bail!(
            "{} already exists; pass --force to overwrite it",
            target.display()
        );
    }
    let detection = detect_all(&dir);
    let yaml = generate(&dir, &a.template, &detection)?;
    if a.dry_run {
        print!("{yaml}");
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::write(&target, &yaml).with_context(|| format!("writing {}", target.display()))?;
    eprintln!("afg: wrote {}", target.display());
    if let Some(home) = crate::project::home_dir() {
        let parsed = afg_core::Policy::from_yaml(&yaml)?;
        let hash = afg_core::eval::policy_hash(&parsed);
        crate::trust::pin(&home, &target, &hash)?;
        eprintln!(
            "  trusted this policy; edits to it will deny commands until `afg policy trust` is run again"
        );
    }
    for p in &detection.projects {
        eprintln!("  detected {:?} project in {}", p.kind, p.dir.display());
    }
    let gi = std::fs::read_to_string(dir.join(".gitignore")).unwrap_or_default();
    if !gi
        .lines()
        .any(|l| l.trim().trim_start_matches('/').starts_with(".agentforge"))
    {
        eprintln!("  hint: add `.agentforge/` to .gitignore; it holds local audit logs");
    }
    eprintln!("  next: `afg doctor`, then review the generated rules in {POLICY_FILE}");
    Ok(ExitCode::SUCCESS)
}

fn yaml_list(argv: &[String]) -> String {
    let items: Vec<String> = argv
        .iter()
        .map(|a| serde_json::to_string(a).expect("string"))
        .collect();
    format!("[{}]", items.join(", "))
}

/// Generate the policy text. Comments in the template are kept.
pub fn generate(dir: &Path, template: &str, d: &Detection) -> anyhow::Result<String> {
    let src = afg_core::builtin::policy_source(template).context("unknown template")?;
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let mut out = src.replace(
        "  name: my-project\n",
        &format!("  name: {}\n", serde_json::to_string(&name)?),
    );

    if !d.agents.is_empty() {
        let agents: Vec<&str> = d
            .agents
            .iter()
            .map(|a| match a.agent {
                AgentKind::ClaudeCode => "claude-code",
                AgentKind::Codex => "codex",
            })
            .collect();
        out = out.replacen(
            "agents: [claude-code, codex]\n",
            &format!("agents: [{}]\n", agents.join(", ")),
            1,
        );
    }

    // Find the detected commands that the template doesn't already handle.
    let base = Policy::from_yaml(&out)?;
    let engine = Engine::new(base, dir, None);
    let mut validation: Vec<Vec<String>> = Vec::new();
    let mut deps: Vec<Vec<String>> = Vec::new();
    let template_routes_t1 = template == "strict";
    for p in &d.projects {
        let cwd = dir.join(&p.dir);
        for c in &p.commands {
            let dec = engine.evaluate(&EvalRequest {
                argv: &c.argv,
                cwd: &cwd,
                path_env: None,
                requested_backend: None,
            });
            if dec.effect != Effect::Deny {
                continue;
            }
            let bucket = match c.tier {
                Tier::T0 | Tier::T1 if !dec.normalized.is_opaque() && !template_routes_t1 => {
                    &mut validation
                }
                Tier::T2 if template == "default" => &mut deps,
                _ => continue,
            };
            if !bucket.contains(&c.argv) {
                bucket.push(c.argv.clone());
            }
        }
    }

    let mut extra = String::new();
    if !validation.is_empty() || !deps.is_empty() {
        extra.push_str(
            "  # Generated by `afg init` from detected projects. Review before committing.\n",
        );
    }
    if !validation.is_empty() {
        extra.push_str("  - id: detected-validation\n    effect: allow\n    commands:\n");
        for v in &validation {
            extra.push_str(&format!("      - {}\n", yaml_list(v)));
        }
        extra.push_str("    denyArgs: [--config*]\n\n");
    }
    if !deps.is_empty() {
        extra.push_str(
            "  - id: detected-dependencies\n    effect: require-approval\n    commands:\n",
        );
        for v in &deps {
            extra.push_str(&format!("      - {}\n", yaml_list(v)));
        }
        extra.push('\n');
    }
    if !extra.is_empty() {
        let at = out
            .find("\naudit:")
            .context("template has no audit section")?;
        out.insert_str(at + 1, &extra);
    }

    // The generated text must still be a valid policy.
    let parsed = Policy::from_yaml(&out).context("generated policy does not parse")?;
    let issues = afg_core::validate::validate(&parsed);
    if afg_core::validate::has_errors(&issues) {
        bail!("generated policy is invalid: {issues:?}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/language-detection")
            .join(name)
            .canonicalize()
            .unwrap()
    }

    /// The consistency rule from the Phase 2 alignment: every detected T0/T1
    /// command is allowed by the generated policy, and no T2 command is
    /// allowed to run locally.
    #[test]
    fn generated_policy_is_consistent_with_detection() {
        for fx in ["polyglot", "js-workspace", "empty", "zig", "python", "mojo"] {
            let dir = fixture(fx);
            let d = detect_all(&dir);
            let yaml = generate(&dir, "default", &d).unwrap();
            let engine = Engine::new(Policy::from_yaml(&yaml).unwrap(), &dir, None);
            for p in &d.projects {
                let cwd = dir.join(&p.dir);
                for c in &p.commands {
                    let dec = engine.evaluate(&EvalRequest {
                        argv: &c.argv,
                        cwd: &cwd,
                        path_env: None,
                        requested_backend: None,
                    });
                    match c.tier {
                        Tier::T0 | Tier::T1 => assert_eq!(
                            dec.effect,
                            Effect::Allow,
                            "{fx}: {:?} {:?}",
                            c.argv,
                            dec.reasons
                        ),
                        _ => assert!(
                            !(dec.effect == Effect::Allow
                                && dec.backend == Some(afg_core::BackendKind::Local)),
                            "{fx}: T2 {:?} must not run locally without approval",
                            c.argv
                        ),
                    }
                }
            }
        }
    }

    #[test]
    fn polyglot_output() {
        let dir = fixture("polyglot");
        let yaml = generate(&dir, "default", &detect_all(&dir)).unwrap();
        assert!(yaml.contains("  name: \"polyglot\"\n"));
        assert!(yaml.contains("id: detected-dependencies"));
        assert!(yaml.contains(r#"["go", "mod", "download"]"#));
        assert!(yaml.contains(r#"["cargo", "fetch"]"#));
        assert!(
            yaml.contains("# AgentForge Guard default policy"),
            "template comments kept"
        );
    }

    #[test]
    fn strict_and_ci_add_no_local_allows() {
        let dir = fixture("polyglot");
        for t in ["strict", "ci"] {
            let yaml = generate(&dir, t, &detect_all(&dir)).unwrap();
            assert!(!yaml.contains("detected-dependencies"), "{t}");
        }
    }
}
