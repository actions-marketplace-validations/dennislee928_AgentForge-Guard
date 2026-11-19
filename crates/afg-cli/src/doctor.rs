//! `afg doctor`: detection, policy decisions for the detected commands,
//! backend availability and risks.

use std::process::ExitCode;

use afg_core::{BackendKind, Effect, EvalRequest};
use afg_detect::{Detection, Tier, detect_all};
use serde::Serialize;

use crate::backends::docker_executor;
use crate::project::{self, home_dir};

#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    policy: PolicyStatus,
    backends: Vec<BackendStatus>,
    commands: Vec<CommandStatus>,
    #[serde(flatten)]
    detection: Detection,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyStatus {
    path: String,
    hash: String,
    trust: String,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendStatus {
    backend: BackendKind,
    enabled: bool,
    available: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandStatus {
    dir: String,
    argv: Vec<String>,
    tier: Tier,
    effect: Effect,
    backend: Option<BackendKind>,
    rule_id: String,
}

pub async fn run(a: DoctorArgs) -> anyhow::Result<ExitCode> {
    let cwd = std::env::current_dir()?;
    let p = project::load(&cwd)?;
    let policy = p.engine.policy();
    let detection = detect_all(&p.root);
    let path = std::env::var_os("PATH");

    let mut commands = Vec::new();
    for proj in &detection.projects {
        let dir = p.root.join(&proj.dir);
        for c in &proj.commands {
            let d = p.engine.evaluate(&EvalRequest {
                argv: &c.argv,
                cwd: &dir,
                path_env: path.as_deref(),
                requested_backend: None,
            });
            commands.push(CommandStatus {
                dir: proj.dir.display().to_string(),
                argv: c.argv.clone(),
                tier: c.tier,
                effect: d.effect,
                backend: d.backend,
                rule_id: d.rule_id,
            });
        }
    }

    let b = &policy.execution.backends;
    let mut backends = vec![BackendStatus {
        backend: BackendKind::Local,
        enabled: b.local.enabled,
        available: true,
        detail: format!("env allowlist: {}", b.local.env.join(", ")),
    }];
    let (available, detail) = if !b.container.enabled {
        (false, "disabled in policy".to_owned())
    } else {
        match docker_executor(policy, &p.root, home_dir().as_deref()) {
            Err(e) => (false, format!("{e:#}")),
            Ok(x) => match x.check_available().await {
                Err(e) => (false, e.to_string()),
                Ok(v) => {
                    let image = image_status(&b.container.image).await;
                    (
                        true,
                        format!(
                            "docker {v}; image {} {image}; network {:?}",
                            b.container.image, b.container.network
                        )
                        .to_lowercase(),
                    )
                }
            },
        }
    };
    backends.push(BackendStatus {
        backend: BackendKind::Container,
        enabled: b.container.enabled,
        available,
        detail,
    });
    let cf = &b.cloudflare;
    let (available, detail) = if !cf.enabled {
        (false, "disabled in policy".to_owned())
    } else {
        match crate::backends::cloudflare_executor(policy, &p.root, home_dir().as_deref()) {
            Ok(_) => (
                true,
                format!(
                    "endpoint {}; key ok; network {:?}; upload cap {} MB",
                    cf.endpoint.as_deref().unwrap_or("-"),
                    cf.network,
                    cf.max_upload_mb
                )
                .to_lowercase(),
            ),
            Err(e) => (false, format!("{e:#}")),
        }
    };
    backends.push(BackendStatus {
        backend: BackendKind::Cloudflare,
        enabled: cf.enabled,
        available,
        detail,
    });

    let report = Report {
        policy: PolicyStatus {
            path: p.policy_path.display().to_string(),
            hash: p.engine.policy_hash().to_owned(),
            trust: match &p.trust {
                crate::trust::Status::Trusted => "trusted".into(),
                crate::trust::Status::Unpinned => "not pinned (run `afg policy trust`)".into(),
                crate::trust::Status::Changed { .. } => {
                    "CHANGED since trusted: every command is denied".into()
                }
            },
            warnings: p.warnings.clone(),
        },
        backends,
        commands,
        detection,
    };
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&report);
    }
    Ok(ExitCode::SUCCESS)
}

async fn image_status(image: &str) -> &'static str {
    let ok = tokio::process::Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success());
    if ok {
        "present"
    } else {
        "missing (pulled on first run)"
    }
}

fn print_human(r: &Report) {
    println!("policy    {} ({})", r.policy.path, r.policy.hash);
    println!("trust     {}", r.policy.trust);
    for w in &r.policy.warnings {
        println!("  {w}");
    }
    println!("\nbackends");
    for b in &r.backends {
        let state = match (b.enabled, b.available) {
            (true, true) => "ok",
            (true, false) => "UNAVAILABLE",
            (false, _) => "disabled",
        };
        println!("  {:<11} {:<12} {}", b.backend.to_string(), state, b.detail);
    }
    println!("\nprojects");
    if r.detection.projects.is_empty() {
        println!("  (none detected)");
    }
    for p in &r.detection.projects {
        let traits = if p.traits.is_empty() {
            String::new()
        } else {
            format!(" [{}]", p.traits.join(", "))
        };
        println!("  {:?} in {}{traits}", p.kind, p.dir.display());
        for c in r
            .commands
            .iter()
            .filter(|c| c.dir == p.dir.display().to_string())
        {
            let backend = c
                .backend
                .map(|b| b.to_string())
                .unwrap_or_else(|| "-".into());
            println!(
                "    {:?}  {:<16} {:<9} {:<28} {}",
                c.tier,
                c.effect.to_string(),
                backend,
                c.argv.join(" "),
                c.rule_id
            );
        }
    }
    println!("\nagents");
    if r.detection.agents.is_empty() {
        println!("  (none detected)");
    }
    for a in &r.detection.agents {
        println!("  {:?}: {}", a.agent, a.markers.join(", "));
    }
    println!("\nrisks");
    if r.detection.risks.is_empty() {
        println!("  (none)");
    }
    for k in &r.detection.risks {
        println!(
            "  {:<5} {}",
            format!("{:?}", k.level).to_uppercase(),
            k.message
        );
    }
}
