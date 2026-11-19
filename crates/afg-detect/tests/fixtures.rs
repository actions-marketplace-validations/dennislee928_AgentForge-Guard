//! Detection over the fixture repositories in `tests/language-detection/`.

use std::path::{Path, PathBuf};

use afg_detect::agents::AgentKind;
use afg_detect::risks::RiskLevel;
use afg_detect::{StackKind, Tier, detect_all};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/language-detection")
        .join(name)
}

fn summary(root: &Path) -> Vec<(StackKind, String)> {
    detect_all(root)
        .projects
        .into_iter()
        .map(|p| (p.kind, p.dir.display().to_string()))
        .collect()
}

#[test]
fn polyglot_monorepo() {
    let root = fixture("polyglot");
    assert_eq!(
        summary(&root),
        vec![
            (StackKind::Go, "services/api".into()),
            (StackKind::Rust, "services/worker".into()),
            (StackKind::Node, "web".into()),
        ],
        "the worker workspace covers its member crate, and node_modules is skipped"
    );

    let d = detect_all(&root);
    let web = d
        .projects
        .iter()
        .find(|p| p.kind == StackKind::Node)
        .unwrap();
    for t in ["pnpm", "typescript", "nextjs"] {
        assert!(web.traits.iter().any(|x| x == t), "{t}");
    }
    let web_cmds: Vec<_> = web
        .commands
        .iter()
        .map(|c| (c.argv.join(" "), c.tier))
        .collect();
    assert_eq!(
        web_cmds,
        vec![
            ("pnpm lint".into(), Tier::T1),
            ("pnpm typecheck".into(), Tier::T1),
            ("pnpm build".into(), Tier::T1),
            ("pnpm install".into(), Tier::T2),
        ]
    );
    let worker = d
        .projects
        .iter()
        .find(|p| p.kind == StackKind::Rust)
        .unwrap();
    assert!(
        worker
            .commands
            .iter()
            .any(|c| c.argv == ["cargo", "test", "--workspace"])
    );

    let agents: Vec<_> = d.agents.iter().map(|a| a.agent).collect();
    assert_eq!(agents, vec![AgentKind::ClaudeCode, AgentKind::Codex]);

    assert!(
        d.risks.iter().all(|r| r.level != RiskLevel::High),
        "{:?}",
        d.risks
    );
    assert!(d.risks.iter().any(|r| r.kind == "ci-config"));
    assert!(d.risks.iter().any(|r| r.kind == "secret-template"));
}

#[test]
fn js_workspace_reports_each_package() {
    let s = summary(&fixture("js-workspace"));
    assert_eq!(
        s,
        vec![
            (StackKind::Node, ".".into()),
            (StackKind::Node, "packages/a".into()),
            (StackKind::Node, "packages/b".into()),
        ]
    );
    let d = detect_all(&fixture("js-workspace"));
    assert!(d.projects[0].traits.iter().any(|t| t == "workspace"));
    assert_eq!(d.projects[0].commands[0].argv, ["npm", "test"]);
}

#[test]
fn empty_repo() {
    let d = detect_all(&fixture("empty"));
    assert!(d.projects.is_empty());
    assert!(d.agents.is_empty());
    assert!(d.risks.iter().any(|r| r.kind == "no-gitignore"));
}
