//! Coding-agent configuration in a repository.

use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentKind {
    ClaudeCode,
    Codex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentPresence {
    pub agent: AgentKind,
    pub markers: Vec<String>,
}

const MARKERS: &[(AgentKind, &[&str])] = &[
    (
        AgentKind::ClaudeCode,
        &[
            "CLAUDE.md",
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".claude",
        ],
    ),
    (
        AgentKind::Codex,
        &["AGENTS.md", ".codex/config.toml", ".codex"],
    ),
];

/// The agents whose configuration exists at the repository root.
pub fn detect_agents(root: &Path) -> Vec<AgentPresence> {
    MARKERS
        .iter()
        .filter_map(|(agent, files)| {
            let markers: Vec<String> = files
                .iter()
                .filter(|f| root.join(f).exists())
                .map(|f| f.to_string())
                .collect();
            (!markers.is_empty()).then_some(AgentPresence {
                agent: *agent,
                markers,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;

    #[test]
    fn detects_both_agents() {
        let t = Tree::new("agents");
        t.file("CLAUDE.md", "")
            .file(".claude/settings.json", "{}")
            .file("AGENTS.md", "");
        let a = detect_agents(t.path());
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].agent, AgentKind::ClaudeCode);
        assert_eq!(
            a[0].markers,
            vec!["CLAUDE.md", ".claude/settings.json", ".claude"]
        );
        assert_eq!(a[1].markers, vec!["AGENTS.md"]);
    }

    #[test]
    fn none() {
        let t = Tree::new("agents-none");
        assert!(detect_agents(t.path()).is_empty());
    }
}
