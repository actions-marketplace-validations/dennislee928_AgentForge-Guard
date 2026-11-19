//! Node.js, TypeScript and Next.js projects.

use std::path::Path;

use crate::{Detector, Project, StackKind, SuggestedCommand, Tier};

pub struct NodeDetector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl PackageManager {
    fn name(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Yarn => "yarn",
            PackageManager::Bun => "bun",
        }
    }

    /// The argv that runs a package script.
    fn script(self, s: &str) -> Vec<String> {
        let v: Vec<&str> = match self {
            PackageManager::Npm if s == "test" => vec!["npm", "test"],
            PackageManager::Npm => vec!["npm", "run", s],
            PackageManager::Pnpm => vec!["pnpm", s],
            PackageManager::Yarn => vec!["yarn", s],
            PackageManager::Bun => vec!["bun", "run", s],
        };
        v.into_iter().map(String::from).collect()
    }

    fn install(self, locked: bool) -> Vec<&'static str> {
        match self {
            PackageManager::Npm if locked => vec!["npm", "ci"],
            PackageManager::Npm => vec!["npm", "install"],
            PackageManager::Pnpm => vec!["pnpm", "install"],
            PackageManager::Yarn => vec!["yarn", "install"],
            PackageManager::Bun => vec!["bun", "install"],
        }
    }
}

const LOCKFILES: &[(&str, PackageManager)] = &[
    ("pnpm-lock.yaml", PackageManager::Pnpm),
    ("yarn.lock", PackageManager::Yarn),
    ("bun.lock", PackageManager::Bun),
    ("bun.lockb", PackageManager::Bun),
    ("package-lock.json", PackageManager::Npm),
    ("npm-shrinkwrap.json", PackageManager::Npm),
];

const NEXT_CONFIGS: &[&str] = &[
    "next.config.js",
    "next.config.mjs",
    "next.config.cjs",
    "next.config.ts",
];

/// Package scripts that afg suggests, in order.
const VERIFY_SCRIPTS: &[&str] = &["lint", "typecheck", "test", "build"];

/// Scripts that npm runs automatically during install.
const LIFECYCLE: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

impl Detector for NodeDetector {
    fn kind(&self) -> StackKind {
        StackKind::Node
    }

    fn detect(&self, dir: &Path, rel: &Path) -> Option<Project> {
        let src = std::fs::read_to_string(dir.join("package.json")).ok()?;
        let pkg: serde_json::Value = serde_json::from_str(&src).unwrap_or_default();
        let mut markers = vec!["package.json".to_string()];
        let mut traits = Vec::new();

        let mut pm = None;
        let mut locked = false;
        for (file, m) in LOCKFILES {
            if dir.join(file).is_file() {
                markers.push((*file).into());
                pm.get_or_insert(*m);
                locked = true;
            }
        }
        if let Some(field) = pkg.get("packageManager").and_then(|v| v.as_str()) {
            let name = field.split('@').next().unwrap_or("");
            pm = match name {
                "pnpm" => Some(PackageManager::Pnpm),
                "yarn" => Some(PackageManager::Yarn),
                "bun" => Some(PackageManager::Bun),
                "npm" => Some(PackageManager::Npm),
                _ => pm,
            };
        }
        let pm = pm.unwrap_or(PackageManager::Npm);
        traits.push(pm.name().to_string());
        if !locked {
            traits.push("no-lockfile".into());
        }

        let has_dep = |name: &str| {
            ["dependencies", "devDependencies"]
                .iter()
                .any(|k| pkg.get(k).and_then(|d| d.get(name)).is_some())
        };
        let ts = dir.join("tsconfig.json").is_file();
        if ts {
            markers.push("tsconfig.json".into());
            traits.push("typescript".into());
        }
        let next_cfg = NEXT_CONFIGS.iter().find(|f| dir.join(f).is_file());
        if let Some(f) = next_cfg {
            markers.push((*f).into());
        }
        if next_cfg.is_some() || has_dep("next") {
            traits.push("nextjs".into());
        }
        if dir.join("pnpm-workspace.yaml").is_file() || pkg.get("workspaces").is_some() {
            traits.push("workspace".into());
        }

        let scripts = pkg.get("scripts").and_then(|s| s.as_object());
        let has_script = |s: &str| scripts.is_some_and(|m| m.contains_key(s));
        if LIFECYCLE.iter().any(|s| has_script(s)) {
            traits.push("lifecycle-scripts".into());
        }

        let mut commands = Vec::new();
        for s in VERIFY_SCRIPTS {
            if has_script(s) {
                commands.push(SuggestedCommand {
                    argv: pm.script(s),
                    tier: Tier::T1,
                    purpose: format!("package script `{s}`"),
                });
            }
        }
        if ts
            && !has_script("typecheck")
            && matches!(pm, PackageManager::Pnpm | PackageManager::Yarn)
        {
            commands.push(SuggestedCommand::new(
                &[pm.name(), "tsc", "--noEmit"],
                Tier::T1,
                "type check",
            ));
        }
        commands.push(SuggestedCommand::new(
            &pm.install(locked),
            Tier::T2,
            "install dependencies (runs lifecycle scripts; needs network)",
        ));

        Some(Project {
            kind: StackKind::Node,
            dir: rel.to_path_buf(),
            markers,
            traits,
            commands,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;

    fn detect(t: &Tree) -> Project {
        NodeDetector.detect(t.path(), Path::new(".")).unwrap()
    }

    #[test]
    fn next_app_with_pnpm() {
        let t = Tree::new("node-next");
        t.file(
            "package.json",
            r#"{"scripts":{"dev":"next dev","build":"next build","lint":"next lint","postinstall":"x"},"dependencies":{"next":"15"}}"#,
        )
        .file("pnpm-lock.yaml", "")
        .file("tsconfig.json", "{}")
        .file("next.config.ts", "");
        let p = detect(&t);
        for tr in ["pnpm", "typescript", "nextjs", "lifecycle-scripts"] {
            assert!(p.traits.contains(&tr.to_string()), "{tr}");
        }
        let argvs: Vec<_> = p.commands.iter().map(|c| c.argv.join(" ")).collect();
        assert_eq!(
            argvs,
            vec![
                "pnpm lint",
                "pnpm build",
                "pnpm tsc --noEmit",
                "pnpm install"
            ]
        );
        assert_eq!(p.commands.last().unwrap().tier, Tier::T2);
        assert!(
            !argvs.iter().any(|a| a.contains("dev")),
            "dev servers are not suggested"
        );
    }

    #[test]
    fn npm_with_lockfile_uses_ci() {
        let t = Tree::new("node-npm");
        t.file(
            "package.json",
            r#"{"scripts":{"test":"jest","lint":"eslint ."}}"#,
        )
        .file("package-lock.json", "{}");
        let argvs: Vec<_> = detect(&t)
            .commands
            .iter()
            .map(|c| c.argv.join(" "))
            .collect();
        assert_eq!(argvs, vec!["npm run lint", "npm test", "npm ci"]);
    }

    #[test]
    fn package_manager_field_wins_and_missing_lockfile_flagged() {
        let t = Tree::new("node-pmfield");
        t.file("package.json", r#"{"packageManager":"yarn@4.5.0"}"#);
        let p = detect(&t);
        assert!(p.traits.contains(&"yarn".to_string()));
        assert!(p.traits.contains(&"no-lockfile".to_string()));
    }

    #[test]
    fn invalid_package_json_is_still_a_project() {
        let t = Tree::new("node-bad");
        t.file("package.json", "{ nope");
        assert_eq!(detect(&t).kind, StackKind::Node);
    }
}
