//! Data-driven language profiles (`language-profiles/*.yaml`).
//!
//! A profile names marker files (exact names or `*` globs), optional traits
//! (a trait is present when its file exists), whether a project covers its
//! subdirectories, and the suggested commands. `{marker}` in a command is
//! replaced by the first marker that matched. Stacks whose detection needs
//! to parse manifests (Rust, Node) remain code detectors.

use std::collections::BTreeMap;
use std::path::Path;

use afg_core::paths::glob_match;
use serde::Deserialize;

use crate::{Detector, Project, StackKind, SuggestedCommand, Tier};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub kind: StackKind,
    pub markers: Vec<String>,
    #[serde(default)]
    pub traits: BTreeMap<String, String>,
    #[serde(default)]
    pub covers_children_if: Option<String>,
    /// `{ file, key }`: read `key = "value"` from `file` and report the
    /// trait `min-version:<value>`.
    #[serde(default)]
    pub min_version: Option<VersionField>,
    pub commands: Vec<ProfileCommand>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionField {
    pub file: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCommand {
    pub tier: Tier,
    pub argv: Vec<String>,
    pub purpose: String,
}

/// The built-in profiles, embedded at build time.
pub const BUILTIN: &[(&str, &str)] = &[("go", include_str!("../../../language-profiles/go.yaml"))];

pub fn builtin_profiles() -> Vec<Profile> {
    BUILTIN
        .iter()
        .map(|(name, src)| {
            serde_norway::from_str(src).unwrap_or_else(|e| panic!("language profile {name}: {e}"))
        })
        .collect()
}

pub struct ProfileDetector(pub Profile);

fn first_marker(dir: &Path, markers: &[String]) -> Option<String> {
    let mut names: Option<Vec<String>> = None;
    for m in markers {
        if m.contains('*') {
            let list = names.get_or_insert_with(|| {
                let mut v: Vec<String> = std::fs::read_dir(dir)
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                v.sort();
                v
            });
            if let Some(n) = list.iter().find(|n| glob_match(m, n)) {
                return Some(n.clone());
            }
        } else if dir.join(m).is_file() {
            return Some(m.clone());
        }
    }
    None
}

/// Read `key = "value"` (also `.key = "value"`, as in build.zig.zon).
fn read_version(dir: &Path, f: &VersionField) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(&f.file)).ok()?;
    text.lines().find_map(|l| {
        let l = l.trim().trim_start_matches('.');
        let rest = l
            .strip_prefix(&f.key)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        let v = rest.trim_end_matches(',').trim().trim_matches('"');
        (!v.is_empty()
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c)))
        .then(|| v.to_owned())
    })
}

impl Detector for ProfileDetector {
    fn kind(&self) -> StackKind {
        self.0.kind
    }

    fn detect(&self, dir: &Path, rel: &Path) -> Option<Project> {
        let p = &self.0;
        let first = first_marker(dir, &p.markers)?;
        let mut markers: Vec<String> = p
            .markers
            .iter()
            .filter(|m| !m.contains('*') && dir.join(m).is_file())
            .cloned()
            .collect();
        if !markers.contains(&first) {
            markers.insert(0, first.clone());
        }
        let mut traits: Vec<String> = p
            .traits
            .iter()
            .filter(|(_, file)| dir.join(file).is_file())
            .map(|(t, _)| t.clone())
            .collect();
        if let Some(v) = p.min_version.as_ref().and_then(|f| read_version(dir, f)) {
            traits.push(format!("min-version:{v}"));
        }
        let commands = p
            .commands
            .iter()
            .map(|c| SuggestedCommand {
                argv: c
                    .argv
                    .iter()
                    .map(|a| a.replace("{marker}", &first))
                    .collect(),
                tier: c.tier,
                purpose: c.purpose.clone(),
            })
            .collect();
        Some(Project {
            kind: p.kind,
            dir: rel.to_path_buf(),
            markers,
            traits,
            commands,
        })
    }

    fn covers_children(&self, project: &Project) -> bool {
        self.0
            .covers_children_if
            .as_ref()
            .is_some_and(|t| project.traits.contains(t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtin_profiles_parse() {
        assert_eq!(builtin_profiles().len(), BUILTIN.len());
    }
}
