//! Command normalization (ADR 0003).
//!
//! The normalizer turns a raw argv into the command that will actually run:
//! it resolves the executable, unwraps known wrappers (`env`, `nice`,
//! `timeout`, ...) and strips harmless `git` global options. It also marks
//! commands whose effect cannot be known from argv as *opaque*: shells,
//! interpreters, indirect executors and suspicious arguments. Opaque commands
//! can never be allowed by an `allow` rule.
//!
//! Normalization never claims that a command is safe. It only removes known
//! ways of disguising one.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Why a command's effect cannot be determined from its argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
pub enum OpaqueReason {
    /// A shell interpreter (`sh`, `bash`, ...).
    Shell(String),
    /// A language interpreter (`python`, `node`, ...) that runs arbitrary code.
    Interpreter(String),
    /// A command that runs other commands (`xargs`, `make`, `find -exec`, ...).
    Indirect(String),
    /// A wrapper option or environment assignment that changes what runs.
    Wrapper(String),
    /// A `git` global option that can run code or redirect the repository.
    GitOption(String),
    /// Shell syntax (`$(`, backticks, `|`, `;`, ...) in an argument.
    ShellSyntax(String),
    /// Control or invisible Unicode characters in an argument.
    SuspiciousCharacters(usize),
    /// The executable is a non-ASCII name.
    NonAsciiExecutable(String),
    /// The executable was given as a path that is not what its bare name
    /// resolves to on `PATH`, for example a repo-local `./cargo`.
    UntrustedPath(String),
}

impl std::fmt::Display for OpaqueReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpaqueReason::Shell(s) => {
                write!(f, "`{s}` is a shell; its commands cannot be analyzed")
            }
            OpaqueReason::Interpreter(s) => {
                write!(f, "`{s}` is an interpreter that runs arbitrary code")
            }
            OpaqueReason::Indirect(s) => write!(f, "`{s}` runs other commands indirectly"),
            OpaqueReason::Wrapper(s) => write!(f, "wrapper option changes execution: {s}"),
            OpaqueReason::GitOption(s) => write!(
                f,
                "git option `{s}` can run code or redirect the repository"
            ),
            OpaqueReason::ShellSyntax(s) => {
                write!(f, "shell syntax `{s}` in argv (no shell is used)")
            }
            OpaqueReason::SuspiciousCharacters(i) => {
                write!(f, "argument {i} contains control or invisible characters")
            }
            OpaqueReason::NonAsciiExecutable(s) => write!(f, "non-ASCII executable name `{s}`"),
            OpaqueReason::UntrustedPath(s) => {
                write!(
                    f,
                    "`{s}` is not the executable that its name resolves to on PATH"
                )
            }
        }
    }
}

/// The result of normalizing an argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Normalized {
    /// The argv exactly as given.
    pub original: Vec<String>,
    /// The wrappers that were removed, outermost first.
    pub wrappers: Vec<String>,
    /// The effective executable name: lowercased basename, without `.exe`.
    pub name: String,
    /// The canonical absolute path of the executable, if it was found.
    pub program: Option<PathBuf>,
    /// The arguments after the effective executable, with harmless `git`
    /// globals removed.
    pub args: Vec<String>,
    /// The argv to execute: the program path (or name, if unresolved), then
    /// every original argument after the unwrapped executable. Wrappers are
    /// dropped, because afg applies its own timeout and environment.
    pub exec_argv: Vec<String>,
    /// The effective working directory (after `git -C`).
    pub cwd: PathBuf,
    pub opaque: Vec<OpaqueReason>,
    /// When set, the command must be denied whatever the policy says.
    pub forbidden: Option<String>,
}

impl Normalized {
    pub fn is_opaque(&self) -> bool {
        !self.opaque.is_empty()
    }
}

/// The environment used to resolve executables.
#[derive(Debug, Clone)]
pub struct Env<'a> {
    pub cwd: &'a Path,
    /// The value of `PATH`. Only absolute entries are searched.
    pub path: Option<&'a OsStr>,
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "ash",
    "fish",
    "csh",
    "tcsh",
    "busybox",
    "pwsh",
    "powershell",
    "cmd",
    "nu",
    "elvish",
    "xonsh",
];

const INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "osascript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "jshell",
    "irb",
    "Rscript",
    "julia",
    "expect",
];

const INDIRECT: &[&str] = &[
    "xargs",
    "parallel",
    "watch",
    "eval",
    "source",
    ".",
    "make",
    "gmake",
    "bmake",
    "just",
    "task",
    "ninja",
    "npx",
    "pnpx",
    "bunx",
    "ssh",
    "script",
    "screen",
    "tmux",
    "chroot",
    "unshare",
    "nsenter",
    "setsid",
    "flock",
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "valgrind",
    "runuser",
    "systemd-run",
    "at",
    "batch",
    "crontab",
];

const PRIVILEGE: &[&str] = &["sudo", "doas", "pkexec", "runas", "su"];

/// Lowercased basename without a `.exe` suffix.
pub fn exe_name(arg0: &str) -> String {
    let base = arg0.rsplit(['/', '\\']).next().unwrap_or(arg0);
    let lower = base.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_owned)
        .unwrap_or(lower)
}

/// True for executables that are always opaque, whatever their arguments.
pub fn is_opaque_name(name: &str) -> bool {
    SHELLS.contains(&name)
        || INTERPRETERS.iter().any(|i| i.eq_ignore_ascii_case(name))
        || INDIRECT.contains(&name)
        || is_versioned_interpreter(name)
}

/// `python3.12`, `node18`, `ruby3.3`, and similar.
fn is_versioned_interpreter(name: &str) -> bool {
    ["python", "node", "ruby", "perl", "php", "lua", "pypy"]
        .iter()
        .any(|p| {
            name.strip_prefix(p).is_some_and(|rest| {
                !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
            })
        })
}

fn is_executable_file(p: &Path) -> bool {
    match std::fs::metadata(p) {
        Ok(m) if m.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// Look up a bare name on the absolute entries of `PATH`.
pub fn resolve_in_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|c| is_executable_file(c))
        .and_then(|c| c.canonicalize().ok())
}

/// Resolve argv[0] to a canonical absolute path.
pub fn resolve_program(arg0: &str, env: &Env<'_>) -> Option<PathBuf> {
    if arg0.contains('/') || arg0.contains('\\') {
        let p = env.cwd.join(arg0);
        if is_executable_file(&p) {
            p.canonicalize().ok()
        } else {
            None
        }
    } else {
        resolve_in_path(arg0, env.path)
    }
}

fn is_suspicious_char(c: char) -> bool {
    (c.is_control() && c != '\t')
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

const SHELL_OPERATORS: &[&str] = &[
    "|", "||", "&&", ";", ";;", "&", ">", ">>", "<", "<<", "<<<", "2>", "2>&1", "&>", "|&",
];

fn shell_syntax(arg: &str) -> Option<String> {
    if SHELL_OPERATORS.contains(&arg) {
        return Some(arg.to_owned());
    }
    for pat in ["$(", "`", "${", "<(", ">("] {
        if arg.contains(pat) {
            return Some(pat.to_owned());
        }
    }
    None
}

/// Normalize an argv. This never fails: problems are reported through
/// [`Normalized::forbidden`] and [`Normalized::opaque`].
pub fn normalize(argv: &[String], env: &Env<'_>) -> Normalized {
    let mut out = Normalized {
        original: argv.to_vec(),
        wrappers: Vec::new(),
        name: String::new(),
        program: None,
        args: Vec::new(),
        exec_argv: Vec::new(),
        cwd: env.cwd.to_path_buf(),
        opaque: Vec::new(),
        forbidden: None,
    };

    let Some(first) = argv.first() else {
        out.forbidden = Some("empty argv".into());
        return out;
    };

    for (i, a) in argv.iter().enumerate() {
        if a.chars().any(is_suspicious_char) {
            out.opaque.push(OpaqueReason::SuspiciousCharacters(i));
        }
        if let Some(s) = shell_syntax(a) {
            out.opaque.push(OpaqueReason::ShellSyntax(s));
        }
    }
    if first.is_empty() || first.trim() != first {
        out.forbidden = Some("invalid executable name".into());
        return out;
    }

    // Unwrap wrappers.
    let mut idx = 0usize;
    loop {
        let Some(arg0) = argv.get(idx) else {
            // The wrapper had no command. Treat the last wrapper as the command.
            idx = idx.saturating_sub(1);
            out.wrappers.pop();
            break;
        };
        let name = exe_name(arg0);
        if PRIVILEGE.contains(&name.as_str()) {
            out.forbidden = Some(format!(
                "privilege escalation via `{name}` is never allowed"
            ));
            out.name = name;
            return out;
        }
        match unwrap_one(&name, &argv[idx + 1..]) {
            Unwrap::NotWrapper => break,
            Unwrap::Stop(reason) => {
                out.opaque.push(OpaqueReason::Wrapper(reason));
                break;
            }
            Unwrap::Inner { skip, opaque } => {
                if let Some(r) = opaque {
                    out.opaque.push(OpaqueReason::Wrapper(r));
                }
                out.wrappers.push(name);
                idx += 1 + skip;
            }
        }
    }

    let arg0 = &argv[idx];
    out.name = exe_name(arg0);
    out.program = resolve_program(arg0, env);
    let rest = &argv[idx + 1..];

    if !arg0.is_ascii() {
        out.opaque
            .push(OpaqueReason::NonAsciiExecutable(arg0.clone()));
    }
    if (arg0.contains('/') || arg0.contains('\\'))
        && out.program.is_some()
        && resolve_in_path(&out.name, env.path) != out.program
    {
        out.opaque.push(OpaqueReason::UntrustedPath(arg0.clone()));
    }

    let n = out.name.as_str();
    if SHELLS.contains(&n) {
        out.opaque.push(OpaqueReason::Shell(n.to_owned()));
    } else if INTERPRETERS.iter().any(|i| i.eq_ignore_ascii_case(n)) || is_versioned_interpreter(n)
    {
        out.opaque.push(OpaqueReason::Interpreter(n.to_owned()));
    } else if INDIRECT.contains(&n) {
        out.opaque.push(OpaqueReason::Indirect(n.to_owned()));
    } else if n == "find" {
        if let Some(a) = rest.iter().find(|a| {
            matches!(
                a.as_str(),
                "-exec" | "-execdir" | "-ok" | "-okdir" | "-delete"
            ) || a.starts_with("-fprint")
                || a.starts_with("-fls")
        }) {
            out.opaque.push(OpaqueReason::Indirect(format!("find {a}")));
        }
    } else if matches!(n, "npm" | "pnpm" | "yarn" | "bun")
        && rest
            .first()
            .is_some_and(|s| matches!(s.as_str(), "exec" | "x" | "dlx"))
    {
        out.opaque
            .push(OpaqueReason::Indirect(format!("{n} {}", rest[0])));
    } else if n == "rustup" && rest.first().is_some_and(|s| s == "run") {
        out.opaque.push(OpaqueReason::Indirect("rustup run".into()));
    }

    out.args = if n == "git" {
        normalize_git(rest, &mut out)
    } else {
        rest.to_vec()
    };

    out.exec_argv = std::iter::once(
        out.program
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| arg0.clone()),
    )
    .chain(rest.iter().cloned())
    .collect();
    out
}

enum Unwrap {
    NotWrapper,
    /// The inner command starts `skip` arguments after the wrapper name.
    Inner {
        skip: usize,
        opaque: Option<String>,
    },
    /// An unrecognized or dangerous wrapper option.
    Stop(String),
}

fn unwrap_one(name: &str, rest: &[String]) -> Unwrap {
    match name {
        "nohup" => Unwrap::Inner {
            skip: 0,
            opaque: None,
        },
        "time" => {
            let skip = rest.iter().take_while(|a| *a == "-p").count();
            Unwrap::Inner { skip, opaque: None }
        }
        "command" => match rest.first().map(String::as_str) {
            Some("-v" | "-V") => Unwrap::NotWrapper,
            Some("-p") | Some("--") => Unwrap::Inner {
                skip: 1,
                opaque: None,
            },
            Some(o) if o.starts_with('-') => Unwrap::Stop(format!("command {o}")),
            _ => Unwrap::Inner {
                skip: 0,
                opaque: None,
            },
        },
        "exec" => match rest.first().map(String::as_str) {
            Some("--") => Unwrap::Inner {
                skip: 1,
                opaque: None,
            },
            Some(o) if o.starts_with('-') => Unwrap::Stop(format!("exec {o}")),
            _ => Unwrap::Inner {
                skip: 0,
                opaque: None,
            },
        },
        "nice" => {
            let mut i = 0;
            while let Some(a) = rest.get(i) {
                if a == "-n" {
                    i += 2;
                } else if a == "--" {
                    i += 1;
                    break;
                } else if a.starts_with("--adjustment=")
                    || (a.starts_with('-')
                        && a.len() > 1
                        && a[1..].trim_start_matches('n').parse::<i32>().is_ok())
                {
                    i += 1;
                } else if a.starts_with('-') {
                    return Unwrap::Stop(format!("nice {a}"));
                } else {
                    break;
                }
            }
            Unwrap::Inner {
                skip: i,
                opaque: None,
            }
        }
        "timeout" => {
            let mut i = 0;
            while let Some(a) = rest.get(i) {
                match a.as_str() {
                    "-s" | "--signal" | "-k" | "--kill-after" => i += 2,
                    "--foreground" | "--preserve-status" | "-v" | "--verbose" => i += 1,
                    "--" => {
                        i += 1;
                        break;
                    }
                    s if s.starts_with("--signal=") || s.starts_with("--kill-after=") => i += 1,
                    s if s.starts_with('-') => return Unwrap::Stop(format!("timeout {s}")),
                    _ => break,
                }
            }
            // The duration comes next.
            if rest.get(i).is_none() {
                return Unwrap::Stop("timeout without a duration".into());
            }
            Unwrap::Inner {
                skip: i + 1,
                opaque: None,
            }
        }
        "env" => {
            let mut i = 0;
            let mut assignments = Vec::new();
            while let Some(a) = rest.get(i) {
                match a.as_str() {
                    "-i" | "--ignore-environment" | "-" => i += 1,
                    "-u" | "--unset" => i += 2,
                    "--" => {
                        i += 1;
                        break;
                    }
                    s if s.starts_with("--unset=") || (s.starts_with("-u") && s.len() > 2) => {
                        i += 1
                    }
                    s if s.starts_with('-') => return Unwrap::Stop(format!("env {s}")),
                    s if is_assignment(s) => {
                        assignments.push(s.split('=').next().unwrap_or(s).to_owned());
                        i += 1;
                    }
                    _ => break,
                }
            }
            // Assignments run after `--` too.
            while let Some(a) = rest.get(i) {
                if is_assignment(a) {
                    assignments.push(a.split('=').next().unwrap_or(a).to_owned());
                    i += 1;
                } else {
                    break;
                }
            }
            let opaque =
                (!assignments.is_empty()).then(|| format!("env sets {}", assignments.join(", ")));
            Unwrap::Inner { skip: i, opaque }
        }
        _ => Unwrap::NotWrapper,
    }
}

fn is_assignment(s: &str) -> bool {
    match s.split_once('=') {
        Some((k, _)) => {
            !k.is_empty()
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !k.starts_with(|c: char| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Harmless `git` global options, which are removed before matching.
const GIT_HARMLESS_GLOBALS: &[&str] = &[
    "-P",
    "--no-pager",
    "--no-replace-objects",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
    "--no-optional-locks",
    "--no-lazy-fetch",
    "--no-advice",
];

/// Global options that are really commands of their own.
const GIT_INFO_GLOBALS: &[&str] = &[
    "--version",
    "--help",
    "-h",
    "--html-path",
    "--man-path",
    "--info-path",
];

fn normalize_git(rest: &[String], out: &mut Normalized) -> Vec<String> {
    let mut i = 0;
    while let Some(a) = rest.get(i) {
        if GIT_HARMLESS_GLOBALS.contains(&a.as_str()) {
            i += 1;
        } else if a == "-C" {
            match rest.get(i + 1) {
                Some(dir) => {
                    out.cwd = out.cwd.join(dir);
                    i += 2;
                }
                None => {
                    out.opaque.push(OpaqueReason::GitOption("-C".into()));
                    return rest[i..].to_vec();
                }
            }
        } else if GIT_INFO_GLOBALS.contains(&a.as_str()) || !a.starts_with('-') {
            return rest[i..].to_vec();
        } else {
            let opt = a.split('=').next().unwrap_or(a).to_owned();
            out.opaque.push(OpaqueReason::GitOption(opt));
            return rest[i..].to_vec();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn norm(args: &[&str]) -> Normalized {
        let cwd = std::env::temp_dir();
        normalize(
            &v(args),
            &Env {
                cwd: &cwd,
                path: None,
            },
        )
    }

    #[test]
    fn plain_command() {
        let n = norm(&["cargo", "check", "--workspace"]);
        assert_eq!(n.name, "cargo");
        assert_eq!(n.args, v(&["check", "--workspace"]));
        assert!(!n.is_opaque());
        assert!(n.forbidden.is_none());
    }

    #[test]
    fn empty_and_blank_argv_forbidden() {
        assert!(norm(&[]).forbidden.is_some());
        assert!(norm(&[" git"]).forbidden.is_some());
        assert!(norm(&[""]).forbidden.is_some());
    }

    #[test]
    fn privilege_escalation_forbidden_even_when_wrapped() {
        assert!(norm(&["sudo", "ls"]).forbidden.is_some());
        assert!(norm(&["env", "doas", "ls"]).forbidden.is_some());
        assert!(
            norm(&["nice", "-n", "5", "/usr/bin/sudo", "ls"])
                .forbidden
                .is_some()
        );
    }

    #[test]
    fn unwraps_wrappers() {
        let n = norm(&[
            "timeout", "-s", "KILL", "30", "nice", "-n", "10", "nohup", "kubectl", "delete", "ns",
            "x",
        ]);
        assert_eq!(n.wrappers, v(&["timeout", "nice", "nohup"]));
        assert_eq!(n.name, "kubectl");
        assert_eq!(n.args, v(&["delete", "ns", "x"]));
        assert!(!n.is_opaque());
        assert_eq!(n.exec_argv, v(&["kubectl", "delete", "ns", "x"]));
    }

    #[test]
    fn env_assignments_are_opaque_but_unwrapped() {
        let n = norm(&["env", "LD_PRELOAD=/tmp/x.so", "terraform", "destroy"]);
        assert_eq!(n.name, "terraform");
        assert_eq!(n.args, v(&["destroy"]));
        assert!(
            n.opaque
                .iter()
                .any(|o| matches!(o, OpaqueReason::Wrapper(s) if s.contains("LD_PRELOAD")))
        );
    }

    #[test]
    fn env_split_string_stops() {
        let n = norm(&["env", "-S", "kubectl delete ns x"]);
        assert_eq!(n.name, "env");
        assert!(n.is_opaque());
    }

    #[test]
    fn bare_env_is_the_command() {
        let n = norm(&["env"]);
        assert_eq!(n.name, "env");
        assert!(n.wrappers.is_empty());
    }

    #[test]
    fn shells_interpreters_and_indirect_are_opaque() {
        for argv in [
            &["bash", "-c", "kubectl delete ns x"][..],
            &["/bin/sh", "script.sh"],
            &["env", "sh", "-c", "x"],
            &["python3", "-c", "import os"],
            &["python3.12", "x.py"],
            &["node", "-e", "1"],
            &["xargs", "rm"],
            &["make", "deploy"],
            &["find", ".", "-exec", "rm", "{}", ";"],
            &["find", ".", "-delete"],
            &["npx", "some-pkg"],
            &["pnpm", "dlx", "x"],
            &["ssh", "host", "rm -rf /"],
        ] {
            assert!(norm(argv).is_opaque(), "{argv:?} should be opaque");
        }
        assert!(!norm(&["find", ".", "-name", "*.rs"]).is_opaque());
    }

    #[test]
    fn shell_syntax_in_args_is_opaque() {
        for a in ["$(rm -rf ~)", "`id`", "${HOME}", "|", "&&", ";", ">"] {
            assert!(norm(&["git", "diff", a]).is_opaque(), "{a}");
        }
    }

    #[test]
    fn suspicious_characters_are_opaque() {
        assert!(norm(&["git", "diff\nrm"]).is_opaque());
        assert!(norm(&["git", "st\u{202E}atus"]).is_opaque());
        assert!(norm(&["kub\u{0435}ctl", "get"]).is_opaque(), "Cyrillic e");
    }

    #[test]
    fn git_globals() {
        let n = norm(&["git", "--no-pager", "-C", "sub", "status"]);
        assert_eq!(n.args, v(&["status"]));
        assert!(!n.is_opaque());
        assert!(n.cwd.ends_with("sub"));

        for argv in [
            &["git", "-c", "diff.external=/tmp/x", "diff"][..],
            &["git", "--config-env=core.pager=X", "log"],
            &["git", "--exec-path=/tmp", "status"],
            &["git", "--git-dir=/elsewhere", "status"],
            &["git", "-p", "log"],
        ] {
            let n = norm(argv);
            assert!(
                n.opaque
                    .iter()
                    .any(|o| matches!(o, OpaqueReason::GitOption(_))),
                "{argv:?}"
            );
        }
        assert_eq!(norm(&["git", "--version"]).args, v(&["--version"]));
    }

    #[test]
    fn names_are_case_folded() {
        assert_eq!(norm(&["Kubectl", "delete"]).name, "kubectl");
        assert_eq!(norm(&["TERRAFORM.EXE", "destroy"]).name, "terraform");
        assert!(norm(&["BASH", "-c", "x"]).is_opaque());
    }

    #[cfg(unix)]
    #[test]
    fn repo_local_binary_shadowing_path_is_untrusted() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("afg-norm-{}", std::process::id()));
        let bin = root.join("bin");
        let repo = root.join("repo");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        for p in [bin.join("cargo"), repo.join("cargo")] {
            std::fs::write(&p, "#!/bin/true\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([&bin]).unwrap();
        let env = Env {
            cwd: &repo,
            path: Some(&path),
        };

        let trusted = normalize(&v(&["cargo", "check"]), &env);
        assert_eq!(
            trusted.program,
            Some(bin.join("cargo").canonicalize().unwrap())
        );
        assert!(!trusted.is_opaque());

        let abs = bin.join("cargo").to_string_lossy().into_owned();
        assert!(!normalize(&v(&[&abs, "check"]), &env).is_opaque());

        let local = normalize(&v(&["./cargo", "check"]), &env);
        assert!(
            local
                .opaque
                .iter()
                .any(|o| matches!(o, OpaqueReason::UntrustedPath(_)))
        );

        // Relative PATH entries are ignored.
        let rel = std::env::join_paths(["."]).unwrap();
        let env = Env {
            cwd: &repo,
            path: Some(&rel),
        };
        assert_eq!(normalize(&v(&["cargo"]), &env).program, None);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
