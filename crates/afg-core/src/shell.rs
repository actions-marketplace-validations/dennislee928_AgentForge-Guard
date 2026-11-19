//! A conservative tokenizer for shell command *strings*, which agent hooks
//! receive (for example Claude Code's `Bash` tool input).
//!
//! It understands only:
//! - words;
//! - single quotes, double quotes and backslash escapes;
//! - the separators `;`, `&&`, `||`, `|`, `|&`, `&` and newline.
//!
//! Anything whose meaning depends on the shell at run time makes the whole
//! string [`Unparseable`]: expansions (`$`, backticks), globs (`*?[`),
//! redirections (`<`, `>`), subshells and grouping (`(`, `)`, `{`, `}`),
//! comments, and dangling operators. Callers must then treat the string as
//! an opaque shell program (ADR 0003).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unparseable(pub String);

impl std::fmt::Display for Unparseable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shell string cannot be analyzed: {}", self.0)
    }
}

/// Split a command string into simple commands (one argv each).
pub fn split_commands(src: &str) -> Result<Vec<Vec<String>>, Unparseable> {
    let err = |m: &str| Err(Unparseable(m.to_owned()));
    let mut cmds: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    // True right after a separator that needs a following command (&&, ||, |).
    let mut need_cmd = false;
    let mut chars = src.chars().peekable();

    macro_rules! end_word {
        () => {
            if in_word {
                cur.push(std::mem::take(&mut word));
                in_word = false;
            }
        };
    }
    macro_rules! end_cmd {
        ($needs:expr) => {{
            end_word!();
            if cur.is_empty() {
                if $needs || need_cmd {
                    return err("operator without a command");
                }
            } else {
                cmds.push(std::mem::take(&mut cur));
            }
            need_cmd = $needs;
        }};
    }

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => end_word!(),
            '\n' => end_cmd!(false),
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => word.push(ch),
                        None => return err("unterminated single quote"),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(ch @ ('"' | '\\')) => word.push(ch),
                            Some('$' | '`') => return err("expansion inside double quotes"),
                            Some('\n') => {}
                            Some(ch) => {
                                word.push('\\');
                                word.push(ch);
                            }
                            None => return err("unterminated double quote"),
                        },
                        Some('$') | Some('`') => return err("expansion inside double quotes"),
                        Some(ch) => word.push(ch),
                        None => return err("unterminated double quote"),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(ch) => {
                    in_word = true;
                    word.push(ch);
                }
                None => return err("trailing backslash"),
            },
            ';' => {
                if chars.peek() == Some(&';') {
                    return err("`;;`");
                }
                end_cmd!(false)
            }
            '&' => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                    end_cmd!(true)
                } else if chars.peek() == Some(&'>') {
                    return err("redirection");
                } else {
                    end_cmd!(false)
                }
            }
            '|' => {
                if matches!(chars.peek(), Some('|') | Some('&')) {
                    chars.next();
                }
                end_cmd!(true)
            }
            '$' | '`' => return err("expansion or substitution"),
            '<' | '>' => return err("redirection"),
            '(' | ')' => return err("subshell or grouping"),
            '*' | '?' | '[' => return err("glob pattern"),
            '{' | '}' if !in_word => return err("grouping or brace expansion"),
            '#' if !in_word => return err("comment"),
            '!' if !in_word => return err("`!` (negation or history expansion)"),
            ch => {
                in_word = true;
                word.push(ch);
            }
        }
    }
    if in_word {
        cur.push(word);
    }
    if !cur.is_empty() {
        cmds.push(cur);
    } else if need_cmd {
        return err("operator without a command");
    }
    Ok(cmds)
}

/// Leading `NAME=value` words. The shell applies them as environment
/// changes for the command, so they are rewritten as an explicit `env`
/// wrapper, which the normalizer treats as opaque.
pub fn hoist_assignments(argv: Vec<String>) -> Vec<String> {
    let n = argv.iter().take_while(|w| is_assignment(w)).count();
    if n == 0 || n == argv.len() {
        return argv;
    }
    std::iter::once("env".to_owned()).chain(argv).collect()
}

fn is_assignment(s: &str) -> bool {
    s.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !k.starts_with(|c: char| c.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Vec<Vec<String>> {
        split_commands(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }
    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn words_and_quotes() {
        assert_eq!(
            ok("cargo test --workspace"),
            vec![v(&["cargo", "test", "--workspace"])]
        );
        assert_eq!(
            ok(r#"git commit -m "fix: a \"b\"" "#),
            vec![v(&["git", "commit", "-m", "fix: a \"b\""])]
        );
        assert_eq!(ok("echo 'a $b `c`'"), vec![v(&["echo", "a $b `c`"])]);
        assert_eq!(ok(r"ls my\ dir"), vec![v(&["ls", "my dir"])]);
        assert_eq!(ok("ls ''"), vec![v(&["ls", ""])]);
        assert_eq!(ok("  "), Vec::<Vec<String>>::new());
    }

    #[test]
    fn separators() {
        assert_eq!(
            ok("cd web && pnpm lint; git status | head -n 5\ncargo test || true"),
            vec![
                v(&["cd", "web"]),
                v(&["pnpm", "lint"]),
                v(&["git", "status"]),
                v(&["head", "-n", "5"]),
                v(&["cargo", "test"]),
                v(&["true"]),
            ]
        );
        assert_eq!(ok("sleep 1 &"), vec![v(&["sleep", "1"])]);
    }

    #[test]
    fn unparseable() {
        for s in [
            "echo $HOME",
            "echo \"$(id)\"",
            "echo `id`",
            "cat < /etc/passwd",
            "echo x > out",
            "ls 2>&1",
            "(cd x && rm -rf y)",
            "{ rm -rf x; }",
            "rm *.log",
            "ls file?",
            "npm test &&",
            "&& ls",
            "a || || b",
            "echo 'unterminated",
            "echo \"unterminated",
            "ls # comment",
            "! false",
            "echo ok\\",
            "x &>/dev/null",
            "case x in a) ;; esac",
        ] {
            assert!(split_commands(s).is_err(), "{s:?} should be unparseable");
        }
    }

    #[test]
    fn assignments_become_env() {
        assert_eq!(
            hoist_assignments(v(&["FOO=1", "cargo", "test"])),
            v(&["env", "FOO=1", "cargo", "test"])
        );
        assert_eq!(
            hoist_assignments(v(&["cargo", "X=1"])),
            v(&["cargo", "X=1"])
        );
        assert_eq!(hoist_assignments(v(&["FOO=1"])), v(&["FOO=1"]));
    }
}
