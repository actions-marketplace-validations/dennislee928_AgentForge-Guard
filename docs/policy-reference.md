# Policy Reference: `agentforge.yaml` (`agentforge.dev/v1alpha1`)

The policy is validated strictly: unknown fields are errors. Its JSON Schema is [`agentforge.schema.json`](../agentforge.schema.json) (`afg policy schema`), and `afg policy validate` checks the semantic rules. Built-in templates live in [`crates/afg-core/policies/`](../crates/afg-core/policies/).

```yaml
apiVersion: agentforge.dev/v1alpha1
kind: AgentPolicy
project: { name: my-project, root: "." }
agents: [claude-code, codex]
execution: { default: local, fallback: deny, backends: { ... } }
rules: [ ... ]
protectedPaths: [ ... ]
audit: { format: json, redactSecrets: true, dir: .agentforge/audit }
```

## `execution`

| Field | Default | Meaning |
|---|---|---|
| `default` | `local` | The backend for `allow` and `require-approval` rules that name none. |
| `fallback` | `deny` | What happens to unmatched commands, and to opaque commands that only `allow` rules matched: `deny`, `require-approval`, or `{ route: container }`. |

### `backends.local`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `env` | `[PATH, HOME, USER, LANG, TERM, TMPDIR]` | Host variables passed through. Everything else is cleared. |
| `timeoutSeconds` | `300` | |

### `backends.container`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `image` | `debian:stable-slim` | **Pin it by digest** (`image@sha256:…`) for reproducibility. It is pulled if missing. |
| `network` | `none` | `none` or `bridge`. `bridge` gives sandboxed code network access, and the validator warns about it. |
| `readOnlyRootfs` | `true` | `/tmp` is always a writable tmpfs. |
| `memoryMB` / `cpus` / `pidsLimit` | `2048` / `2` / `256` | Swap is disabled (`--memory-swap` equals `--memory`). |
| `timeoutSeconds` | `300` | On timeout the container is killed and removed. |
| `env` | `[]` | Host variable *names* to pass in. Names starting with `DOCKER_` are rejected. |

The container gets a **copy** of the project. Gitignored files, protected files, symlinks, `.git` and `.agentforge` are excluded, and changes are discarded when the run ends.

`backends.cloudflare.enabled` must be `false` in this version.

## `rules`

```yaml
- id: read-only-git              # unique
  description: optional text
  effect: allow                  # allow | route | require-approval | deny
  backend: local                 # required for route (and must not be local)
  commands:                      # argv prefixes: [executable, leading args...]
    - [git, diff]
    - [git, log]
  denyArgs: [--ext-diff, --output]   # allow/route only
  allowFlags: [--stat, --oneline]    # allow/route only
```

### How a command is decided

1. **Normalize.**
   - The executable is resolved on the *absolute* `PATH` entries.
   - The wrappers `env`, `nice`, `timeout`, `nohup`, `command`, `exec` and `time` are unwrapped.
   - Names are compared case-insensitively, without `.exe`.
   - Harmless `git` globals are stripped (`--no-pager`, `-C <dir>`, …).
2. **Hard denies.**
   - Privilege escalation: `sudo`, `doas`, `su`, `pkexec`.
   - An invalid argv.
   - Any argument or working directory that refers to a **protected path**.
3. **Rules.** Of all the matching rules, the most severe wins: **deny > require-approval > route > allow**. Ties go to the first rule.
4. **Fallback.** This applies when nothing matched.
5. **Backend.** The chosen backend must be enabled, or the command is denied. `afg run --isolation container` can raise the isolation level, but `--isolation local` can never lower it.

### Matching

- **The executable** (`commands[i][0]`) matches by name. An entry that contains `/` matches the canonical path instead. A repo-local `./cargo` that isn't what `cargo` resolves to on `PATH` is opaque.
- **`allow` and `route` rules** need an **exact prefix**. `[cargo, test]` matches `cargo test --workspace`, but not `cargo --offline test`, which falls to the fallback (fail closed). `*` matches any single argument.
- **`deny` and `require-approval` rules** match their tail as an **ordered subsequence**, so interleaved flags can't evade them. `[kubectl, delete]` matches `kubectl -n prod --context x delete pod y`.
- **`denyArgs`.** If any argument after the prefix matches, the rule doesn't apply. `--flag` also matches `--flag=value`, and a trailing `*` makes the pattern a prefix match (`--no-ignore*`, `-u*`).
- **`allowFlags`.** If this is set, every flag after the prefix (up to `--`) must match an entry.
- **Constraints on `deny` and `require-approval` rules are rejected**, because they would weaken those rules.

### Opaque commands

The following are *opaque*, meaning their effect can't be known from argv:

- shells (`sh`, `bash`, …);
- interpreters (`python`, `node`, …);
- indirect executors (`xargs`, `make`, `find -exec`, `npx`, `ssh`, …);
- `env NAME=value`;
- `git -c` and other code-running git globals;
- shell syntax in argv (`$(`, backticks, `|`, `;`, `>`, …);
- control or invisible Unicode characters;
- non-ASCII executable names.

**Opaque commands never match `allow` rules.** Route them to a container (`effect: route`), require approval, or let the fallback deny them. The validator warns about `allow` rules that name an always-opaque executable.

## `protectedPaths`

These entries are **added** to the built-in list. They can never remove built-in entries.

- **Built-in paths:** `~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.gnupg`, `~/.docker`, `~/.config/gcloud`, `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials{,.toml}`, `/var/run/docker.sock`, `/run/docker.sock`.
- **Built-in globs:** `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_dsa*`, `id_ecdsa*`, `id_ed25519*`, `kubeconfig`, `*.kubeconfig`, `*.tfstate`, `*.tfstate.backup`, `.netrc`, `.git-credentials`.
- **Your own entries.** Entries that contain `/` or start with `~` are paths, and relative ones are resolved against the project root. All other entries are basename globs.

Arguments are checked as written, after `~` expansion and `..` normalization, and after resolving symlinks. The value parts of `--opt=value`, `@file`, `a:b` and `-fVALUE` are checked too.

## `audit`

`afg` appends one JSON line per decision to `<dir>/YYYY-MM-DD.jsonl` (mode 0600, under a 0700 directory). Each record holds:

- the argv (redacted) and cwd;
- the policy version and hash;
- the effect, backend, rule and reasons;
- the approval outcome and channel;
- the exit code, timeout and duration;
- stdout and stderr **length and SHA-256 only**;
- backend details (image, container, snapshot manifest hash).

`redactSecrets: true` (the default) scrubs known token formats, private keys, URL credentials, `NAME=secret` assignments and `--password <value>` pairs. Environment values are never recorded.
