# npm package security findings

AgentForge Guard's npm distribution contains one JavaScript launcher and five platform
packages holding compiled Rust executables. Socket's `trivialPackage` alert counts each
platform package's three-line JavaScript path export. That count describes the wrapper,
but treating the entire native package as trivial misclassifies its payload. Packaging
defects still need independent tests and fixes.

## rc.5 component metrics and rc.6 improvements

Socket CLI 1.16.0 was used to refresh all six rc.5 reports on 2026-11-22. The detailed
`/v0/npm/<name>/<version>/score` and `/issues` endpoints provide additional inputs that the
CLI's shallow report does not expose. Selected observations are in
[npm-socket-rc.5.json](npm-socket-rc.5.json). The endpoints return different views: the
launcher has quality 99 in the shallow CLI report and approximately 96.4 in the detailed
report, whose issue locations include dependencies. Do not mix these scores into one baseline.

| Detailed rc.5 metric | Five platform packages | Launcher | Action |
|---|---:|---:|---|
| Supply chain score | 57.4007 | 68.8942 | Add actual artifact-integrity checks; public score still requires a rescan |
| Quality score | 69.1979 | 96.4134 | Ship runnable tests and improve platform documentation |
| Download count | 0 | 0 | Requires real adoption and metric refresh; no synthetic traffic |
| README length reported by Socket | 54 | 335 | Platform docs now cover installation, API, tests, integrity, provenance and troubleshooting |
| JavaScript lines reported by Socket | 3 | 70 | The platform export now calls a real integrity verifier; no filler code |
| Low quality issue count | 2 | 7 | `noTests` is actionable; `noV1` remains appropriate while prerelease |

For a platform package, the README component contributes 0.186207 out of a possible
0.344828, code size contributes 0.002069 out of 0.034483, and the download component
contributes zero out of 0.285714. These are component weights, not direct final-score
percentage-point losses; the final score also applies scaling. The missing download input
dominates the remaining supply-chain gap. Smaller archives alone cannot fill it, and the
rc.5 response does not include a bundle-size component in quality.

The detailed issues endpoint reports `noTests`, `noV1` and `trivialPackage` for a platform
package. It also reports a `licenseSpdxDisj` policy alert with `spdxDisj: MIT` and empty
violation/warning/monitor arrays, while both score APIs give license 100 and the shallow
CLI omits the license alert. This discrepancy is recorded; it is not evidence that the
MIT package needs a different license or that a license-policy change would improve its
quality or supply-chain score.

The rc.6 source adds these behaviors:

- Every package ships an explicit `npm test` command and its test source. Platform tests
  verify installed bytes without executing foreign binaries; launcher tests check the
  installed host dependency and exact version pins. No install or publish lifecycle hooks
  are added, and the allowlist names every shipped file.
- Each platform package includes `artifact.json` with its binary hash and source archive
  identity/hash. The path export checks the local binary before returning its path. The
  launcher also checks the expected package name, version, target and binary path before
  spawning it. A missing/malformed manifest, wrong version, modified binary (including
  same-size changes) or binary symlink fails before execution.
- Platform READMEs grew from 53 to 157 physical newline-terminated lines in a local preview
  (`wc -l`; Socket reported 54 for the old file). The added sections explain actual
  supported workflows, prerequisites, verification limits, tests and installation failures.

The integrity verifier reads only package-local files and uses Node built-ins, with no
new dependencies, downloads or install-time execution. Reading and hashing the binary adds
startup work and may produce legitimate filesystem/cryptographic capability findings.
The co-shipped hash is not a trust anchor: an attacker who can change the binary, manifest
and verifier can bypass this check, and it does not prevent a file swap after verification.
npm provenance and signed release comparison remain the origin checks. Policy authorization
continues to belong to `afg-core`.

The regression suite packs/extracts all six artifacts, runs their included tests, and
checks rejection of corrupted bytes and metadata. A preview assembled from the real,
previously attested rc.5 archives also passed all six package self-test suites, and the
host launcher returned `afg 1.0.0-rc.5`. This preview was local and was not republished as
rc.5. Public post-change scores, removal of scanner alerts, and the next release's complete
OS installation matrix remain unverified until publication and rescan. `noV1` is not a
reason to bypass the independent-review gate for stable 1.0.0.

## Socket results for 1.0.0-rc.4

Socket CLI 1.16.0 returned the following results on 2026-11-22. The normalized
[API evidence](npm-socket-rc.4.json) preserves package IDs, sizes, scores and alert details;
it excludes credentials and organization-specific policy metadata.

| Package | Supply chain | Quality | License | Vulnerabilities | Direct alerts |
|---|---:|---:|---:|---:|---|
| `agentforge-guard` | 69 | 99 | 100 | 100 | None |
| `agentforge-guard-darwin-arm64` | 57 | 58 | 100 | 100 | `trivialPackage`, 3 lines in `package/index.js` |
| `agentforge-guard-darwin-x64` | 57 | 58 | 100 | 100 | `trivialPackage`, 3 lines in `package/index.js` |
| `agentforge-guard-linux-arm64` | 57 | 58 | 100 | 100 | `trivialPackage`, 3 lines in `package/index.js` |
| `agentforge-guard-linux-x64` | 57 | 58 | 100 | 100 | `trivialPackage`, 3 lines in `package/index.js` |
| `agentforge-guard-win32-x64` | 57 | 58 | 100 | 100 | `trivialPackage`, 3 lines in `package/index.js` |

The Windows package initially returned `pendingScan`; the later request in the evidence
file returned a completed scan. The launcher's separate deep report includes all five
optional dependencies and returns a minimum aggregate of 57 for supply chain and quality.
That endpoint returned 68/98 for the launcher itself, slightly different from the shallow
endpoint's 69/99. These are recorded API observations, not promised future scores.

Socket's [alert definition](https://docs.socket.dev/docs/supply-chain-risk) treats fewer
than ten lines of code as a trivial package that could be copied into a project. Here the
JavaScript exports a binary path; copying those three lines does not replace the program.
The published macOS arm64 tarball was inspected directly: it contains a Mach-O arm64
executable and the three-line export. Its five-file layout matches the intended platform
package. Its binary matched the GitHub release archive byte for byte, and
`gh attestation verify` accepted the archive for `dennislee928/AgentForge-Guard`.
The evidence file records the binary hash. This supports classifying this alert
as a mismatch between the JavaScript heuristic and the native distribution, rather than
adding redundant JavaScript to cross a line-count threshold.

Socket's [score metrics](https://docs.socket.dev/docs/package-scores) also include downloads,
bundle size, code size and repository activity. A low score without alerts is therefore
possible. Those metrics are relevant context for a new project shipping multi-megabyte
binaries, but these API reports do not expose enough inputs to assign each missing point
to a particular metric. A score of 100 for vulnerabilities is not a security audit of the
native code.

## Packaging defects and fixes

| Finding | Evidence | Fix |
|---|---|---|
| A broad `bin/` allowlist can publish unintended files | A failing `npm pack` regression included an obviously fake `bin/accidental.env` fixture | Generate an exact `bin/afg` or `bin/afg.exe` file allowlist |
| The platform README contradicts its contents | It claimed “no JavaScript” while shipping `index.js` | Describe both the native binary and the JavaScript path export |
| Verification instructions leave the workflow identity as `v*` | A literal wildcard is not the release's exact certificate identity | Generate the exact tagged identity, OIDC issuer and commands to compare npm's binary with the signed release |
| Tests inspect assembly directories without testing npm's file selection | Assembly tests cannot detect files that npm unexpectedly includes or omits | Pack and extract all six packages offline, inspect exact file lists, verify entry points and binary bytes, and exercise the extracted launcher with its host platform package |

The unexpected-file regression demonstrates a packaging risk; it is not evidence that any
published release leaked a credential. All credentials in test fixtures are obviously fake.
The tarball tests also enforce MIT licensing, no lifecycle scripts, no additional runtime
dependencies, executable modes and exact version pins for the five optional dependencies.
CI already runs this packaging suite on each PR.

These packaging fixes are included in the `1.0.0-rc.5` source. Published `1.0.0-rc.4` artifacts
and its recorded Socket scores are unchanged. The minimal `index.js` remains three lines. There are
no scanner exclusions, score thresholds or organization-policy changes in this fix.

## Rechecking a release

Configure `SOCKET_CLI_API_TOKEN` in the environment with `packages:list` permission;
keep it out of command arguments and saved reports. Run the following with Socket CLI:

```sh
socket package shallow npm agentforge-guard@1.0.0-rc.4 agentforge-guard-darwin-arm64@1.0.0-rc.4 agentforge-guard-darwin-x64@1.0.0-rc.4 agentforge-guard-linux-arm64@1.0.0-rc.4 agentforge-guard-linux-x64@1.0.0-rc.4 agentforge-guard-win32-x64@1.0.0-rc.4 --json --no-banner --no-spinner
socket package score npm agentforge-guard@1.0.0-rc.4 --json --no-banner --no-spinner
```

Treat `pendingScan` as incomplete and recheck it before making a security claim. Review new
alert types on their own merits; the rationale for this three-line path export does not
apply to arbitrary trivial packages or to other alerts. Socket may need to correct the
native-package classification upstream; an organization-level ignore does not establish
that the public score changed.

Each generated platform README includes commands to download the matching npm tarball
without install scripts, verify the GitHub archive with Sigstore and GitHub attestations,
and compare the extracted binaries. Run `npm audit signatures` in a project that installed
the package to verify npm signatures and available provenance. Hash equality links the
two artifacts; signature verification authenticates the publisher workflow. Neither proves
the program free of vulnerabilities.

Run the local packaging suite with:

```sh
node --test packaging/npm/test/npm.test.mjs
```

The suite uses fake release binaries and checks packaging and host launcher behavior. It
does not execute real binaries for all five operating-system targets or replace the
post-release matrix planned in T15.4.
