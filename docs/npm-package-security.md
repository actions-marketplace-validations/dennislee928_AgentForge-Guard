# npm package security findings

AgentForge Guard's npm distribution contains one JavaScript launcher and five platform
packages holding compiled Rust executables. Socket's `trivialPackage` alert counts each
platform package's three-line JavaScript path export. That count describes the wrapper,
but treating the entire native package as trivial misclassifies its payload. Packaging
defects still need independent tests and fixes.

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
