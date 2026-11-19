# Security Policy

AgentForge Guard sits between AI coding agents and the systems they act on,
so we take bypasses seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting ("Report a vulnerability" on the Security tab). Include:

- the afg version (`afg --version`), the OS and the Docker version;
- the policy, or a minimal policy that reproduces the problem;
- the exact argv and working directory;
- the expected and actual decision or behavior.

We aim to acknowledge reports within 3 business days.

## In scope

- Policy bypasses: a command classified as `allow` (or run locally) when it should be denied, routed or approval-gated.
- Protected-path bypasses: reading credentials through traversal, symlinks or option values.
- Sandbox escapes caused by afg's container configuration, or host data leaking into a snapshot.
- TOCTOU: executing content other than what was decided on.
- Secrets that reach audit logs despite `redactSecrets: true`, for a documented token format.
- Approval spoofing in ways other than the documented PTY limitation.

## Out of scope

- The limitations documented in [docs/security-boundaries.md](docs/security-boundaries.md), such as the PTY approval limitation and test code running with user privileges in T1, unless you show a practical improvement.
- Kernel or container-runtime escapes that afg's configuration does not cause.
- Agents that do not use afg.

## Supported versions

During pre-alpha, only the latest `main` receives fixes.
