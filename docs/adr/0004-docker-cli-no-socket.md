# ADR 0004: Docker via CLI argv, never mount the socket

- Status: Accepted
- Date: 2026-11-19

## Context

The container backend has to work for users without a cloud account, and it must not give sandboxed code a way to escape (the Docker socket, $HOME, or host credentials).

## Decision

The Docker executor invokes the `docker` CLI with a structured argv (no shell, no Docker SDK dependency). Every run uses `--rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges`, a non-root `--user`, the policy's memory, CPU and pids limits, and an environment allowlist. The workspace is a manifest-filtered snapshot copy; the Docker socket and $HOME are never mounted.

## Consequences

Users need Docker installed. Isolation tests run only where Docker is available; Linux CI is the reference runner.
