# ADR 0005: No MCP server: managed mode plus native hooks

- Status: Accepted
- Date: 2026-11-19

## Context

The reference proposed both a Rust and a TypeScript MCP server. AgentForge Guard is a code-execution tool, not a tool catalog, and a second interface would duplicate the enforcement surface.

## Decision

There is no MCP server. Agents use the tool in two ways: **managed mode** (`afg run -- <argv>`), where afg's own executor enforces policy; and **integration mode**, where native agent mechanisms (Claude Code PreToolUse hooks and permission rules, Codex sandbox and approval settings) call the same engine.

## Consequences

The docs must state that integration mode is only as strong as the agent's hook API and OS sandbox, and is weaker than managed mode. This decision may be revisited after v1.0 if there is demand.
