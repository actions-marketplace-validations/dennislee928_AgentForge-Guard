# n8n evaluation API v1

The n8n integration calls the Rust gateway. `afg-core` remains the only
authorization engine (ADR 0002). The gateway evaluates commands and never runs
them, creates approvals, or exports execution credentials.

## Request

`POST /v1/evaluate`, `Content-Type: application/json`, and
`Authorization: Bearer <API key>` are required. All endpoints require this key.

```json
{"argv":["git","status"],"requestedBackend":"container"}
```

`argv` is a nonempty array of strings, with at most 256 entries; each entry is
at most 4096 bytes and cannot contain NUL. The body limit is 64 KiB. Optional
`requestedBackend` is `local`, `container`, or `cloudflare` (availability is
decided by the engine). Unknown fields, client policies, shell strings, client
working directories and environment overrides are rejected.

## Response

```json
{
  "schemaVersion": 1,
  "effect": "allow",
  "backend": "local",
  "ruleId": "read-only-git",
  "reasons": ["matched rule `read-only-git` (allow)"],
  "policyVersion": "agentforge.dev/v1",
  "policyHash": "sha256:<64 lowercase hex characters>"
}
```

The engine effects are `allow`, `deny`, `require-approval`, and `route`.
Denied evaluations return HTTP 200 with `backend: null`. An approval requirement
is not approval; a route requires the selected executor. No response is an
execution permit. `GET /v1/health` returns
`{"schemaVersion":1,"status":"ok"}` after authentication and policy checks.

HTTP 400/422 means invalid input, 401 invalid authentication, 413 oversized input,
415 wrong content type, and 503 unavailable/changed/invalid policy. Unsupported
routes/methods return 404/405. Errors never contain an allow decision. Callers
must stop on transport errors, timeouts, unexpected schemas or policy changes.

## Deployment and trust

The operator fixes the project directory at startup, supplies the reviewed policy
hash using `--policy-hash`, and supplies the key through `AFG_GATEWAY_API_KEY`.
No key is accepted on the command line. The gateway validates the policy/hash
before binding, reloads per request, and refuses decisions if the policy changes,
disappears or becomes invalid. Existing CLI trust-pin changes are also refused.
A restart with an explicitly reviewed new hash adopts a new policy.

Default binding is loopback. Use a TLS reverse proxy for remote n8n instances,
with request deadlines, connection limits and rate limiting. Run as an
unprivileged service account with a minimal PATH and read-only policy/workspace.

Evaluation uses the gateway's filesystem, home and PATH, not n8n's or a future
execution host's. Symlinks, executable identities and files may change afterward.
Execute through `afg run` on the target host to re-evaluate and enforce isolation,
approval and TOCTOU checks. Argv matching and workflow instructions are not
security boundaries. This API provides integration-mode advice unless a trusted
executor enforces the returned requirements.

Policy Evaluate, Command Analyze and Security Validate use this contract.
Analyze reports deterministic engine reasons without invented risk scores.
Security Validate stops on every engine effect other than `allow`. Remote
approval, audit query/export and MCP inspection remain future contracts.

## Upstream references

- [Official starter](https://github.com/n8n-io/n8n-nodes-starter)
- [Verification guidelines](https://docs.n8n.io/connect/create-nodes/build-your-node/reference/verification-guidelines)
- [Submission and provenance](https://docs.n8n.io/connect/create-nodes/deploy-your-node/submit-community-nodes)

Checked 2026-11-25. Verification requires external review; successful lint or npm
publication does not establish it.
