# Workflow templates

Import these JSON files into a self-hosted n8n instance with the community node
installed, then select your AgentForge Guard API credential on every Guard node.
No credential IDs or keys are embedded. Run manually against your reviewed
gateway policy. The bundled default policy produces these examples:

| Template | Expected result |
| --- | --- |
| `policy-gate.json` | `git status` returns allow and reaches the no-op branch |
| `security-validate.json` | `terraform destroy` stops at Security Validate |
| `command-analyze.json` | `sh -c` returns route to container without execution |

In the gate template, replace Argv with `["terraform","destroy"]` to test deny,
`["kubectl","apply"]` to test approval, or `["sh","-c","echo example"]` to test
routing. All three reach Stop And Error. Set an invalid API key or stop the gateway
to verify that no success output reaches the branch. Do not enable Continue on
Error for security gates; if enabled, explicitly reject items with an `error` field.

The allow branch is a no-op. Re-evaluate using `afg run` on the execution host
before any real execution. The gateway's filesystem and PATH can differ from the
execution host, and evaluation does not bind later execution to the checked files.

These templates do not automatically approve operations, send incidents, or
execute commands. JEF integration requires its actual API contract and is tracked
separately in `docs/plan.md`.
