# @agentforge/adoption-worker

A Cloudflare Worker that shows npm download counts for all six AgentForge Guard packages:

- `agentforge-guard`
- `agentforge-guard-darwin-arm64`
- `agentforge-guard-darwin-x64`
- `agentforge-guard-linux-arm64`
- `agentforge-guard-linux-x64`
- `agentforge-guard-win32-x64`

**It runs on the Workers free plan.** It uses no database, KV, D1, R2 or Containers, and has no bindings. Each refresh makes one request to npm's public [downloads API](https://github.com/npm/registry/blob/main/docs/download-counts.md): a single bulk "range" query that covers all six packages.

| Path | Returns |
|---|---|
| `/` | HTML table. For each package: last day, last 7 days, last 30 days, total since `LAUNCH_DATE`, and a 30-day bar chart. A final row gives the sum across packages |
| `/api/downloads.json` | The same data as JSON, with CORS `*` |

npm's counts lag about a day. Responses are cached for an hour.

## Configure

The settings are the `vars` in `wrangler.jsonc`:

- `PACKAGES`: comma-separated, unscoped npm names. The Worker validates each name before putting it in the upstream URL.
- `LAUNCH_DATE`: the first publish date. npm's bulk queries cover at most 365 days, so after a year, "total" means the last 365 days.

## Develop and deploy

```sh
cd packages/adoption-worker
pnpm install
pnpm check          # typecheck + unit tests
pnpm dev            # local preview at http://localhost:8787
pnpm deploy         # needs `wrangler login` (free account is enough)
```

After deploying, the dashboard is at `https://agentforge-guard-adoption.<your-subdomain>.workers.dev/`.
