// AgentForge Guard adoption dashboard: npm download counts for every
// agentforge-guard package, from npm's public API. Free plan only: no storage,
// no bindings. One upstream request per refresh, cached for an hour.

import { parsePackages, rangeUrl, renderHtml, summarize, totals, type PackageStats } from "./stats";

export interface Env {
  /** Comma-separated unscoped npm package names. */
  PACKAGES: string;
  /** First publish date (YYYY-MM-DD); totals count from here. */
  LAUNCH_DATE: string;
}

interface Snapshot {
  generatedAt: string;
  packages: PackageStats[];
  totals: ReturnType<typeof totals>;
}

const CACHE_SECONDS = 3600;

async function snapshot(env: Env): Promise<Snapshot> {
  const packages = parsePackages(env.PACKAGES);
  const upstream = await fetch(rangeUrl(packages, env.LAUNCH_DATE, new Date()), {
    headers: { accept: "application/json", "user-agent": "agentforge-guard-adoption-worker" },
    // Cache the npm response at the edge for an hour (free; applies where edge caching is available).
    cf: { cacheTtl: CACHE_SECONDS, cacheEverything: true },
  });
  if (!upstream.ok) throw new Error(`npm downloads API returned ${upstream.status}`);
  const stats = summarize(packages, await upstream.json());
  return { generatedAt: new Date().toISOString(), packages: stats, totals: totals(stats) };
}

const headers = (type: string) => ({
  "content-type": type,
  "cache-control": `public, max-age=${CACHE_SECONDS}`,
  "x-content-type-options": "nosniff",
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405, headers: { allow: "GET, HEAD" } });
    }
    const path = new URL(request.url).pathname;
    if (path !== "/" && path !== "/api/downloads.json") {
      return new Response("not found", { status: 404 });
    }
    let data: Snapshot;
    try {
      data = await snapshot(env);
    } catch (e) {
      console.error("adoption snapshot failed", e);
      return new Response(JSON.stringify({ error: "upstream unavailable" }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    }
    if (path === "/api/downloads.json") {
      return new Response(JSON.stringify(data, null, 2), {
        headers: { ...headers("application/json"), "access-control-allow-origin": "*" },
      });
    }
    return new Response(renderHtml(data.packages, data.generatedAt), {
      headers: {
        ...headers("text/html; charset=utf-8"),
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'",
      },
    });
  },
} satisfies ExportedHandler<Env>;
