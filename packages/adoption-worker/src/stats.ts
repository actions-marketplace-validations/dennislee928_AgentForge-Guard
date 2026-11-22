// Pure functions: build the npm query, summarize the response, render HTML.
// No network and no Workers APIs here, so everything is unit-testable.

export interface Day {
  day: string;
  downloads: number;
}

export interface PackageStats {
  name: string;
  lastDay: number;
  last7: number;
  last30: number;
  total: number;
  /** The most recent 30 days, oldest first. */
  daily: Day[];
}

export interface Totals {
  lastDay: number;
  last7: number;
  last30: number;
  total: number;
}

const DAY_MS = 86_400_000;
/** Unscoped npm names only: they are interpolated into the upstream URL. */
const NAME = /^[a-z0-9][a-z0-9._-]*$/;

export function parsePackages(list: string): string[] {
  const names = list.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (names.length === 0) throw new Error("PACKAGES is empty");
  for (const n of names) {
    if (!NAME.test(n) || n.includes("..")) throw new Error(`invalid npm package name: ${JSON.stringify(n)}`);
  }
  return names;
}

const ymd = (d: Date) => d.toISOString().slice(0, 10);

/** npm's bulk range query, from the launch date (or 364 days ago, npm's limit) to today. */
export function rangeUrl(packages: string[], launchDate: string, now: Date): string {
  const end = new Date(`${ymd(now)}T00:00:00Z`);
  const earliest = new Date(end.getTime() - 364 * DAY_MS);
  const launch = new Date(`${launchDate}T00:00:00Z`);
  const start = Number.isNaN(launch.getTime()) || launch < earliest ? earliest : launch;
  return `https://api.npmjs.org/downloads/range/${ymd(start)}:${ymd(end)}/${packages.join(",")}`;
}

function daysOf(entry: unknown): Day[] {
  if (typeof entry !== "object" || entry === null) return [];
  const list = (entry as { downloads?: unknown }).downloads;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (d): d is Day =>
      typeof d === "object" && d !== null &&
      typeof (d as Day).day === "string" && /^\d{4}-\d{2}-\d{2}$/.test((d as Day).day) &&
      typeof (d as Day).downloads === "number" && Number.isFinite((d as Day).downloads),
  );
}

const sum = (days: Day[]) => days.reduce((n, d) => n + d.downloads, 0);

/** Accepts npm's bulk shape ({ name: entry | null }) and its single-package shape. */
export function summarize(packages: string[], body: unknown): PackageStats[] {
  const obj = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  const single = typeof obj.package === "string";
  return packages.map((name) => {
    const days = daysOf(single ? (obj.package === name ? obj : null) : obj[name]).sort((a, b) =>
      a.day < b.day ? -1 : a.day > b.day ? 1 : 0,
    );
    return {
      name,
      lastDay: days.at(-1)?.downloads ?? 0,
      last7: sum(days.slice(-7)),
      last30: sum(days.slice(-30)),
      total: sum(days),
      daily: days.slice(-30),
    };
  });
}

export function totals(stats: PackageStats[]): Totals {
  return stats.reduce(
    (t, s) => ({
      lastDay: t.lastDay + s.lastDay,
      last7: t.last7 + s.last7,
      last30: t.last30 + s.last30,
      total: t.total + s.total,
    }),
    { lastDay: 0, last7: 0, last30: 0, total: 0 },
  );
}

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const fmt = (n: number) => n.toLocaleString("en-US");

/** A tiny bar chart of the last 30 days, as inline SVG. */
function bars(daily: Day[]): string {
  const w = 120;
  const h = 24;
  const max = Math.max(1, ...daily.map((d) => d.downloads));
  const bw = w / 30;
  const rects = daily
    .map((d, i) => {
      const bh = Math.max(d.downloads > 0 ? 1 : 0, Math.round((d.downloads / max) * h));
      const x = (30 - daily.length + i) * bw;
      return `<rect x="${x.toFixed(1)}" y="${h - bh}" width="${(bw - 1).toFixed(1)}" height="${bh}"><title>${esc(d.day)}: ${d.downloads}</title></rect>`;
    })
    .join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="downloads, last 30 days">${rects}</svg>`;
}

export function renderHtml(stats: PackageStats[], generatedAt: string): string {
  const t = totals(stats);
  const rows = stats
    .map(
      (s) => `<tr>
  <td><a href="https://www.npmjs.com/package/${encodeURIComponent(s.name)}">${esc(s.name)}</a></td>
  <td>${fmt(s.lastDay)}</td><td>${fmt(s.last7)}</td><td>${fmt(s.last30)}</td><td>${fmt(s.total)}</td>
  <td>${bars(s.daily)}</td>
</tr>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentForge Guard downloads</title>
<style>
  :root { --bg: #fff; --fg: #1a1a1a; --muted: #666; --line: #e5e5e5; --bar: #3b6fd8; }
  @media (prefers-color-scheme: dark) { :root { --bg: #111; --fg: #eee; --muted: #999; --line: #2a2a2a; --bar: #7aa2f7; } }
  body { background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 960px; padding: 24px 16px; }
  h1 { font-size: 1.4rem; margin: 0 0 4px; }
  p { color: var(--muted); margin: 0 0 20px; }
  .wrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border-bottom: 1px solid var(--line); padding: 8px 10px; text-align: right; white-space: nowrap; }
  th:first-child, td:first-child { text-align: left; }
  tfoot td { font-weight: 600; }
  a { color: inherit; }
  rect { fill: var(--bar); }
</style>
</head>
<body>
<h1>AgentForge Guard: npm downloads</h1>
<p>Source: npm's public downloads API (counts lag about a day). Updated ${esc(generatedAt)}. JSON: <a href="/api/downloads.json">/api/downloads.json</a></p>
<div class="wrap"><table>
<thead><tr><th>Package</th><th>Last day</th><th>7 days</th><th>30 days</th><th>Total</th><th>Last 30 days</th></tr></thead>
<tbody>
${rows}
</tbody>
<tfoot><tr><td>All packages</td><td>${fmt(t.lastDay)}</td><td>${fmt(t.last7)}</td><td>${fmt(t.last30)}</td><td>${fmt(t.total)}</td><td></td></tr></tfoot>
</table></div>
</body>
</html>
`;
}
