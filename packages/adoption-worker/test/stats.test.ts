import { describe, expect, it } from "vitest";
import { parsePackages, rangeUrl, renderHtml, summarize, totals } from "../src/stats";

const PKGS = ["agentforge-guard", "agentforge-guard-linux-x64"];

function days(start: string, counts: number[]) {
  const d = new Date(`${start}T00:00:00Z`);
  return counts.map((downloads, i) => {
    const day = new Date(d.getTime() + i * 86_400_000).toISOString().slice(0, 10);
    return { day, downloads };
  });
}

describe("parsePackages", () => {
  it("splits, trims and keeps valid unscoped npm names", () => {
    expect(parsePackages(" agentforge-guard , agentforge-guard-win32-x64 ")).toEqual([
      "agentforge-guard",
      "agentforge-guard-win32-x64",
    ]);
  });

  it("rejects anything that could change the upstream URL", () => {
    for (const bad of ["a/b", "a?x=1", "@scope/pkg", "a b", "../x", "A", ""]) {
      expect(() => parsePackages(bad), bad).toThrow();
    }
  });
});

describe("rangeUrl", () => {
  it("queries the bulk range API from the launch date to today", () => {
    const url = rangeUrl(PKGS, "2026-11-21", new Date("2026-12-05T10:00:00Z"));
    expect(url).toBe(
      "https://api.npmjs.org/downloads/range/2026-11-21:2026-12-05/agentforge-guard,agentforge-guard-linux-x64",
    );
  });

  it("never asks for more than 365 days (npm's bulk limit)", () => {
    const url = rangeUrl(PKGS, "2026-01-01", new Date("2028-03-01T00:00:00Z"));
    expect(url).toContain("/range/2027-03-03:2028-03-01/");
  });
});

describe("summarize", () => {
  it("computes last day, 7 days, 30 days and total per package", () => {
    const counts = Array.from({ length: 40 }, (_, i) => i + 1); // 1..40
    const body = {
      "agentforge-guard": { package: "agentforge-guard", downloads: days("2026-11-01", counts) },
      "agentforge-guard-linux-x64": { package: "agentforge-guard-linux-x64", downloads: days("2026-11-01", [0, 2]) },
    };
    const [main, linux] = summarize(PKGS, body);
    expect(main).toMatchObject({ name: "agentforge-guard", lastDay: 40, last7: 34 + 35 + 36 + 37 + 38 + 39 + 40, total: 820 });
    expect(main!.last30).toBe((11 + 40) * 30 / 2);
    expect(main!.daily).toHaveLength(30);
    expect(linux).toMatchObject({ lastDay: 2, last7: 2, last30: 2, total: 2 });
  });

  it("treats a missing or null package as zero downloads", () => {
    const [main, linux] = summarize(PKGS, { "agentforge-guard": null });
    expect(main).toMatchObject({ lastDay: 0, last7: 0, last30: 0, total: 0, daily: [] });
    expect(linux!.total).toBe(0);
  });

  it("accepts npm's single-package (non-bulk) response shape", () => {
    const [only] = summarize(["agentforge-guard"], { package: "agentforge-guard", downloads: days("2026-11-21", [3, 4]) });
    expect(only!.total).toBe(7);
  });

  it("ignores malformed entries instead of throwing", () => {
    const [main] = summarize(["agentforge-guard"], { "agentforge-guard": { downloads: [{ day: "x", downloads: "7" }, { day: "2026-11-22", downloads: 5 }] } });
    expect(main!.total).toBe(5);
  });
});

describe("totals and HTML", () => {
  it("sums every package", () => {
    const stats = summarize(PKGS, {
      "agentforge-guard": { downloads: days("2026-11-21", [1, 2]) },
      "agentforge-guard-linux-x64": { downloads: days("2026-11-21", [3]) },
    });
    expect(totals(stats)).toEqual({ lastDay: 5, last7: 6, last30: 6, total: 6 });
  });

  it("renders every package and escapes text", () => {
    const stats = summarize(["agentforge-guard"], { "agentforge-guard": { downloads: days("2026-11-21", [9]) } });
    const html = renderHtml(stats, "2026-11-22T00:00:00.000Z<script>");
    expect(html).toContain("agentforge-guard");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
  });
});
