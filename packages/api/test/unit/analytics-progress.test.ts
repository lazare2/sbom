import { describe, expect, it } from "vitest";
import { DEFAULT_ATTENTION_SETTINGS, type AttentionSettings, type ProjectProgress } from "@sbom/shared";
import {
  attentionFlags,
  buildCadence,
  buildDeltaSection,
  buildOverdueFlag,
  buildPairs,
  projectBuildDeltas,
  rollup,
  windowMovement,
  zeroPair,
  type BuildFact,
} from "../../src/modules/analytics/progress.js";

/**
 * The rules that decide which projects Analytics names as needing attention, and what each
 * build did to the findings of the one before it. Each fails silently when wrong - a team is
 * flagged for nothing, or a real regression averages away - so each is pinned here.
 */

const NOW = new Date("2026-11-11T12:00:00Z");
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000);
const PERIOD_START = day(30);

let n = 0;
function build(daysAgo: number, over: Partial<BuildFact> = {}): BuildFact {
  n += 1;
  return {
    applicationId: "app",
    scanId: `s${String(n).padStart(3, "0")}`,
    createdAt: day(daysAgo),
    sha: `sha-${n}`,
    buildNumber: String(n),
    assessed: true,
    criticalHigh: 0,
    ...over,
  };
}

const settings = (over: Partial<AttentionSettings> = {}): AttentionSettings => ({
  ...DEFAULT_ATTENTION_SETTINGS,
  ...over,
});

describe("build pairs", () => {
  it("skips a byte-identical rebuild and pairs the next build with the last one that differed", () => {
    const a = build(20, { sha: "x" });
    const rebuild = build(15, { sha: "x" });
    const c = build(10, { sha: "y" });
    const { pairs, identicalSkippedInWindow } = buildPairs([c, rebuild, a], PERIOD_START);

    expect(identicalSkippedInWindow).toBe(1);
    expect(pairs).toHaveLength(1);
    expect(pairs[0]).toMatchObject({ inWindow: true, isLast: true, comparable: true });
    expect(pairs[0]!.from.scanId).toBe(a.scanId);
    expect(pairs[0]!.to.scanId).toBe(c.scanId);
  });

  it("keeps the latest pair even when it falls before the window", () => {
    const { pairs } = buildPairs([build(90), build(60)], PERIOD_START);
    expect(pairs).toHaveLength(1);
    expect(pairs[0]).toMatchObject({ inWindow: false, isLast: true });
  });

  it("does not compare a build whose packages are still being matched", () => {
    const { pairs } = buildPairs([build(20), build(10, { assessed: false })], PERIOD_START);
    expect(pairs[0]!.comparable).toBe(false);
  });
});

describe("build cadence and the overdue flag", () => {
  it("averages the gaps between builds inside the cadence window, rebuilds included", () => {
    const builds = [build(100), build(40), build(30), build(20), build(10)];
    const cadence = buildCadence(builds, NOW, PERIOD_START, 90);
    // The build exactly 30 days ago sits on the window boundary and counts inside it.
    expect(cadence).toMatchObject({ cadenceBuilds: 4, averageDaysBetweenBuilds: 10, daysSinceLastBuild: 10, inWindow: 3 });
  });

  it("flags at the project's own pace times the multiplier, and says so", () => {
    const cadence = buildCadence([build(31), build(29), build(27), build(25)], NOW, PERIOD_START, 90);
    // Every 2 days; 1.5x is 3 days, but the 7-day floor applies; last build 25 days ago.
    const flag = buildOverdueFlag(cadence, settings());
    expect(flag?.kind).toBe("build_overdue");
    expect(flag?.reason).toContain("Usually built every 2 days");
    expect(flag?.reason).toContain("7 days minimum");
    expect(flag?.reason).toContain("Last build 25 days ago");
  });

  it("uses the multiplier when it is above the floor", () => {
    const cadence = buildCadence([build(70), build(60), build(50), build(40)], NOW, PERIOD_START, 90);
    // Every 10 days, so 15 with slack; 40 days since is overdue, 14 would not be.
    expect(buildOverdueFlag(cadence, settings())?.reason).toContain("flagged after 1.5x that, 15 days");
    const recent = buildCadence([build(44), build(34), build(24), build(14)], NOW, PERIOD_START, 90);
    expect(buildOverdueFlag(recent, settings())).toBeNull();
  });

  it("flags at exactly the average with the multiplier switched off", () => {
    const recent = buildCadence([build(44), build(34), build(24), build(14)], NOW, PERIOD_START, 90);
    expect(buildOverdueFlag(recent, settings({ useMultiplier: false }))?.reason).toContain("flagged after 10 days");
  });

  it("falls back to the fixed limit with too little history, and says why", () => {
    const sparse = buildCadence([build(80), build(45)], NOW, PERIOD_START, 90);
    const flag = buildOverdueFlag(sparse, settings());
    expect(flag?.reason).toContain("Not enough recent history");
    expect(flag?.reason).toContain("fixed limit of 30 days applies");
    expect(buildOverdueFlag(buildCadence([build(80), build(20)], NOW, PERIOD_START, 90), settings())).toBeNull();
  });

  it("applies one limit to everyone in fixed mode", () => {
    const busy = buildCadence([build(34), build(33), build(32), build(31)], NOW, PERIOD_START, 90);
    expect(buildOverdueFlag(busy, settings({ buildOverdueMode: "fixed" }))?.reason).toBe(
      "No build in 31 days; the limit is 30 days.",
    );
  });

  it("flags a project that has never built", () => {
    expect(buildOverdueFlag(buildCadence([], NOW, PERIOD_START, 90), settings())?.reason).toContain("No build");
  });
});

function project(over: Partial<ProjectProgress> = {}): ProjectProgress {
  return {
    applicationId: "app",
    name: "svc",
    status: "active",
    squads: [],
    tribes: [],
    builds: buildCadence([build(3), build(2), build(1)], NOW, PERIOD_START, 90),
    vulnerabilities: {
      comparedBuilds: 2,
      fixed: 3,
      introduced: 1,
      net: -2,
      fixedCriticalHigh: 0,
      introducedCriticalHigh: 0,
      openCritical: 0,
      openHigh: 0,
      criticalHighAtStart: 0,
      criticalHighChange: 0,
      meanDaysToFix: null,
      fixesTimed: 0,
    },
    ...over,
  };
}

describe("attention flags", () => {
  it("raises nothing for a healthy project", () => {
    expect(attentionFlags(project(), undefined, settings())).toEqual([]);
  });

  it("names known-exploited advisories", () => {
    const flags = attentionFlags(project(), { knownExploited: { count: 1, ids: ["CVE-1"] }, criticalFixable: [] }, settings());
    expect(flags[0]).toMatchObject({ kind: "known_exploited" });
    expect(flags[0]!.reason).toContain("CVE-1");
  });

  it("flags critical fixes only once they are older than the setting", () => {
    const risk = {
      knownExploited: null,
      criticalFixable: [
        { vulnerabilityId: "CVE-OLD", packageName: "openssl", openDays: 45.2 },
        { vulnerabilityId: "CVE-NEW", packageName: "zlib", openDays: 3 },
      ],
    };
    const flag = attentionFlags(project(), risk, settings()).find((f) => f.kind === "critical_fix_overdue");
    expect(flag?.reason).toContain("1 critical finding");
    expect(flag?.reason).toContain("CVE-OLD in openssl, open 45.2 days");
    expect(attentionFlags(project(), risk, settings({ criticalFixDays: 60 }))).toEqual([]);
  });

  it("flags rising vulnerabilities only when builds introduced more than they fixed", () => {
    const rising = project({
      vulnerabilities: { ...project().vulnerabilities!, fixed: 1, introduced: 5, net: 4, introducedCriticalHigh: 2 },
    });
    const flag = attentionFlags(rising, undefined, settings()).find((f) => f.kind === "vulnerabilities_rising");
    expect(flag?.reason).toBe("Builds in this window introduced 5 findings and fixed 1 (net +4, 2 of them critical or high).");
  });
});

describe("build-to-build averages", () => {
  it("averages per pair inside the window and reports the latest pair separately", () => {
    const a = build(50);
    const b = build(20);
    const c = build(10);
    const { pairs } = buildPairs([a, b, c], PERIOD_START);
    const d1 = zeroPair();
    d1.app.fixed.total = 4;
    d1.app.fixed.critical = 1;
    const d2 = zeroPair();
    d2.app.introduced.total = 3;
    d2.os.unchanged.total = 100;
    const deltas = new Map([
      [b.scanId, d1],
      [c.scanId, d2],
    ]);

    const result = projectBuildDeltas("app", "svc", pairs, deltas);
    expect(result.comparedBuilds).toBe(2);
    expect(result.average!.app.fixed).toEqual({ total: 2, critical: 0.5, high: 0 });
    expect(result.average!.app.introduced.total).toBe(1.5);
    expect(result.average!.os.unchanged.total).toBe(50);
    expect(result.last!.scanId).toBe(c.scanId);
    expect(result.last!.app.introduced.total).toBe(3);

    expect(windowMovement(pairs, deltas)).toMatchObject({ compared: 2, fixed: 4, introduced: 3, fixedCH: 1 });
  });

  it("weighs every project the same in the estate average", () => {
    const one = zeroPair();
    one.app.fixed.total = 10;
    const section = buildDeltaSection(
      [
        { applicationId: "a", name: "a", comparedBuilds: 9, average: one, last: null },
        { applicationId: "b", name: "b", comparedBuilds: 1, average: zeroPair(), last: null },
        { applicationId: "c", name: "c", comparedBuilds: 0, average: null, last: null },
      ],
      2,
    );
    expect(section.estateAverage!.app.fixed.total).toBe(5);
    expect(section.comparedBuilds).toBe(10);
    expect(section.identicalRebuildsSkipped).toBe(2);
  });
});

describe("squad and tribe rollups", () => {
  it("counts a project on two squads in both, groups case-insensitively, and lists the unassigned last", () => {
    const rows = rollup(
      [
        project({ applicationId: "1", squads: ["Payments", "Core"] }),
        project({ applicationId: "2", squads: ["payments"] }),
        project({ applicationId: "3", squads: [] }),
      ],
      "squads",
      new Set(["2"]),
    );
    expect(rows.map((r) => [r.name, r.applications, r.flaggedApplications])).toEqual([
      ["Core", 1, 0],
      ["Payments", 2, 1],
      [null, 1, 0],
    ]);
    expect(rows[1]!.vulnerabilities).toMatchObject({ fixed: 6, introduced: 2, net: -4 });
  });

  it("weights the time to fix by fixes, not by projects", () => {
    const base = project().vulnerabilities!;
    const rows = rollup(
      [
        project({ applicationId: "1", squads: ["s"], vulnerabilities: { ...base, meanDaysToFix: 10, fixesTimed: 9 } }),
        project({ applicationId: "2", squads: ["s"], vulnerabilities: { ...base, meanDaysToFix: 100, fixesTimed: 1 } }),
      ],
      "squads",
      new Set(),
    );
    expect(rows[0]!.vulnerabilities!.meanDaysToFix).toBe(19);
  });
});
