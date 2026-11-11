import { describe, expect, it } from "vitest";
import type { AnalyticsReport, ReportRunSummary } from "@sbom/shared";
import { placeholdersFor, reportWindowDays, totalsOf } from "../../src/modules/reports/report.service.js";
import { currentMonthPeriod, previousMonthPeriod } from "../../src/modules/reports/period.js";
import { renderTemplate } from "../../src/modules/reports/mailer.js";

/**
 * The monthly report is the analytics report for the month, filed and emailed. What it adds is
 * small and easy to get wrong silently: how long the window is, which headline figures are
 * filed with the run, and what the email says - including when scanning was off and a figure
 * was never measured.
 */

const TZ = "Asia/Tbilisi";

describe("report window", () => {
  it("covers the whole previous month for a monthly run", () => {
    const now = new Date("2026-12-01T06:00:00Z");
    expect(reportWindowDays(previousMonthPeriod(now, TZ), now)).toBe(30); // November
  });

  it("covers the month so far for an ad-hoc run, and never less than a day", () => {
    const now = new Date("2026-11-11T12:00:00Z");
    expect(reportWindowDays(currentMonthPeriod(now, TZ), now)).toBe(11);
    const first = new Date("2026-11-01T00:30:00Z");
    expect(reportWindowDays(currentMonthPeriod(first, TZ), first)).toBe(1);
  });
});

function report(vulnScanningEnabled: boolean): AnalyticsReport {
  const v = (fixed: number, introduced: number) => ({
    comparedBuilds: 1,
    fixed,
    introduced,
    net: introduced - fixed,
    fixedCriticalHigh: 0,
    introducedCriticalHigh: 0,
    openCritical: 0,
    openHigh: 0,
    criticalHighAtStart: null,
    criticalHighChange: null,
    meanDaysToFix: null,
    fixesTimed: 0,
  });
  const builds = { inWindow: 1, lastBuildAt: null, daysSinceLastBuild: null, cadenceBuilds: 1, averageDaysBetweenBuilds: null };
  return {
    meta: { vulnScanningEnabled },
    totals: { applications: 12 },
    progress: {
      projects: [
        { vulnerabilities: vulnScanningEnabled ? v(10, 3) : null, builds },
        { vulnerabilities: vulnScanningEnabled ? v(1, 7) : null, builds },
      ],
      squads: [],
      tribes: [],
    },
    attention: { projects: [{}, {}, {}], packages: [], fragmentationRising: [] },
  } as unknown as AnalyticsReport;
}

const run = { periodLabel: "2026-11", generatedAt: "2026-12-01T06:00:00.000Z" } as ReportRunSummary;

describe("filed totals and email placeholders", () => {
  it("sums the window's movement across projects", () => {
    const totals = totalsOf(report(true), { findings: 900, critical: 4, high: 40 });
    expect(totals).toEqual({
      applications: 12,
      fixed: 11,
      introduced: 10,
      openFindings: 900,
      openCritical: 4,
      openHigh: 40,
      needAttention: 3,
    });
  });

  it("fills every documented placeholder, keeping the old name for fixed", () => {
    const values = placeholdersFor(run, totalsOf(report(true), { findings: 1234, critical: 4, high: 40 }));
    expect(values).toMatchObject({
      period: "2026-11",
      applications: "12",
      findings: "1,234",
      fixed: "11",
      resolved: "11",
      introduced: "10",
      net: "-1",
      attention: "3",
      generatedAt: "2026-12-01 06:00 UTC",
    });
    expect(renderTemplate("{{introduced}} in (net {{net}})", values)).toBe("10 in (net -1)");
  });

  it("says n/a, never 0, for figures not measured with scanning off", () => {
    const values = placeholdersFor(run, totalsOf(report(false), { findings: 0, critical: 0, high: 0 }));
    expect(values).toMatchObject({ fixed: "n/a", introduced: "n/a", net: "n/a", findings: "n/a", applications: "12" });
  });

  it("signs a rise", () => {
    expect(placeholdersFor(run, { fixed: 1, introduced: 5 }).net).toBe("+4");
  });
});
