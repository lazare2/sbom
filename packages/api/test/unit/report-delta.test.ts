import { describe, expect, it } from "vitest";
import { REPORT_SNAPSHOT_VERSION, type ReportSnapshot } from "@sbom/shared";
import { computeDelta, findingKey } from "../../src/modules/reports/delta.js";

/**
 * The delta is the whole report, and it is where the report can most easily mislead.
 *
 * Findings are matched against today's vulnerability database across retained builds, so a
 * count that fell means either the team upgraded something or the database changed its mind.
 * Presenting those as one number tells management the team did work it did not do. These
 * tests pin each attribution to the situation that produces it, and the situations are
 * deliberately the awkward ones: an application deleted with open findings, a package still
 * present whose advisory was withdrawn, a vulnerability that came back.
 */

const APP_A = "11111111-1111-1111-1111-111111111111";
const APP_B = "22222222-2222-2222-2222-222222222222";

function snapshot(over: Partial<ReportSnapshot> = {}): ReportSnapshot {
  const base: ReportSnapshot = {
    version: REPORT_SNAPSHOT_VERSION,
    takenAt: "2026-08-01T00:00:00.000Z",
    vulnDbBuiltAt: "2026-07-30T00:00:00.000Z",
    applications: [
      { id: APP_A, name: "checkout-web", status: "active", lastScanAt: null },
    ],
    components: [
      { id: 1, name: "log4j-core", version: "2.14.1", ecosystem: "maven", kind: "library" },
      { id: 2, name: "log4j-core", version: "2.24.1", ecosystem: "maven", kind: "library" },
    ],
    dependencies: { [APP_A]: [1] },
    findings: [findingKey(APP_A, 1, "CVE-2021-44228")],
    severities: { "CVE-2021-44228": "critical" },
    totals: {
      applications: 1,
      components: 1,
      findings: 1,
      bySeverity: { critical: 1 },
    },
    ...over,
  };
  return base;
}

describe("report delta attribution", () => {
  it("calls it an upgrade when the vulnerable package is gone but the application remains", () => {
    const before = snapshot();
    const after = snapshot({
      // Moved from log4j-core 2.14.1 to 2.24.1: the vulnerable component id is no longer present.
      dependencies: { [APP_A]: [2] },
      findings: [],
      totals: { applications: 1, components: 1, findings: 0, bySeverity: {} },
    });

    const delta = computeDelta(before, after);

    expect(delta.findings.resolved).toHaveLength(1);
    expect(delta.findings.resolved[0]?.cause).toBe("upgraded-or-removed");
  });

  it("does NOT call it an upgrade when the package is still there and the advisory changed", () => {
    const before = snapshot();
    const after = snapshot({
      // Same dependency, same version. Only the finding disappeared, so the database moved.
      vulnDbBuiltAt: "2026-08-15T00:00:00.000Z",
      findings: [],
      totals: { applications: 1, components: 1, findings: 0, bySeverity: {} },
    });

    const delta = computeDelta(before, after);

    // The distinction the whole report exists for: nobody fixed anything here.
    expect(delta.findings.resolved[0]?.cause).toBe("advisory-withdrawn-or-rescored");
    expect(delta.databaseChanged).toBe(true);
  });

  it("attributes findings on a deleted application to the deletion, not to a fix", () => {
    const before = snapshot();
    const after = snapshot({
      applications: [],
      dependencies: {},
      findings: [],
      totals: { applications: 0, components: 0, findings: 0, bySeverity: {} },
    });

    const delta = computeDelta(before, after);

    // Deleting an application would otherwise read as the best month the team ever had.
    expect(delta.findings.resolved[0]?.cause).toBe("application-removed");
    expect(delta.applications.removed).toEqual([{ id: APP_A, name: "checkout-web" }]);
  });

  it("separates a newly published advisory from a newly added dependency", () => {
    const before = snapshot({ findings: [], totals: { applications: 1, components: 1, findings: 0, bySeverity: {} } });

    // Same dependency as before, new advisory against it.
    const newAdvisory = snapshot({
      findings: [findingKey(APP_A, 1, "CVE-2026-0001")],
      severities: { "CVE-2026-0001": "high" },
      totals: { applications: 1, components: 1, findings: 1, bySeverity: { high: 1 } },
    });
    expect(computeDelta(before, newAdvisory).findings.introduced[0]?.cause).toBe(
      "newly-published-advisory",
    );

    // A component that was not in the previous build at all.
    const newDependency = snapshot({
      dependencies: { [APP_A]: [1, 2] },
      findings: [findingKey(APP_A, 2, "CVE-2026-0002")],
      severities: { "CVE-2026-0002": "high" },
      totals: { applications: 1, components: 2, findings: 1, bySeverity: { high: 1 } },
    });
    expect(computeDelta(before, newDependency).findings.introduced[0]?.cause).toBe("new-dependency");
  });

  it("attributes findings arriving with a new application to the application", () => {
    const before = snapshot();
    const after = snapshot({
      applications: [
        { id: APP_A, name: "checkout-web", status: "active", lastScanAt: null },
        { id: APP_B, name: "payments-api", status: "active", lastScanAt: null },
      ],
      dependencies: { [APP_A]: [1], [APP_B]: [1] },
      findings: [findingKey(APP_A, 1, "CVE-2021-44228"), findingKey(APP_B, 1, "CVE-2021-44228")],
      totals: { applications: 2, components: 1, findings: 2, bySeverity: { critical: 2 } },
    });

    const delta = computeDelta(before, after);

    expect(delta.findings.introduced).toHaveLength(1);
    expect(delta.findings.introduced[0]?.cause).toBe("application-added");
    expect(delta.applications.added).toEqual([{ id: APP_B, name: "payments-api" }]);
  });

  it("recognises a reintroduction only with the report before the baseline", () => {
    const twoMonthsAgo = snapshot();
    const lastMonth = snapshot({
      dependencies: { [APP_A]: [2] },
      findings: [],
      totals: { applications: 1, components: 1, findings: 0, bySeverity: {} },
    });
    const now = snapshot();

    // Without the earlier report this is indistinguishable from a new problem, and saying
    // otherwise would be invention.
    expect(computeDelta(lastMonth, now).findings.reintroduced).toHaveLength(0);
    expect(computeDelta(lastMonth, now, twoMonthsAgo).findings.reintroduced).toHaveLength(1);
  });

  it("keeps introduced totalling the sum of its causes when something is reintroduced", () => {
    const twoMonthsAgo = snapshot();
    const lastMonth = snapshot({
      dependencies: { [APP_A]: [2] },
      findings: [],
      totals: { applications: 1, components: 1, findings: 0, bySeverity: {} },
    });
    const now = snapshot();

    const delta = computeDelta(lastMonth, now, twoMonthsAgo);

    // A regression is a property of a finding, not a fourth bucket beside the causes. If it
    // were counted instead of being introduced, the report would stop adding up.
    expect(delta.findings.introduced).toHaveLength(1);
    expect(delta.findings.reintroduced).toHaveLength(1);
  });

  it("reports a severity that fell to zero rather than dropping it", () => {
    const before = snapshot();
    const after = snapshot({
      dependencies: { [APP_A]: [2] },
      findings: [],
      totals: { applications: 1, components: 1, findings: 0, bySeverity: {} },
    });

    // Critical going 1 -> 0 is the best news in the report; omitting the row hides it.
    expect(computeDelta(before, after).findings.bySeverity.critical).toEqual({ now: 0, before: 1 });
  });

  it("does not flag a database change when the build is unchanged", () => {
    const delta = computeDelta(snapshot(), snapshot());
    expect(delta.databaseChanged).toBe(false);
    expect(delta.findings.resolved).toHaveLength(0);
    expect(delta.findings.introduced).toHaveLength(0);
  });

  it("counts dependency movement across the estate", () => {
    const before = snapshot();
    const after = snapshot({ dependencies: { [APP_A]: [2] } });

    const delta = computeDelta(before, after);

    expect(delta.dependencies.added).toBe(1);
    expect(delta.dependencies.removed).toBe(1);
  });
});
