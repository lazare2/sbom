import { describe, expect, it } from "vitest";
import {
  assemblePackageDetail,
  compareVersionsDesc,
  type DetailFinding,
  type DetailPair,
} from "../../src/modules/components/package-search.service.js";

/**
 * The package drill-down: which applications use a package, at which versions, and what the
 * vulnerability database says about the versions in current use.
 *
 * Every rule here is one a reader would otherwise have to guess at, and each one gets a wrong
 * answer silently - an upgrade read as a removal, a dropped version counted as exposure, an
 * unassessed version shown as clean.
 */

let scan = 0;
function pair(over: Partial<DetailPair>): DetailPair {
  scan += 1;
  return {
    componentId: "1",
    version: "1.0.0",
    assessed: true,
    applicationId: "app-a",
    applicationName: "alpha",
    applicationStatus: "active",
    inLatest: true,
    lastSeenScanId: `scan-${scan}`,
    lastSeenAt: "2026-10-01T00:00:00.000Z",
    lastSeenBuildNumber: "1",
    ...over,
  };
}

function finding(over: Partial<DetailFinding>): DetailFinding {
  return {
    applicationId: "app-a",
    version: "1.0.0",
    vulnerabilityId: "CVE-1",
    severity: "high",
    knownExploited: false,
    ...over,
  };
}

describe("package detail", () => {
  it("treats an upgrade as current use, and the old version as removed", () => {
    const { applications, versions } = assemblePackageDetail(
      [
        pair({ version: "1.0.0", inLatest: false, lastSeenAt: "2026-09-01T00:00:00.000Z" }),
        pair({ version: "1.1.0", inLatest: true }),
      ],
      [],
      true,
    );

    expect(applications).toHaveLength(1);
    expect(applications[0]).toMatchObject({ usage: "current", versions: ["1.1.0"] });
    expect(versions.map((v) => [v.version, v.currentApplications, v.historicalApplications])).toEqual([
      ["1.1.0", 1, 0],
      ["1.0.0", 0, 1],
    ]);
  });

  it("reports a dropped package by the versions in the last build that shipped it", () => {
    const { applications } = assemblePackageDetail(
      [
        pair({ version: "1.0.0", inLatest: false, lastSeenScanId: "old", lastSeenAt: "2026-08-01T00:00:00.000Z" }),
        pair({ version: "2.0.0", inLatest: false, lastSeenScanId: "newer", lastSeenAt: "2026-09-01T00:00:00.000Z" }),
      ],
      [],
      true,
    );
    expect(applications[0]).toMatchObject({ usage: "historical", versions: ["2.0.0"], lastSeenScanId: "newer" });
    expect(applications[0]!.vulnerabilities).toBeNull();
  });

  it("counts distinct advisories, not findings", () => {
    const { applications, versions } = assemblePackageDetail(
      [
        pair({ applicationId: "app-a", applicationName: "alpha" }),
        pair({ applicationId: "app-b", applicationName: "beta" }),
      ],
      [
        finding({ applicationId: "app-a", vulnerabilityId: "CVE-1", severity: "critical", knownExploited: true }),
        finding({ applicationId: "app-b", vulnerabilityId: "CVE-1", severity: "critical", knownExploited: true }),
        finding({ applicationId: "app-b", vulnerabilityId: "CVE-2", severity: "high" }),
      ],
      true,
    );

    // One version, two applications, CVE-1 in both: two advisories, not three findings.
    expect(versions[0]!.vulnerabilities).toEqual({ advisories: 2, critical: 1, high: 1, knownExploited: 1 });
    expect(applications.find((a) => a.applicationId === "app-a")!.vulnerabilities).toEqual({
      advisories: 1, critical: 1, high: 0, knownExploited: 1,
    });
    expect(applications.find((a) => a.applicationId === "app-b")!.vulnerabilities!.advisories).toBe(2);
  });

  it("shows an application with no findings as clean - it is still listed", () => {
    const { applications } = assemblePackageDetail([pair({})], [], true);
    expect(applications[0]!.vulnerabilities).toEqual({ advisories: 0, critical: 0, high: 0, knownExploited: 0 });
  });

  it("never reports an unassessed version as clean", () => {
    const { applications, versions } = assemblePackageDetail([pair({ assessed: false })], [], true);
    expect(applications[0]!.vulnerabilities).toBeNull();
    expect(versions[0]).toMatchObject({ assessed: false, vulnerabilities: null });
  });

  it("carries no vulnerability figures at all with scanning switched off", () => {
    const { applications, versions } = assemblePackageDetail([pair({})], [finding({})], false);
    expect(applications[0]!.vulnerabilities).toBeNull();
    expect(versions[0]!.vulnerabilities).toBeNull();
  });

  it("lists current users before past ones, then by name", () => {
    const { applications } = assemblePackageDetail(
      [
        pair({ applicationId: "z", applicationName: "zulu", inLatest: false }),
        pair({ applicationId: "b", applicationName: "bravo" }),
        pair({ applicationId: "a", applicationName: "Alpha" }),
      ],
      [],
      true,
    );
    expect(applications.map((a) => a.applicationName)).toEqual(["Alpha", "bravo", "zulu"]);
  });

  it("orders versions newest first, numerically, with an unknown version last", () => {
    const sorted = ["1.9.0", null, "1.10.0", "1.2.0"].sort(compareVersionsDesc);
    expect(sorted).toEqual(["1.10.0", "1.9.0", "1.2.0", null]);
  });
});
