import { describe, expect, it } from "vitest";
import { findCycle, supportStatus } from "@sbom/shared";
import { buildActionPlan, type PlanFinding } from "../../src/modules/vulnerabilities/action-plan.js";
import { buildPurl } from "../../src/modules/vulnerabilities/package.routes.js";
import { packageKey } from "../../src/modules/vulnerabilities/recommend.js";

/** Step 7: packages - the shared recommendation, version checks, out-of-support marks. */

describe("the support list shipped with the release", () => {
  it.each([
    ["debian", "10", "Debian 10"],
    ["debian", "12", "Debian 12"],
    ["ubuntu", "22.04", "Ubuntu 22.04"],
    ["alpine", "3.18.4", "Alpine Linux 3.18"],
    ["node", "22.11.0", "Node.js 22"],
    ["node", "v18.20.1", "Node.js 18"],
    ["python", "3.10.12", "Python 3.10"],
  ])("%s %s is %s", (product, version, label) => {
    expect(findCycle(product, version)?.label).toBe(label);
  });

  it("does not confuse 3.1 with 3.10", () => {
    expect(findCycle("python", "3.1.5")).toBeNull();
    expect(findCycle("python", "3.10.0")?.cycle).toBe("3.10");
  });

  it("says nothing about what it does not list", () => {
    expect(findCycle("debian", "99")).toBeNull();
    expect(findCycle("haiku-os", "1")).toBeNull();
    expect(supportStatus({ osName: "plan9", osVersion: "4", runtimes: [] })).toEqual([]);
  });

  it("marks ended and ending-soon cycles on the day asked", () => {
    const today = new Date("2026-11-17T00:00:00Z");
    const marks = supportStatus(
      { osName: "debian", osVersion: "10", runtimes: [{ name: "node", version: "22.1.0" }, { name: "python", version: "3.12.1" }] },
      today,
    );
    expect(marks).toEqual([
      { kind: "os", label: "Debian 10", endsOn: "2024-06-30", ended: true, endsSoon: false },
      { kind: "runtime", label: "Node.js 22", endsOn: "2027-04-30", ended: false, endsSoon: true },
      { kind: "runtime", label: "Python 3.12", endsOn: "2028-10-31", ended: false, endsSoon: false },
    ]);
  });
});

describe("the recommended version", () => {
  const finding = (over: Partial<PlanFinding>): PlanFinding => ({
    componentId: 1,
    name: "lodash",
    version: "4.17.15",
    ecosystem: "npm",
    purl: "pkg:npm/lodash@4.17.15",
    origin: "app",
    vulnerabilityId: "CVE-1",
    severity: "high",
    knownExploited: false,
    fixState: "fixed",
    fixVersions: ["4.17.19"],
    cvssVector: null,
    paths: [],
    pulledInBy: [],
    startedAt: "2026-11-01T00:00:00.000Z",
    ...over,
  });

  it("is the package page's version in the action plan, even above this project's own minimum", () => {
    const recommended = new Map([[packageKey("npm", "lodash"), { version: "4.17.21" }]]);
    const plan = buildActionPlan([finding({})], { osPretty: null, imageRef: null, recommended });
    expect(plan[0]!.toVersion).toBe("4.17.21");
    expect(plan[0]!.title).toBe("Upgrade lodash from 4.17.15 to 4.17.21");
    expect(plan[0]!.packageEcosystem).toBe("npm");
  });

  it("falls back to the project's own minimum where the page has none", () => {
    const plan = buildActionPlan([finding({})], { osPretty: null, imageRef: null, recommended: new Map() });
    expect(plan[0]!.toVersion).toBe("4.17.19");
  });
});

describe("checking a version nobody here uses yet", () => {
  it.each([
    ["npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"],
    ["npm", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"],
    ["maven", "org.apache.logging.log4j:log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"],
    ["pypi", "Django_REST", "3.15.2", "pkg:pypi/django-rest@3.15.2"],
    ["golang", "golang.org/x/net", "0.33.0", "pkg:golang/golang.org/x/net@v0.33.0"],
  ])("%s %s %s", (ecosystem, name, version, purl) => {
    expect(buildPurl(ecosystem, name, version)).toBe(purl);
  });

  it("refuses to guess a package URL it cannot build", () => {
    expect(buildPurl("maven", "log4j-core", "2.17.1")).toBeNull();
    expect(buildPurl("deb", "openssl", "3.0.15")).toBeNull();
  });
});
