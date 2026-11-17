import { describe, expect, it } from "vitest";
import { findingUrgency, projectStatus, type ProjectUrgencyCounts } from "@sbom/shared";
import {
  buildActionPlan,
  changeSize,
  upgradeLine,
  urgencyCounts,
  type PlanFinding,
} from "../../src/modules/vulnerabilities/action-plan.js";

/** Step 4: the developer view's rules - urgency, status, and one line per thing to do. */

const REMOTE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";

let id = 0;
function finding(over: Partial<PlanFinding>): PlanFinding {
  id += 1;
  return {
    componentId: 1,
    name: "lodash",
    version: "4.17.15",
    ecosystem: "npm",
    purl: "pkg:npm/lodash@4.17.15",
    origin: "app",
    vulnerabilityId: `CVE-2026-${id}`,
    severity: "high",
    knownExploited: false,
    fixState: "fixed",
    fixVersions: ["4.17.21"],
    cvssVector: LOCAL,
    paths: ["package-lock.json"],
    pulledInBy: [],
    ...over,
  };
}

describe("urgency of one vulnerability", () => {
  it.each([
    [{ fixable: true, usedInAttacks: true, severity: "low", remote: false }, "now"],
    [{ fixable: true, usedInAttacks: false, severity: "critical", remote: true }, "now"],
    [{ fixable: true, usedInAttacks: false, severity: "critical", remote: false }, "soon"],
    [{ fixable: true, usedInAttacks: false, severity: "high", remote: true }, "soon"],
    [{ fixable: true, usedInAttacks: false, severity: "medium", remote: true }, "later"],
    [{ fixable: false, usedInAttacks: true, severity: "critical", remote: true }, "none"],
  ] as const)("%o is %s", (input, expected) => {
    expect(findingUrgency(input)).toBe(expected);
  });
});

describe("project status", () => {
  const counts = (over: Partial<ProjectUrgencyCounts>): ProjectUrgencyCounts => ({
    total: 0, now: 0, nowUsedInAttacks: 0, soon: 0, later: 0, none: 0, noneSerious: 0, ...over,
  });
  const base = { hasBuild: true, stale: false, daysSinceBuild: 3, scanningOff: false };

  it("fix now names what makes it urgent", () => {
    expect(projectStatus({ ...base, counts: counts({ total: 5, now: 3, nowUsedInAttacks: 1 }) })).toEqual({
      status: "fix-now",
      reason: "1 vulnerability used in real attacks and 2 critical that can be attacked remotely, with a fix available.",
    });
  });

  it("fix soon for critical or high with a fix", () => {
    expect(projectStatus({ ...base, counts: counts({ total: 4, soon: 4 }) }).status).toBe("fix-soon");
  });

  it("an urgent fix outranks an old build, and the reason says both", () => {
    const r = projectStatus({ ...base, stale: true, daysSinceBuild: 45, counts: counts({ total: 1, now: 1 }) });
    expect(r.status).toBe("fix-now");
    expect(r.reason).toContain("No recent build: last build 45 days ago.");
  });

  it("no recent build when nothing urgent and the build is old, or there is none", () => {
    expect(projectStatus({ ...base, stale: true, daysSinceBuild: 45, counts: counts({ total: 2, later: 2 }) }))
      .toEqual({ status: "no-recent-build", reason: "No recent build: last build 45 days ago (2 lower-severity fixes available)." });
    expect(projectStatus({ ...base, hasBuild: false, daysSinceBuild: null, counts: counts({}) }).status).toBe("no-recent-build");
  });

  it("nothing to do still mentions what is waiting on a fix", () => {
    expect(projectStatus({ ...base, counts: counts({ total: 3, none: 3, noneSerious: 1 }) })).toEqual({
      status: "nothing-to-do",
      reason: "No critical or high vulnerability with a fix (1 critical or high without a fix yet).",
    });
    expect(projectStatus({ ...base, counts: counts({}) }).reason).toBe("No known vulnerabilities.");
  });

  it("says so when scanning is off rather than claiming the project is clean", () => {
    expect(projectStatus({ ...base, scanningOff: true, counts: counts({}) }).reason).toContain("switched off");
  });
});

describe("the action plan", () => {
  const findings: PlanFinding[] = [
    // lodash: three advisories, one upgrade.
    finding({ fixVersions: ["4.17.19"] }),
    finding({ fixVersions: ["4.17.21"], severity: "critical", cvssVector: REMOTE }),
    finding({ fixVersions: ["4.17.20"], severity: "medium" }),
    // jackson: one advisory, transitive.
    finding({
      name: "jackson-databind", version: "2.17.3", ecosystem: "maven",
      purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.3",
      fixVersions: ["2.18.0"], pulledInBy: ["spring-boot-starter-web"],
    }),
    // base image: openssl and zlib, used in real attacks once - one rebuild.
    finding({ name: "openssl", version: "3.0.13-1", ecosystem: "deb", origin: "os", fixVersions: ["3.0.15-1"], knownExploited: true }),
    finding({ name: "openssl", version: "3.0.13-1", ecosystem: "deb", origin: "os", fixVersions: ["3.0.15-1"] }),
    finding({ name: "zlib1g", version: "1.2.13", ecosystem: "deb", origin: "os", fixVersions: ["1.2.13.dfsg-1"] }),
    // no fix yet
    finding({ name: "glibc", ecosystem: "deb", origin: "os", fixState: "not-fixed", fixVersions: [], severity: "critical" }),
    finding({ name: "lodash", fixState: "not-fixed", fixVersions: [], severity: "low" }),
  ];
  const plan = buildActionPlan(findings, { osPretty: "Debian GNU/Linux 12 (bookworm)", imageRef: "registry/payments:1.4" });

  it("is one line per thing to do, not per vulnerability", () => {
    expect(plan.map((i) => i.key).sort()).toEqual(["base-image", "no-fix", "upgrade:maven:jackson-databind", "upgrade:npm:lodash"]);
  });

  it("puts every vulnerability in exactly one line, so it adds up to the list", () => {
    const fixLines = plan.filter((i) => i.kind !== "no-fix").reduce((n, i) => n + i.clears, 0);
    const noFix = plan.find((i) => i.kind === "no-fix")!;
    const waiting = Object.values(noFix.counts).reduce((n, x) => n + x, 0);
    expect(fixLines + waiting).toBe(findings.length);
    const counts = urgencyCounts(findings);
    expect(counts.total).toBe(findings.length);
    expect(counts.none).toBe(waiting);
  });

  it("upgrades a package once, to the version that clears all its advisories", () => {
    const lodash = plan.find((i) => i.key === "upgrade:npm:lodash")!;
    expect(lodash.title).toBe("Upgrade lodash from 4.17.15 to 4.17.21");
    expect(lodash.clears).toBe(3);
    expect(lodash.urgency).toBe("now"); // critical and remote
    expect(lodash.size).toBe("patch");
    expect(lodash.copyLine).toBe("npm install lodash@4.17.21");
    expect(lodash.where).toBe("In package-lock.json.");
  });

  it("says which direct dependency brings a transitive one in", () => {
    const jackson = plan.find((i) => i.key === "upgrade:maven:jackson-databind")!;
    expect(jackson.where).toContain("Brought in by spring-boot-starter-web");
    expect(jackson.size).toBe("minor");
    expect(jackson.copyLine).toContain("<artifactId>jackson-databind</artifactId><version>2.18.0</version>");
  });

  it("treats the base image as one rebuild", () => {
    const base = plan.find((i) => i.key === "base-image")!;
    expect(base.clears).toBe(3);
    expect(base.title).toBe("Rebuild on an up-to-date Debian GNU/Linux 12 (bookworm)");
    expect(base.urgency).toBe("now"); // used in real attacks
    expect(base.where).toContain("registry/payments:1.4");
  });

  it("ends with what has no fix yet, which is never urgent", () => {
    const noFix = plan.find((i) => i.kind === "no-fix")!;
    expect(noFix.urgency).toBe("none");
    expect(noFix.clears).toBe(0);
    expect(Math.max(...plan.map((i) => i.priority))).toBe(noFix.priority);
  });
});

describe("helpers", () => {
  it.each([
    ["1.2.3", "1.2.9", "patch"],
    ["1.2.3", "1.4.0", "minor"],
    ["1.2.3", "2.0.0", "major"],
    ["v1.2.3", "v1.2.4", "patch"],
    [null, "1.0.0", "unknown"],
  ] as const)("%s -> %s is %s", (from, to, size) => {
    expect(changeSize(from, to)).toBe(size);
  });

  it("writes the upgrade in each package manager's words", () => {
    expect(upgradeLine("pypi", "django", "4.2.16", null)).toBe("django>=4.2.16");
    expect(upgradeLine("golang", "golang.org/x/net", "0.33.0", null)).toBe("go get golang.org/x/net@v0.33.0");
    expect(upgradeLine("nuget", "Newtonsoft.Json", "13.0.1", null)).toBe("dotnet add package Newtonsoft.Json --version 13.0.1");
    expect(upgradeLine("unknown-eco", "x", "1", null)).toBeNull();
  });
});
