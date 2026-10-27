import { describe, expect, it } from "vitest";
import {
  chooseFix,
  compareVersions,
  normalizeVersion,
  planPackages,
  walkCandidate,
  withVersion,
  type CandidateFinding,
  type FindingInput,
} from "../../src/modules/vulnerabilities/fix-advisor.js";

/**
 * Fix recommendations.
 *
 * The question these answer is the one the findings table leaves to the reader: a package has
 * several advisories, each with its own "fixed in", so which single version clears them all -
 * and is that version itself clean? The worked example throughout is the one this feature was
 * asked for: three log4j advisories fixed in 1.2, 2.3 and 1.8 resolve to "at least 2.3", and if
 * 2.3 is itself affected by something fixed in 2.8, the answer is 2.8.
 */

const sorted = (versions: string[]) => [...versions].sort(compareVersions);

describe("ordering versions", () => {
  it("compares numeric runs as numbers, not as text", () => {
    // The bug a string sort ships: "2.10" sorting before "2.9".
    expect(compareVersions("2.10.0", "2.9.1")).toBe(1);
    expect(compareVersions("1.2", "1.10")).toBe(-1);
  });

  it("treats a shorter version as earlier than a longer numeric one", () => {
    expect(compareVersions("1.0", "1.0.1")).toBe(-1);
    expect(compareVersions("1.0.0", "1.0")).toBe(1);
  });

  it("puts pre-releases before the release they qualify", () => {
    expect(sorted(["2.0.0", "2.0.0-rc1", "2.0.0-beta2", "2.0.0-alpha"])).toEqual([
      "2.0.0-alpha",
      "2.0.0-beta2",
      "2.0.0-rc1",
      "2.0.0",
    ]);
    expect(compareVersions("5.3.0-SNAPSHOT", "5.3.0")).toBe(-1);
  });

  it("reads Final and GA as the release itself", () => {
    expect(compareVersions("5.4.2.Final", "5.4.2")).toBe(0);
    expect(compareVersions("5.4.3.Final", "5.4.2.Final")).toBe(1);
  });

  it("orders a distro revision after its upstream release", () => {
    expect(compareVersions("3.0.11-1~deb12u2", "3.0.11")).toBe(1);
    expect(compareVersions("3.0.11-1~deb12u2", "3.0.11-1~deb12u3")).toBe(-1);
  });

  it("puts Debian's tilde before everything, including the bare release", () => {
    expect(compareVersions("1.0~rc1", "1.0")).toBe(-1);
  });

  it("lets an epoch outrank any version without one", () => {
    expect(compareVersions("1:1.0", "9.9.9")).toBe(1);
  });
});

describe("cleaning provider notation", () => {
  it("strips Xray's range brackets and a leading v", () => {
    expect(normalizeVersion("[2.15.0]")).toBe("2.15.0");
    expect(normalizeVersion("[2.17.1,)")).toBe("2.17.1");
    expect(normalizeVersion("v1.4.2")).toBe("1.4.2");
    expect(normalizeVersion(">= 3.1")).toBe("3.1");
  });

  it("returns null for nothing at all", () => {
    expect(normalizeVersion("  ")).toBeNull();
    expect(normalizeVersion("[]")).toBeNull();
  });
});

describe("choosing the fix for one advisory", () => {
  it("takes the lowest fix above the installed version, not the newest release", () => {
    // One advisory, two release lines: the 2.12 line is fixed in 2.12.2, the 2.x line in 2.15.
    expect(chooseFix(["2.15.0", "2.12.2"], "2.12.1")).toBe("2.12.2");
    expect(chooseFix(["2.15.0", "2.12.2"], "2.14.1")).toBe("2.15.0");
  });

  it("finds nothing when every listed fix is at or below what is installed", () => {
    expect(chooseFix(["2.3.1"], "2.14.1")).toBeNull();
    expect(chooseFix([], "1.0")).toBeNull();
  });
});

describe("putting another version into a package URL", () => {
  it("keeps the qualifiers, which carry the distro", () => {
    expect(withVersion("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12", "3.0.15-1~deb12u1"))
      .toBe("pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12");
  });

  it("keeps an npm scope written with a literal @", () => {
    expect(withVersion("pkg:npm/@babel/core@7.0.0", "7.24.0")).toBe("pkg:npm/@babel/core@7.24.0");
    expect(withVersion("pkg:npm/%40babel/core@7.0.0", "7.24.0")).toBe("pkg:npm/%40babel/core@7.24.0");
  });

  it("encodes characters the version may not carry raw", () => {
    expect(withVersion("pkg:deb/debian/bash@5.2.15-2", "1:5.2.21-2")).toBe("pkg:deb/debian/bash@1%3A5.2.21-2");
  });

  it("adds a version to a purl that had none, and refuses something that is not a purl", () => {
    expect(withVersion("pkg:pypi/requests", "2.32.0")).toBe("pkg:pypi/requests@2.32.0");
    expect(withVersion("requests==2.31.0", "2.32.0")).toBeNull();
  });
});

const log4j = (over: Partial<FindingInput>): FindingInput => ({
  componentId: 1,
  name: "log4j-core",
  version: "1.0",
  ecosystem: "maven",
  purl: "pkg:maven/org.apache.logging.log4j/log4j-core@1.0",
  origin: "app",
  vulnerabilityId: "CVE-A",
  severity: "high",
  knownExploited: false,
  fixState: "fixed",
  fixVersions: [],
  ...over,
});

describe("one minimum version per package", () => {
  it("clears every advisory with the highest of their fixes", () => {
    const [plan] = planPackages([
      log4j({ vulnerabilityId: "CVE-A", fixVersions: ["1.2"] }),
      log4j({ vulnerabilityId: "CVE-B", fixVersions: ["2.3"], severity: "critical" }),
      log4j({ vulnerabilityId: "CVE-C", fixVersions: ["1.8"] }),
    ]);

    expect(plan!.minimumVersion).toBe("2.3");
    expect(plan!.resolvedByMinimum).toBe(3);
    // Worst first, so the reason to upgrade is at the top of the row's detail.
    expect(plan!.advisories[0]!.vulnerabilityId).toBe("CVE-B");
  });

  it("counts an advisory with no fix as unresolved rather than ignoring it", () => {
    const [plan] = planPackages([
      log4j({ vulnerabilityId: "CVE-A", fixVersions: ["1.2"] }),
      log4j({ vulnerabilityId: "CVE-X", fixVersions: [], fixState: "not-fixed" }),
    ]);
    expect(plan!.minimumVersion).toBe("1.2");
    expect(plan!.resolvedByMinimum).toBe(1);
    expect(plan!.advisories).toHaveLength(2);
  });

  it("has no minimum when nothing reported against it has a fix", () => {
    const [plan] = planPackages([log4j({ fixVersions: [], fixState: "wont-fix" })]);
    expect(plan!.minimumVersion).toBeNull();
  });

  it("treats two shipped versions as one package, and never recommends a downgrade", () => {
    // 2.14 is affected (fixed in 2.15); the build also ships 2.16. Moving both to 2.15 would
    // downgrade one of them, so the answer is the newer of the two.
    const plans = planPackages([
      log4j({ componentId: 1, version: "2.14.1", vulnerabilityId: "CVE-A", fixVersions: ["2.15.0"] }),
      log4j({
        componentId: 2,
        version: "2.16.0",
        purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
        vulnerabilityId: "CVE-Z",
        fixVersions: [],
        fixState: "not-fixed",
      }),
    ]);
    expect(plans).toHaveLength(1);
    expect(plans[0]!.installedVersions).toEqual(["2.14.1", "2.16.0"]);
    expect(plans[0]!.minimumVersion).toBe("2.16.0");
    // The candidate is substituted into the newest shipped version's purl.
    expect(plans[0]!.purl).toBe("pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0");
  });

  it("keeps different packages apart, including the same name in another ecosystem", () => {
    const plans = planPackages([
      log4j({ fixVersions: ["1.2"] }),
      log4j({ ecosystem: "npm", purl: "pkg:npm/log4j-core@1.0", fixVersions: ["9.9"] }),
    ]);
    expect(plans.map((p) => p.key).sort()).toEqual(["maven:log4j-core", "npm:log4j-core"]);
  });
});

describe("checking the minimum, and walking forward", () => {
  const db: Record<string, CandidateFinding[]> = {
    "2.3": [{ vulnerabilityId: "CVE-D", severity: "high", fixState: "fixed", fixVersions: ["2.8"] }],
    "2.8": [],
  };

  it("moves past a minimum that is itself affected, to a version with nothing known", () => {
    const walk = walkCandidate("2.3", (v) => db[v], 5);
    expect(walk.status).toBe("clean");
    expect(walk.recommendedVersion).toBe("2.8");
    // The chain is the explanation the screen shows: why 2.8 and not 2.3.
    expect(walk.checks.map((c) => c.version)).toEqual(["2.3", "2.8"]);
    expect(walk.checks[0]!.advisories[0]).toMatchObject({ vulnerabilityId: "CVE-D", fixedIn: "2.8" });
  });

  it("stops at residual when what remains has no later fix", () => {
    const walk = walkCandidate(
      "2.3",
      () => [{ vulnerabilityId: "CVE-N", severity: "medium", fixState: "not-fixed", fixVersions: [] }],
      5,
    );
    expect(walk.status).toBe("residual");
    expect(walk.recommendedVersion).toBe("2.3");
  });

  it("reports unverified, never clean, for a version it could not ask about", () => {
    const walk = walkCandidate("2.3", (v) => (v === "2.3" ? db["2.3"] : undefined), 5);
    expect(walk.status).toBe("unverified");
    // Where it would have gone next, so the next round knows what to ask.
    expect(walk.recommendedVersion).toBe("2.8");
  });

  it("gives up after the round limit rather than chasing fixes forever", () => {
    let n = 0;
    const walk = walkCandidate(
      "1",
      (v) => {
        n += 1;
        return [{ vulnerabilityId: `CVE-${v}`, severity: "low", fixState: "fixed", fixVersions: [String(Number(v) + 1)] }];
      },
      3,
    );
    expect(n).toBe(3);
    expect(walk.status).toBe("unverified");
  });
});
