import { describe, expect, it } from "vitest";
import {
  compareVersions,
  normalizeEcosystem,
  normalizePackageName,
  reportCoversVersion,
  versionInRange,
  type MatchableReport,
} from "../../src/modules/malicious/matching.js";
import { parseOsvReport } from "../../src/modules/malicious/malicious-feed.service.js";

/**
 * Deciding whether a package in the estate is the package a malicious-package report names.
 *
 * The aggregation and the sweep need a database and are verified against one. What is pinned
 * here is the decision itself, because it fails in two directions that are both expensive and
 * neither of which announces itself:
 *
 *   a false NEGATIVE leaves real malware in the estate and reports the estate as clean. Nobody
 *   ever discovers it, because the absence of a finding looks exactly like the absence of a
 *   problem;
 *
 *   a false POSITIVE starts an incident. Somebody rotates a fleet of credentials and tears down
 *   a service over a package that was fine, and the next real finding is trusted less.
 *
 * The feed's own shape is what makes exactness achievable: of its 236,015 reports, 89.7% say
 * "every version of this package", 13.6% list exact versions, and under 1% need a version
 * comparison at all. These tests hold the line between those three.
 */

const report = (over: Partial<MatchableReport> = {}): MatchableReport => ({
  id: "MAL-2024-1",
  matchMode: "all_versions",
  affectedVersions: [],
  versionRanges: null,
  ...over,
});

describe("ecosystem normalisation", () => {
  it("translates OSV's names to the purl types stored on components", () => {
    // Two vocabularies for one set. Getting this wrong does not error -- it simply never
    // matches, which is the silent failure.
    expect(normalizeEcosystem("npm")).toBe("npm");
    expect(normalizeEcosystem("PyPI")).toBe("pypi");
    expect(normalizeEcosystem("RubyGems")).toBe("gem");
    expect(normalizeEcosystem("crates.io")).toBe("cargo");
    expect(normalizeEcosystem("Go")).toBe("golang");
    expect(normalizeEcosystem("NuGet")).toBe("nuget");
    expect(normalizeEcosystem("Packagist")).toBe("composer");
  });

  it("drops the qualifier after a colon", () => {
    // OSV qualifies some ecosystems by distribution or registry. The qualifier names where the
    // package came from, not what kind of package it is.
    expect(normalizeEcosystem("VSCode:https://open-vsx.org")).toBeNull();
    expect(normalizeEcosystem("Go:something")).toBe("golang");
  });

  it("returns null for ecosystems this platform cannot observe", () => {
    // Syft never reports a VSCode extension, so storing the report would pad a number an
    // administrator reads as coverage with entries that can never match anything.
    expect(normalizeEcosystem("VSCode")).toBeNull();
    expect(normalizeEcosystem("Chainguard")).toBeNull();
  });
});

describe("package name normalisation", () => {
  it("applies PEP 503 to PyPI, where punctuation and case are not significant", () => {
    // PyPI treats all of these as one project. A report filed under one spelling must match an
    // SBOM that used another, or the finding is silently lost.
    expect(normalizePackageName("pypi", "Zope.Interface")).toBe("zope-interface");
    expect(normalizePackageName("pypi", "zope_interface")).toBe("zope-interface");
    expect(normalizePackageName("pypi", "ZOPE--INTERFACE")).toBe("zope-interface");
  });

  it("folds case for npm without touching the scope separator", () => {
    expect(normalizePackageName("npm", "Left-Pad")).toBe("left-pad");
    expect(normalizePackageName("npm", "@Scope/Thing")).toBe("@scope/thing");
  });

  it("leaves Maven and Go alone, where case IS significant", () => {
    /*
      github.com/Sirupsen/logrus and github.com/sirupsen/logrus were genuinely two different
      modules at the same time. Folding case here would merge them and attribute a finding
      against one to consumers of the other.
    */
    expect(normalizePackageName("golang", "github.com/Sirupsen/logrus")).toBe(
      "github.com/Sirupsen/logrus",
    );
    expect(normalizePackageName("maven", "com.Example:Thing")).toBe("com.Example:Thing");
  });
});

describe("version comparison", () => {
  it("orders ordinary releases numerically, not lexically", () => {
    // The classic string-compare bug: "10" sorts before "9" as text, which would put a range
    // boundary in the wrong place for every package that reaches version 10.
    expect(compareVersions("1.10.0", "1.9.0")).toBe(1);
    expect(compareVersions("2.0.0", "10.0.0")).toBe(-1);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("treats missing components as zero", () => {
    expect(compareVersions("1.2", "1.2.0")).toBe(0);
    expect(compareVersions("1.2.1", "1.2")).toBe(1);
  });

  it("sorts a prerelease below the release it leads to", () => {
    // Per semver. Collapsing them would make a range starting at 1.0.0 swallow every release
    // candidate published before it.
    expect(compareVersions("1.0.0-rc1", "1.0.0")).toBe(-1);
    expect(compareVersions("1.0.0", "1.0.0-rc1")).toBe(1);
  });

  it("returns null rather than guessing when a version is not orderable", () => {
    /*
      The signal the range matcher depends on. `1.0.RELEASE` against `1.0.0` has no defensible
      ordering, and inventing one would silently shift which versions a range covers.
    */
    expect(compareVersions("1.0.RELEASE", "1.0.0")).toBeNull();
    expect(compareVersions("", "1.0.0")).toBeNull();
    expect(compareVersions("latest", "1.0.0")).toBeNull();
  });
});

describe("range matching", () => {
  const range = (over: Record<string, string | null>) => [
    { type: "SEMVER", introduced: null, fixed: null, lastAffected: null, ...over },
  ];

  it("covers everything from an introduced bound with no upper bound", () => {
    expect(versionInRange("1.2.3", range({ introduced: "1.2.2" }))).toBe(true);
    expect(versionInRange("9.0.0", range({ introduced: "1.2.2" }))).toBe(true);
    expect(versionInRange("1.2.1", range({ introduced: "1.2.2" }))).toBe(false);
  });

  it("treats `fixed` as exclusive and `last_affected` as inclusive", () => {
    /*
      OSV's two upper bounds mean different things, and conflating them shifts every bounded
      range by exactly one release -- either missing the last compromised version or condemning
      the first clean one.
    */
    expect(versionInRange("2.0.0", range({ introduced: "1.0.0", fixed: "2.0.0" }))).toBe(false);
    expect(versionInRange("1.9.9", range({ introduced: "1.0.0", fixed: "2.0.0" }))).toBe(true);
    expect(versionInRange("2.0.0", range({ introduced: "1.0.0", lastAffected: "2.0.0" }))).toBe(true);
    expect(versionInRange("2.0.1", range({ introduced: "1.0.0", lastAffected: "2.0.0" }))).toBe(false);
  });

  it("reports the match when the versions cannot be ordered", () => {
    /*
      Uncertainty resolves toward reporting, and the direction is chosen rather than accidental.
      A dropped match is invisible -- nobody learns the platform quietly decided a version was
      outside a range. A reported one is visible, attributed to its upstream report, and
      dismissable in a click. Ranges are 0.7% of the feed, so the noise this admits is bounded
      in a way the silence would not be.
    */
    expect(versionInRange("1.0.RELEASE", range({ introduced: "1.0.0" }))).toBe(true);
  });

  it("does not match on an empty range list", () => {
    expect(versionInRange("1.0.0", [])).toBe(false);
  });
});

describe("does a report cover this package version", () => {
  it("matches every version when the whole package is malicious", () => {
    const whole = report({ matchMode: "all_versions" });
    expect(reportCoversVersion(whole, "0.0.1")).toBe(true);
    expect(reportCoversVersion(whole, "99.0.0")).toBe(true);
    // Including a version that did not exist when the report was written: a typosquat's author
    // can publish more, and they are malicious too.
    expect(reportCoversVersion(whole, "2030.1.1")).toBe(true);
  });

  it("matches an unversioned component only when the whole package is malicious", () => {
    /*
      CycloneDX permits a component with no resolvable version. For a wholly malicious package
      the name alone is the finding; for a specific compromised release, asserting that an
      unknown version is one of them would be inventing the fact the match rests on.
    */
    expect(reportCoversVersion(report({ matchMode: "all_versions" }), null)).toBe(true);
    expect(
      reportCoversVersion(report({ matchMode: "exact_versions", affectedVersions: ["1.0.0"] }), null),
    ).toBe(false);
    expect(reportCoversVersion(report({ matchMode: "version_range", versionRanges: [] }), null)).toBe(
      false,
    );
  });

  it("matches exact versions exactly, and nothing either side of them", () => {
    /*
      The dangerous class: a legitimate, widely used package with three compromised releases.
      Widening this would condemn every version of something half the estate depends on.
    */
    const exact = report({
      matchMode: "exact_versions",
      affectedVersions: ["1.0.0", "1.0.3", "1.32.1"],
    });
    expect(reportCoversVersion(exact, "1.0.0")).toBe(true);
    expect(reportCoversVersion(exact, "1.32.1")).toBe(true);
    expect(reportCoversVersion(exact, "1.0.1")).toBe(false);
    expect(reportCoversVersion(exact, "1.0.2")).toBe(false);
    expect(reportCoversVersion(exact, "2.0.0")).toBe(false);
  });
});

/**
 * Turning an OSV document into a row.
 *
 * The documents here are cut down from real entries in the OpenSSF feed, keeping the fields
 * the parser reads and the shapes that decide which of the three match modes applies.
 */
describe("parsing an OSV malicious-package report", () => {
  const base = {
    id: "MAL-2024-1677",
    summary: "Malicious code in probe-pkg (npm)",
    details: "Any computer that has this package installed should be considered compromised.",
    modified: "2024-05-01T00:00:00Z",
    published: "2024-05-01T00:00:00Z",
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-x" }],
    database_specific: {
      "malicious-packages-origins": [{ source: "ghsa-malware" }, { source: "ghsa-malware" }],
    },
  };

  it("reads a whole-package report as all_versions", () => {
    const parsed = parseOsvReport({
      ...base,
      affected: [
        {
          package: { ecosystem: "npm", name: "probe-pkg" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ],
    });
    expect(parsed?.matchMode).toBe("all_versions");
    expect(parsed?.ecosystem).toBe("npm");
    // Left empty on purpose: listing versions for a wholly malicious package implies the
    // others are safe.
    expect(parsed?.affectedVersions).toEqual([]);
  });

  it("reads an explicit version list as exact_versions", () => {
    const parsed = parseOsvReport({
      ...base,
      affected: [
        {
          package: { ecosystem: "npm", name: "probe-pkg" },
          versions: ["2.0.2", "1.2.0"],
        },
      ],
    });
    expect(parsed?.matchMode).toBe("exact_versions");
    expect(parsed?.affectedVersions).toEqual(["2.0.2", "1.2.0"]);
  });

  it("prefers all_versions over an explicit list when the range says from zero", () => {
    /*
      Around nine thousand reports carry both. Where the range starts at 0 the package exists
      only to carry a payload, and its `versions` array is an inventory of what happened to be
      published when somebody looked -- so matching exactly against it would miss every version
      the attacker pushed afterwards.
    */
    const parsed = parseOsvReport({
      ...base,
      affected: [
        {
          package: { ecosystem: "npm", name: "probe-pkg" },
          versions: ["1.0.0"],
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ],
    });
    expect(parsed?.matchMode).toBe("all_versions");
  });

  it("reads a bounded range as version_range and keeps both bounds", () => {
    const parsed = parseOsvReport({
      ...base,
      affected: [
        {
          package: { ecosystem: "npm", name: "probe-pkg" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.27" }, { last_affected: "2.0.28" }] }],
        },
      ],
    });
    expect(parsed?.matchMode).toBe("version_range");
    expect(parsed?.versionRanges).toEqual([
      { type: "SEMVER", introduced: "2.0.27", fixed: null, lastAffected: "2.0.28" },
    ]);
  });

  it("treats a report with no version information as covering the package", () => {
    // A claim about the package rather than about a release of it.
    const parsed = parseOsvReport({
      ...base,
      affected: [{ package: { ecosystem: "npm", name: "probe-pkg" } }],
    });
    expect(parsed?.matchMode).toBe("all_versions");
  });

  it("carries provenance, deduplicated", () => {
    /*
      Not decoration. Telling somebody they shipped malware starts an incident, and they are
      entitled to see who reported it and read the original before they begin revoking keys.
    */
    const parsed = parseOsvReport({
      ...base,
      affected: [{ package: { ecosystem: "npm", name: "probe-pkg" } }],
    });
    expect(parsed?.sources).toEqual(["ghsa-malware"]);
    expect(parsed?.referenceUrl).toBe("https://github.com/advisories/GHSA-x");
  });

  it("records a withdrawal so a retracted report stops producing findings", () => {
    const parsed = parseOsvReport({
      ...base,
      withdrawn: "2026-07-16T00:38:53Z",
      affected: [{ package: { ecosystem: "npm", name: "probe-pkg" } }],
    });
    expect(parsed?.withdrawnAt).toBeInstanceOf(Date);
  });

  it("normalises the name it will be matched on", () => {
    const parsed = parseOsvReport({
      ...base,
      affected: [{ package: { ecosystem: "PyPI", name: "Zope.Interface" } }],
    });
    expect(parsed?.ecosystem).toBe("pypi");
    // Both are kept: one to match on, one to show.
    expect(parsed?.normalizedName).toBe("zope-interface");
    expect(parsed?.packageName).toBe("Zope.Interface");
  });

  it("drops a report this platform could never match", () => {
    expect(
      parseOsvReport({
        ...base,
        affected: [{ package: { ecosystem: "VSCode", name: "some.extension" } }],
      }),
    ).toBeNull();
    expect(parseOsvReport({ ...base, affected: [] })).toBeNull();
    expect(parseOsvReport({ affected: [{ package: { ecosystem: "npm", name: "x" } }] })).toBeNull();
  });
});
