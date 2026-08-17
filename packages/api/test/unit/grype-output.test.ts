import { describe, expect, it } from "vitest";
import {
  buildScanDocument,
  collectAliases,
  parseGrypeReport,
  pickCvss,
  pickEpss,
  toFixState,
  toSeverity,
} from "../../src/services/scanner/grype-output.js";

/**
 * Tests for the Grype report parser.
 *
 * This is where the correctness risk in the whole vulnerability feature sits: every count
 * on every dashboard is downstream of these functions, and a mis-parsed severity or a
 * finding attributed to the wrong package produces numbers that look entirely plausible
 * and are wrong.
 *
 * The fixtures are shaped from real Grype 0.115.0 output, including the details that were
 * verified rather than assumed — `bom-ref` coming back as `artifact.id`, the CVE living in
 * `relatedVulnerabilities` when the primary id is a GHSA, and `knownExploited` being an
 * array whose presence is the signal.
 */

/** One match, with the fields the parser reads. */
function match(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    vulnerability: {
      id: "GHSA-jfh8-c2jp-5v3q",
      severity: "Critical",
      dataSource: "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
      namespace: "github:language:java",
      urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
      description: "Remote code execution in Log4j.",
      cvss: [
        { type: "Secondary", version: "3.1", vector: "CVSS:3.1/AV:N", metrics: { baseScore: 10 } },
      ],
      epss: [{ cve: "CVE-2021-44228", epss: 0.99999, percentile: 1, date: "2026-08-11" }],
      knownExploited: [{ cve: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j2" }],
      fix: { versions: ["2.15.0"], state: "fixed" },
      ...(overrides.vulnerability as object | undefined),
    },
    relatedVulnerabilities: overrides.relatedVulnerabilities ?? [{ id: "CVE-2021-44228" }],
    matchDetails: overrides.matchDetails ?? [{ type: "exact-direct-match" }],
    artifact: { id: "4071", name: "log4j-core", version: "2.14.1", type: "java-archive", ...(overrides.artifact as object | undefined) },
  };
}

function report(matches: unknown[], descriptor?: unknown): string {
  return JSON.stringify({
    matches,
    descriptor: descriptor ?? {
      name: "grype",
      version: "0.115.0",
      db: { status: { schemaVersion: "v6.1.9", built: "2026-08-12T06:38:08Z", valid: true } },
    },
  });
}

describe("toSeverity", () => {
  it("lowercases Grype's ladder", () => {
    expect(toSeverity("Critical")).toBe("critical");
    expect(toSeverity("HIGH")).toBe("high");
    expect(toSeverity("Negligible")).toBe("negligible");
  });

  it("maps anything unrecognised to unknown rather than guessing", () => {
    /*
     * Both alternatives misrepresent the data: dropping the finding hides a real match,
     * and defaulting to `low` invents an assessment nobody made. Plenty of advisories
     * genuinely carry no rating.
     */
    expect(toSeverity("Moderate")).toBe("unknown");
    expect(toSeverity("")).toBe("unknown");
    expect(toSeverity(undefined)).toBe("unknown");
    expect(toSeverity(7)).toBe("unknown");
  });
});

describe("toFixState", () => {
  it("keeps wont-fix distinct from not-fixed", () => {
    // Different work: one waits for a release, the other never gets one.
    expect(toFixState("fixed")).toBe("fixed");
    expect(toFixState("not-fixed")).toBe("not-fixed");
    expect(toFixState("wont-fix")).toBe("wont-fix");
    expect(toFixState("unknown")).toBe("unknown");
    expect(toFixState(null)).toBe("unknown");
  });
});

describe("pickCvss", () => {
  it("takes the highest CVSS version, not the highest score", () => {
    /*
     * Preferring the largest number would systematically inflate scores by always
     * choosing whichever scale rated the advisory worst. The newest metric is the current
     * assessment.
     */
    const result = pickCvss([
      { version: "2.0", vector: "AV:N/AC:L", metrics: { baseScore: 10 } },
      { version: "3.1", vector: "CVSS:3.1/AV:N", metrics: { baseScore: 7.5 } },
    ]);
    expect(result.baseScore).toBe(7.5);
    expect(result.vector).toBe("CVSS:3.1/AV:N");
  });

  it("returns nulls rather than zero when no score is present", () => {
    // Zero is a real CVSS score meaning "no impact"; absence has to stay absent.
    expect(pickCvss([])).toEqual({ baseScore: null, vector: null });
    expect(pickCvss(undefined)).toEqual({ baseScore: null, vector: null });
    // A CVSS entry with a version but no metrics still yields no score.
    expect(pickCvss([{ version: "3.1" }])).toEqual({ baseScore: null, vector: null });
  });

  it("survives a malformed entry", () => {
    const result = pickCvss([null, "nonsense", { version: "3.1", metrics: { baseScore: 9.8 } }]);
    expect(result.baseScore).toBe(9.8);
  });
});

describe("pickEpss", () => {
  it("takes the highest probability across the advisory's CVEs", () => {
    // Unlike CVSS these are all the same metric on the same scale, so "the worst CVE this
    // advisory covers" is a coherent answer.
    const result = pickEpss([
      { cve: "CVE-1", epss: 0.2, percentile: 0.5 },
      { cve: "CVE-2", epss: 0.9, percentile: 0.99 },
    ]);
    expect(result.score).toBe(0.9);
    expect(result.percentile).toBe(0.99);
  });

  it("returns nulls when absent", () => {
    expect(pickEpss(undefined)).toEqual({ score: null, percentile: null });
    expect(pickEpss([])).toEqual({ score: null, percentile: null });
  });
});

describe("collectAliases", () => {
  it("pulls the CVE out of relatedVulnerabilities", () => {
    /*
     * The behaviour CVE search depends on. Grype's primary id for a language package is
     * usually a GHSA — Log4Shell is GHSA-jfh8-c2jp-5v3q — and someone searching the CVE
     * number they read in the news has to reach the same row.
     */
    expect(collectAliases(match())).toEqual(["CVE-2021-44228"]);
  });

  it("never lists the advisory as its own alias", () => {
    // Otherwise a dedupe-by-alias would match a row against itself.
    const self = match({ relatedVulnerabilities: [{ id: "GHSA-jfh8-c2jp-5v3q" }, { id: "CVE-2021-44228" }] });
    expect(collectAliases(self)).toEqual(["CVE-2021-44228"]);
  });

  it("returns an empty array when there are none", () => {
    /*
     * The common shape for OS advisories, which are reported with the CVE as the primary
     * id. This case caused a real NOT NULL violation once, because array_agg over an empty
     * set returns NULL — so it is worth pinning that the parser produces `[]` and not
     * undefined.
     */
    expect(collectAliases(match({ relatedVulnerabilities: [] }))).toEqual([]);
    // Built without the fixture helper: its `?? default` would put the alias back.
    expect(collectAliases({ vulnerability: { id: "CVE-2024-6119" } })).toEqual([]);
  });
});

describe("parseGrypeReport", () => {
  it("maps a finding back to the exact component that was submitted", () => {
    /*
     * The single most important assertion in this file. `bom-ref` is set to the component
     * id and comes back as `artifact.id`, verified against Grype 0.115.0. Matching on purl
     * or name+version instead would mis-attribute findings whenever two components share a
     * name and version across ecosystems, or when a package has no purl at all.
     */
    const parsed = parseGrypeReport(report([match()]));
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]!.componentId).toBe(4071);
    expect(parsed.unmappedFindings).toBe(0);
  });

  it("counts a grype-generated artifact id as unmapped instead of guessing", () => {
    /*
     * When no bom-ref is supplied Grype substitutes a hash like `92547e41269f40eb`. Parsing
     * that as a component id is impossible, and silently dropping it would understate every
     * count — so it is counted, and the sweep logs it.
     */
    const parsed = parseGrypeReport(report([match({ artifact: { id: "92547e41269f40eb" } })]));
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.unmappedFindings).toBe(1);
  });

  it("rejects an artifact id that is not a bare integer", () => {
    for (const id of ["4071x", " 4071", "-5", "0", "4071.0", ""]) {
      const parsed = parseGrypeReport(report([match({ artifact: { id } })]));
      expect(parsed.findings, `id ${JSON.stringify(id)}`).toHaveLength(0);
      expect(parsed.unmappedFindings).toBe(1);
    }
  });

  it("extracts every field the dashboards depend on", () => {
    const finding = parseGrypeReport(report([match()])).findings[0]!;
    expect(finding.vulnerabilityId).toBe("GHSA-jfh8-c2jp-5v3q");
    expect(finding.severity).toBe("critical");
    expect(finding.aliases).toEqual(["CVE-2021-44228"]);
    expect(finding.cvssBaseScore).toBe(10);
    expect(finding.epssScore).toBe(0.99999);
    expect(finding.knownExploited).toBe(true);
    expect(finding.fixState).toBe("fixed");
    expect(finding.fixVersions).toEqual(["2.15.0"]);
    expect(finding.matchType).toBe("exact-direct-match");
    expect(finding.namespace).toBe("github:language:java");
  });

  it("treats an empty knownExploited array as not exploited", () => {
    // Presence of an entry is the signal, not presence of the key.
    const parsed = parseGrypeReport(report([match({ vulnerability: { knownExploited: [] } })]));
    expect(parsed.findings[0]!.knownExploited).toBe(false);
  });

  it("collapses the same (component, advisory) reported by two match rules", () => {
    /*
     * Grype reports one pairing more than once when several rules fire — a direct purl
     * match and a CPE match, say. Those are one finding, and letting both through would
     * double-count it in every severity total on every dashboard.
     */
    const parsed = parseGrypeReport(
      report([match(), match({ matchDetails: [{ type: "cpe-match" }] })]),
    );
    expect(parsed.findings).toHaveLength(1);
  });

  it("keeps the same advisory against two different components", () => {
    // The opposite case: one CVE affecting two packages is genuinely two findings.
    const parsed = parseGrypeReport(report([match(), match({ artifact: { id: "9" } })]));
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings.map((f) => f.componentId).sort((a, b) => a - b)).toEqual([9, 4071]);
  });

  it("reads the database provenance so a stale figure is explainable", () => {
    const parsed = parseGrypeReport(report([match()]));
    expect(parsed.grypeVersion).toBe("0.115.0");
    expect(parsed.dbBuiltAt?.toISOString()).toBe("2026-08-12T06:38:08.000Z");
    expect(parsed.dbSchemaVersion).toBe("v6.1.9");
  });

  it("skips a malformed match without discarding the batch", () => {
    /*
     * A sweep processes tens of thousands of matches at a time. One odd entry must not
     * throw away the other 9,999 — the batch would be retried forever and never converge.
     */
    const parsed = parseGrypeReport(report([null, "nonsense", { artifact: { id: "1" } }, match()]));
    expect(parsed.findings).toHaveLength(1);
  });

  it("throws on a payload that is not a grype report at all", () => {
    /*
     * The one case that must NOT degrade quietly. Returning zero findings for unparseable
     * output would mark every component in the batch as scanned and clean.
     */
    expect(() => parseGrypeReport("not json")).toThrow(/valid JSON/);
    expect(() => parseGrypeReport("[]")).toThrow(/JSON object/);
    expect(() => parseGrypeReport("{}")).toThrow(/matches/);
  });

  it("accepts a report with no matches as a genuine empty result", () => {
    // Distinct from the case above: a well-formed report with nothing in it means the
    // packages were checked and are clean.
    const parsed = parseGrypeReport(report([]));
    expect(parsed.findings).toEqual([]);
    expect(parsed.grypeVersion).toBe("0.115.0");
  });
});

describe("buildScanDocument", () => {
  const packages = [
    { componentId: 4071, name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ecosystem: "maven" },
    { componentId: 9, name: "openssl", version: "1.1.1n-0+deb11u3", purl: "pkg:deb/debian/openssl@1.1.1n-0+deb11u3?distro=debian-11&arch=amd64", ecosystem: "deb" },
    { componentId: 88, name: "no-purl-lib", version: null, purl: null, ecosystem: "unknown" },
  ];

  it("carries the component id as bom-ref", () => {
    const doc = JSON.parse(buildScanDocument(packages));
    expect(doc.components.map((c: { "bom-ref": string }) => c["bom-ref"])).toEqual(["4071", "9", "88"]);
  });

  it("passes the purl through verbatim, qualifiers included", () => {
    /*
     * The distro qualifier is what lets Grype match an OS package: verified that
     * `?distro=debian-11` alone is sufficient with no operating-system component present,
     * which is what makes batching packages from many distros into one document sound.
     */
    const doc = JSON.parse(buildScanDocument(packages));
    expect(doc.components[1].purl).toContain("?distro=debian-11&arch=amd64");
  });

  it("omits version and purl rather than sending null", () => {
    // CycloneDX has no null; a literal null there makes the document invalid.
    const doc = JSON.parse(buildScanDocument(packages));
    expect(doc.components[2]).not.toHaveProperty("version");
    expect(doc.components[2]).not.toHaveProperty("purl");
    expect(doc.components[2].name).toBe("no-purl-lib");
  });

  it("produces a document with the CycloneDX markers the parser requires", () => {
    const doc = JSON.parse(buildScanDocument(packages));
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.5");
    // No metadata.component: this document describes no single image, and inventing a
    // subject would put a meaningless name in grype's output.
    expect(doc.metadata.component).toBeUndefined();
  });

  it("handles an empty batch", () => {
    const doc = JSON.parse(buildScanDocument([]));
    expect(doc.components).toEqual([]);
  });
});
