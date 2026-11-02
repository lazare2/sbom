import { describe, expect, it } from "vitest";
import type { VulnScanner } from "@sbom/shared";
import type { ParsedFinding } from "../../src/services/scanner/grype-output.js";
import { compareVersions, upgradeFixes } from "../../src/services/scanner/versions.js";
import { buildTrivyDocuments, parseDistro, parseTrivyReport, sourcePackage, trivyFixState } from "../../src/services/scanner/trivy-output.js";
import { buildOsvDocument, osvFix, osvPurl, parseOsvReport } from "../../src/services/scanner/osv-output.js";
import { mergeFindings } from "../../src/services/scanner/merge.js";
import { CompositeScanner, type ScannerMember } from "../../src/services/scanner/composite.js";
import type { VulnerabilityScanner } from "../../src/services/scanner/types.js";

/**
 * Tests for merging several scanners' findings.
 *
 * The fixtures are cut down from real output - Trivy 0.76.1 and osv-scanner 2.7.0 against
 * spring-webflux 6.2.0, jackson-databind 2.9.10 and Debian's openssl - because the cases that
 * matter are the ones those produced: a fix on a later release line, fix lists spanning
 * several lines, and Debian bulletins that alias every CVE they fix.
 */

function finding(over: Partial<ParsedFinding> & { source: VulnScanner; vulnerabilityId: string }): ParsedFinding {
  return {
    componentId: 101,
    severity: "high",
    aliases: [],
    cvssBaseScore: null,
    cvssVector: null,
    epssScore: null,
    epssPercentile: null,
    knownExploited: false,
    description: null,
    summary: null,
    cwes: [],
    dataSource: null,
    namespace: null,
    urls: [],
    fixState: "unknown",
    fixVersions: [],
    matchType: null,
    affectedRange: null,
    ...over,
  };
}

describe("compareVersions", () => {
  it("orders the common shapes", () => {
    expect(compareVersions("6.2.19", "6.2.20")).toBeLessThan(0);
    expect(compareVersions("7.0.9", "6.2.20")).toBeGreaterThan(0);
    expect(compareVersions("2.9.10.1", "2.9.10")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0-rc1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("3.0.11-1~deb12u2", "3.0.11-1")).toBeLessThan(0);
    expect(compareVersions("3.0.13-1~deb12u1", "3.0.11-1~deb12u1")).toBeGreaterThan(0);
    expect(compareVersions("1:2.0", "3.0")).toBeGreaterThan(0);
    expect(compareVersions("v0.23.0", "0.17.0")).toBeGreaterThan(0);
    expect(compareVersions("5.2.26.RELEASE", "5.2.25.RELEASE")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("offers only fixes newer than what is installed, lowest first", () => {
    // Trivy lists every line's fix for jackson-databind; only one is an upgrade from 2.9.10.
    expect(upgradeFixes(["2.9.10.1", "2.8.11.5", "2.6.7.3"], "2.9.10")).toEqual(["2.9.10.1"]);
    expect(upgradeFixes(["7.0.9", "6.2.19", "6.2.19"], "6.2.0")).toEqual(["6.2.19", "7.0.9"]);
  });
});

describe("Trivy input", () => {
  const packages = [
    { componentId: 1, name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20", ecosystem: "npm" },
    {
      componentId: 2,
      name: "libssl3",
      version: "3.0.11-1~deb12u1",
      purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12.11&upstream=openssl",
      ecosystem: "deb",
    },
    { componentId: 3, name: "musl", version: "1.2.4-r2", purl: "pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.19.0", ecosystem: "apk" },
    { componentId: 4, name: "orphan", version: "1", purl: "pkg:deb/debian/orphan@1", ecosystem: "deb" },
    { componentId: 5, name: "nopurl", version: "1", purl: null, ecosystem: "unknown" },
  ];

  it("splits a batch into one document per distribution, because Trivy refuses mixed OS types", () => {
    const docs = buildTrivyDocuments(packages);
    expect(docs.map((d) => [d.label, d.componentIds])).toEqual([
      ["language", [1]],
      ["debian 12.11", [2]],
      ["alpine 3.19.0", [3]],
    ]);
  });

  it("leaves kernel header packages out, as Grype does, because a container runs the host's kernel", () => {
    const headers = [
      { componentId: 8, name: "linux-libc-dev", version: "6.12.111-1", purl: "pkg:deb/debian/linux-libc-dev@6.12.111-1?distro=debian-13.7&upstream=linux", ecosystem: "deb" },
      { componentId: 9, name: "linux-headers", version: "6.6.0-r0", purl: "pkg:apk/alpine/linux-headers@6.6.0-r0?distro=alpine-3.19.0", ecosystem: "apk" },
    ];
    expect(buildTrivyDocuments(headers)).toEqual([]);
    expect(buildOsvDocument(headers).byPurl.size).toBe(0);
  });

  it("names the distribution and each package's source, which Debian matching needs", () => {
    const deb = JSON.parse(buildTrivyDocuments(packages)[1]!.json) as {
      components: Array<{ type: string; name: string; version?: string; properties?: Array<{ name: string; value: string }> }>;
    };
    expect(deb.components[0]).toMatchObject({ type: "operating-system", name: "debian", version: "12.11" });
    expect(deb.components[1]!.properties).toEqual([
      { name: "aquasecurity:trivy:SrcName", value: "openssl" },
      { name: "aquasecurity:trivy:SrcVersion", value: "3.0.11-1~deb12u1" },
    ]);
  });

  it("reads Syft's distro and upstream qualifiers", () => {
    expect(parseDistro("debian-12.11")).toEqual({ family: "debian", version: "12.11" });
    expect(parseDistro("rhel-9.4")).toEqual({ family: "redhat", version: "9.4" });
    expect(sourcePackage("deb", "libgav1@0.18.0-1", "0.18.0-1+b1")).toEqual({ name: "libgav1", version: "0.18.0-1" });
    expect(sourcePackage("rpm", "openssl-3.0.7-24.el9.src.rpm", "3.0.7-24.el9")).toEqual({ name: "openssl", version: "3.0.7-24.el9" });
  });
});

describe("Trivy output", () => {
  const report = JSON.stringify({
    Results: [
      {
        Target: "Java",
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2026-47892",
            VendorIDs: ["GHSA-9qf2-26p9-2q2q"],
            PkgIdentifier: { BOMRef: "101" },
            InstalledVersion: "6.2.0",
            FixedVersion: "7.0.9",
            Status: "fixed",
            SeveritySource: "ghsa",
            Title: "Spring Framework: Header Predicate Bypass in WebFlux Functional Endpoints",
            Description: "A WebFlux application using functional endpoints may be vulnerable to a header predicate bypass.",
            Severity: "CRITICAL",
            CweIDs: ["CWE-863"],
            CVSS: { ghsa: { V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8 }, redhat: { V3Score: 6.5 } },
            References: ["https://spring.io/security/cve-2026-47892"],
            DataSource: { ID: "ghsa", URL: "https://github.com/advisories" },
          },
          {
            VulnerabilityID: "CVE-2019-16942",
            PkgIdentifier: { BOMRef: "103" },
            InstalledVersion: "2.9.10",
            FixedVersion: "2.9.10.1, 2.8.11.5, 2.6.7.3",
            Status: "fixed",
            Severity: "CRITICAL",
          },
          { VulnerabilityID: "CVE-2000-0001", PkgIdentifier: { BOMRef: "999" }, Severity: "LOW" },
        ],
      },
    ],
  });

  it("maps each finding back through its BOMRef and reports a fix on a later line", () => {
    const parsed = parseTrivyReport(report, new Set([101, 103]));
    const webflux = parsed.findings.find((f) => f.componentId === 101)!;
    expect(webflux).toMatchObject({
      vulnerabilityId: "CVE-2026-47892",
      aliases: ["GHSA-9qf2-26p9-2q2q"],
      severity: "critical",
      fixState: "fixed",
      fixVersions: ["7.0.9"],
      cvssBaseScore: 9.8,
      cwes: ["CWE-863"],
      source: "trivy",
    });
    expect(webflux.summary).toMatch(/Header Predicate Bypass/);
  });

  it("drops fix versions older than the installed one", () => {
    const parsed = parseTrivyReport(report, new Set([101, 103]));
    expect(parsed.findings.find((f) => f.componentId === 103)!.fixVersions).toEqual(["2.9.10.1"]);
  });

  it("counts a BOMRef outside the batch as unmapped rather than guessing", () => {
    expect(parseTrivyReport(report, new Set([101, 103])).unmappedFindings).toBe(1);
  });

  it("maps Trivy's statuses", () => {
    expect(trivyFixState("affected", [])).toBe("not-fixed");
    expect(trivyFixState("will_not_fix", [])).toBe("wont-fix");
    expect(trivyFixState("fixed", [])).toBe("not-fixed");
    expect(trivyFixState("fixed", ["1.0"])).toBe("fixed");
  });
});

describe("OSV input and output", () => {
  it("rewrites a Debian package to its source, which is what OSV matches", () => {
    expect(
      osvPurl({
        componentId: 1,
        name: "libssl3",
        version: "3.0.11-1~deb12u1",
        purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl",
        ecosystem: "deb",
      }),
    ).toBe("pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12");
    expect(osvPurl({ componentId: 2, name: "x", version: "1", purl: "pkg:generic/x@1", ecosystem: "generic" })).toBeNull();
  });

  it("leaves out the distributions it is told to skip, and nothing else", () => {
    const doc = buildOsvDocument(
      [
        { componentId: 1, name: "acl", version: "2.3.2", purl: "pkg:deb/ubuntu/acl@2.3.2?distro=ubuntu-24.04", ecosystem: "deb" },
        { componentId: 2, name: "acl", version: "2.3.1", purl: "pkg:deb/debian/acl@2.3.1?distro=debian-12", ecosystem: "deb" },
        { componentId: 3, name: "ubuntu", version: "1.0.0", purl: "pkg:npm/ubuntu@1.0.0", ecosystem: "npm" },
      ],
      ["ubuntu"],
    );
    expect([...doc.byPurl.values()]).toEqual([[2], [3]]);
  });

  it("sends two binaries of one source once and maps the result back to both", () => {
    const doc = buildOsvDocument([
      { componentId: 1, name: "libssl3", version: "3.0.11-1", purl: "pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12&upstream=openssl", ecosystem: "deb" },
      { componentId: 2, name: "openssl", version: "3.0.11-1", purl: "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12&upstream=openssl", ecosystem: "deb" },
    ]);
    expect([...doc.byPurl.values()]).toEqual([[1, 2]]);
  });

  const spring = {
    package: {
      name: "org.springframework:spring-webflux",
      version: "6.2.0",
      ecosystem: "Maven",
      purl: "pkg:maven/org.springframework/spring-webflux@6.2.0",
    },
    vulnerabilities: [
      {
        id: "GHSA-9qf2-26p9-2q2q",
        aliases: ["CVE-2026-47892"],
        summary: "Spring Framework Header Predicate Bypass in WebFlux Functional Endpoints",
        details: "A WebFlux application using functional endpoints may be vulnerable to a header predicate bypass in a pre-flight request.",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        database_specific: { severity: "CRITICAL", cwe_ids: ["CWE-863"] },
        affected: [
          {
            package: { ecosystem: "Maven", name: "org.springframework:spring-webflux" },
            ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "6.2.0" }, { last_affected: "6.2.19" }] }],
          },
          {
            package: { ecosystem: "Maven", name: "org.springframework:spring-webflux" },
            ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "7.0.0" }, { fixed: "7.0.9" }] }],
          },
        ],
      },
    ],
    groups: [{ ids: ["GHSA-9qf2-26p9-2q2q"], aliases: ["CVE-2026-47892", "GHSA-9qf2-26p9-2q2q"], max_severity: "9.8" }],
  };

  it("reads the affected range and the fix on a later line from OSV's ranges", () => {
    const fix = osvFix(spring.vulnerabilities as never, spring.package, "6.2.0");
    expect(fix).toEqual({ fixState: "fixed", fixVersions: ["7.0.9"], affectedRange: ">=6.2.0,<=6.2.19" });
  });

  it("produces one finding per flaw with title, description, score and CWE", () => {
    const byPurl = new Map([[spring.package.purl, [101]]]);
    const parsed = parseOsvReport(JSON.stringify({ results: [{ packages: [spring] }] }), byPurl);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]).toMatchObject({
      componentId: 101,
      vulnerabilityId: "GHSA-9qf2-26p9-2q2q",
      aliases: ["CVE-2026-47892"],
      severity: "critical",
      cvssBaseScore: 9.8,
      cwes: ["CWE-863"],
      summary: "Spring Framework Header Predicate Bypass in WebFlux Functional Endpoints",
      source: "osv",
    });
  });

  it("keeps per-CVE Debian records apart even though a bulletin aliases them all", () => {
    const record = (id: string, cve: string, fixed: string) => ({
      id,
      upstream: [cve],
      affected: [{ package: { ecosystem: "Debian:12", name: "openssl" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }] }],
    });
    const pkg = {
      package: { name: "openssl", version: "3.0.11-1~deb12u1", ecosystem: "Debian:12", purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12" },
      vulnerabilities: [
        record("DEBIAN-CVE-2025-9230", "CVE-2025-9230", "3.0.17-1~deb12u3"),
        record("DEBIAN-CVE-2025-9232", "CVE-2025-9232", "3.0.17-1~deb12u3"),
        { ...record("DSA-6015-1", "CVE-2025-9230", "3.0.17-1~deb12u3"), upstream: ["CVE-2025-9230", "CVE-2025-9232"] },
      ],
      // osv-scanner's own grouping joins all three through the bulletin.
      groups: [{ ids: ["DEBIAN-CVE-2025-9230", "DEBIAN-CVE-2025-9232", "DSA-6015-1"], max_severity: "7.5" }],
    };
    const parsed = parseOsvReport(JSON.stringify({ results: [{ packages: [pkg] }] }), new Map([[pkg.package.purl, [7]]]));
    expect(parsed.findings.map((f) => [f.vulnerabilityId, f.aliases])).toEqual([
      ["DEBIAN-CVE-2025-9230", ["CVE-2025-9230"]],
      ["DEBIAN-CVE-2025-9232", ["CVE-2025-9232"]],
    ]);
  });
});

describe("mergeFindings", () => {
  const grype = finding({
    source: "grype",
    vulnerabilityId: "GHSA-9qf2-26p9-2q2q",
    aliases: ["CVE-2026-47892"],
    severity: "critical",
    fixState: "not-fixed",
    affectedRange: ">=6.2.0,<=6.2.19",
    summary: "Header Predicate Bypass",
    description: "Header Predicate Bypass in WebFlux.",
  });
  const trivy = finding({
    source: "trivy",
    vulnerabilityId: "CVE-2026-47892",
    aliases: ["GHSA-9qf2-26p9-2q2q"],
    severity: "critical",
    fixState: "fixed",
    fixVersions: ["7.0.9"],
    cvssBaseScore: 9.8,
    description: "A WebFlux application using functional endpoints may be vulnerable to a header predicate bypass in a pre-flight request.",
  });
  const osv = finding({ source: "osv", vulnerabilityId: "GHSA-9qf2-26p9-2q2q", aliases: ["CVE-2026-47892"], severity: "critical", fixState: "fixed", fixVersions: ["7.0.9"] });

  it("merges the same flaw from three scanners into one finding that knows the fix", () => {
    const [merged, ...rest] = mergeFindings([trivy, osv, grype]);
    expect(rest).toHaveLength(0);
    expect(merged).toMatchObject({
      vulnerabilityId: "GHSA-9qf2-26p9-2q2q",
      aliases: ["CVE-2026-47892"],
      fixState: "fixed",
      fixVersions: ["7.0.9"],
      foundBy: ["grype", "trivy", "osv"],
      cvssBaseScore: 9.8,
      affectedRange: ">=6.2.0,<=6.2.19",
    });
    expect(merged!.description).toMatch(/^A WebFlux application/);
    expect(merged!.sources!.map((s) => [s.scanner, s.advisoryId, s.fixState])).toEqual([
      ["grype", "GHSA-9qf2-26p9-2q2q", "not-fixed"],
      ["trivy", "CVE-2026-47892", "fixed"],
      ["osv", "GHSA-9qf2-26p9-2q2q", "fixed"],
    ]);
  });

  it("keeps the id the platform already stores, so accepted risks still apply", () => {
    const known = new Map([["CVE-2026-47892", "CVE-2026-47892"]]);
    expect(mergeFindings([trivy, osv], known)[0]!.vulnerabilityId).toBe("CVE-2026-47892");
    expect(mergeFindings([trivy, osv])[0]!.vulnerabilityId).toBe("GHSA-9qf2-26p9-2q2q");
  });

  it("reports the highest severity any scanner gave", () => {
    const merged = mergeFindings([
      { ...grype, severity: "high" },
      { ...trivy, severity: "critical" },
    ]);
    expect(merged[0]!.severity).toBe("critical");
  });

  it("keeps a finding only one scanner reported, attributed to it", () => {
    const merged = mergeFindings([grype, finding({ source: "trivy", vulnerabilityId: "CVE-2099-0001" })]);
    expect(merged.map((f) => [f.vulnerabilityId, f.foundBy])).toEqual([
      ["GHSA-9qf2-26p9-2q2q", ["grype"]],
      ["CVE-2099-0001", ["trivy"]],
    ]);
  });

  it("never merges two advisories from the same scanner, even when they share a CVE", () => {
    const merged = mergeFindings([
      finding({ source: "grype", vulnerabilityId: "GHSA-aaaa", aliases: ["CVE-2024-1"] }),
      finding({ source: "grype", vulnerabilityId: "GHSA-bbbb", aliases: ["CVE-2024-1"] }),
    ]);
    expect(merged).toHaveLength(2);
  });

  it("does not let a multi-CVE advisory chain unrelated findings together", () => {
    const merged = mergeFindings([
      finding({ source: "grype", vulnerabilityId: "CVE-2025-1" }),
      finding({ source: "trivy", vulnerabilityId: "CVE-2025-2" }),
      finding({ source: "osv", vulnerabilityId: "DSA-1", aliases: ["CVE-2025-1", "CVE-2025-2"] }),
    ]);
    expect(merged).toHaveLength(3);
  });

  it("never merges across components", () => {
    expect(mergeFindings([grype, { ...trivy, componentId: 202 }])).toHaveLength(2);
  });
});

describe("CompositeScanner", () => {
  function fake(name: string, builtAt: Date | null, findings: ParsedFinding[] = []): VulnerabilityScanner {
    return {
      name,
      availability: async () => ({ available: true, version: "1", path: name, resolvedBy: "test", supportedDbSchema: null, attempts: [] }),
      dbStatus: async () => ({ present: builtAt !== null, builtAt, schemaVersion: null, valid: builtAt !== null, error: builtAt ? null : "none", path: null }),
      watermark: async () => builtAt,
      listingUrl: async () => name,
      checkReachable: async () => ({ reachable: true, url: name, message: null }),
      updateDb: async () => ({ outcome: "already-current", message: "ok", builtBefore: builtAt, builtAfter: builtAt, schemaVersion: null, sourceUrl: name }),
      importDb: async () => ({ outcome: "failed", message: "no", builtBefore: null, builtAfter: null, schemaVersion: null, sourceUrl: null }),
      match: async (packages) => ({ findings, grypeVersion: null, dbBuiltAt: builtAt, unmappedFindings: 0, submittedComponentIds: packages.map((p) => p.componentId) }),
    };
  }

  function composite(members: () => ScannerMember[]) {
    let stored: { fingerprint: string; at: Date } | null = null;
    const scanner = new CompositeScanner({
      members: async () => members(),
      settings: async () => ({ grype: true, trivy: true, osv: true, xray: false }),
      watermarkStore: { read: async () => stored, write: async (v) => void (stored = v) },
      knownAdvisories: async () => new Map(),
      updateSources: { grype: async () => null, trivy: async () => null, osv: async () => null, xray: async () => null },
      logger: { info: () => undefined, warn: () => undefined } as never,
    });
    return scanner;
  }

  it("moves the watermark only when the scanner set or a database changes", async () => {
    let trivyDb: Date | null = null;
    const scanner = composite(() => [
      { name: "grype", scanner: fake("grype", new Date("2026-11-01T00:00:00Z")) },
      { name: "trivy", scanner: fake("trivy", trivyDb) },
    ]);
    const first = await scanner.watermark();
    scanner.invalidate();
    expect(await scanner.watermark()).toEqual(first);

    // Trivy's database arrives: the usable set changed, so the estate is re-queued.
    await new Promise((r) => setTimeout(r, 5));
    trivyDb = new Date("2026-11-02T00:00:00Z");
    scanner.invalidate();
    const second = await scanner.watermark();
    expect(second!.getTime()).toBeGreaterThan(first!.getTime());
  });

  it("runs only the usable scanners and merges what they found", async () => {
    const scanner = composite(() => [
      { name: "grype", scanner: fake("grype", new Date(), [finding({ source: "grype", vulnerabilityId: "GHSA-x", aliases: ["CVE-1"] })]) },
      { name: "trivy", scanner: fake("trivy", new Date(), [finding({ source: "trivy", vulnerabilityId: "CVE-1" })]) },
      { name: "osv", scanner: fake("osv", null, [finding({ source: "osv", vulnerabilityId: "GHSA-unseen" })]) },
    ]);
    const result = await scanner.match([{ componentId: 101, name: "p", version: "1", purl: "pkg:npm/p@1", ecosystem: "npm" }]);
    expect(result.findings.map((f) => [f.vulnerabilityId, f.foundBy])).toEqual([["GHSA-x", ["grype", "trivy"]]]);
    const availability = await scanner.availability();
    expect(availability.attempts.map((a) => a.strategy)).toEqual(["osv"]);
  });
});
