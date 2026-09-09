import { describe, expect, it, vi } from "vitest";
import type { FastifyBaseLogger } from "fastify";
import { XrayScanner } from "../../src/services/scanner/xray.js";
import type { XrayClient, XrayScanResult } from "../../src/services/scanner/xray-client.js";
import type { ScannablePackage } from "../../src/services/scanner/grype-output.js";

/**
 * The Xray scanner as the sweep sees it.
 *
 * One property here matters more than everything else in the file: `submittedComponentIds`
 * is what the sweep stamps as assessed, and a package that could not be turned into an Xray
 * coordinate must not appear in it.
 *
 * Get that wrong and the platform records "we asked Xray about this package and it had
 * nothing" for a package that was never sent. There is no error, no empty state and no way
 * for a reader to tell — the component simply joins the clean ones. On a container image the
 * packages most likely to be unmappable are the operating-system ones, which is most of the
 * image.
 */

const logger = {
  debug: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
} as unknown as FastifyBaseLogger;

function scannerWith(result: XrayScanResult, spy?: (coords: readonly string[]) => void) {
  const client = {
    version: async () => "3.118.24",
    scanGraph: async (coordinates: readonly string[]) => {
      spy?.(coordinates);
      return result;
    },
  } as unknown as XrayClient;

  return new XrayScanner(
    { baseUrl: "https://xray.example.org", username: "u", token: "t", allowSelfSigned: false },
    { logger, client },
  );
}

function pkg(over: Partial<ScannablePackage> & { componentId: number }): ScannablePackage {
  return {
    name: "lodash",
    version: "4.17.15",
    purl: "pkg:npm/lodash@4.17.15",
    ecosystem: "npm",
    ...over,
  };
}

const EMPTY: XrayScanResult = { status: "completed", vulnerabilities: [] };

describe("matching a batch against Xray", () => {
  it("marks only the packages it actually submitted as assessed", async () => {
    /*
      The regression this whole file exists for. Four packages, two of which cannot be
      expressed: `generic` has no Xray identifier at all, and a deb package with no
      architecture cannot be identified correctly. Both must be left out of the submitted
      list so the sweep leaves them unassessed.
    */
    const scanner = scannerWith(EMPTY);
    const result = await scanner.match([
      pkg({ componentId: 1 }),
      pkg({ componentId: 2, ecosystem: "generic", purl: "pkg:generic/busybox@1.36.1", name: "busybox" }),
      pkg({
        componentId: 3,
        ecosystem: "deb",
        name: "openssl",
        version: "1.1.1n",
        purl: "pkg:deb/debian/openssl@1.1.1n",
      }),
      pkg({
        componentId: 4,
        ecosystem: "deb",
        name: "openssl",
        version: "1.1.1n",
        purl: "pkg:deb/debian/openssl@1.1.1n?arch=amd64",
      }),
    ]);

    expect(result.submittedComponentIds.sort()).toEqual([1, 4]);
  });

  it("sends each distinct coordinate once, however many components share it", async () => {
    // The platform deduplicates components by identity hash, but two identity hashes can
    // still produce one Xray coordinate. Submitting it twice would ask a shared corporate
    // server the same question twice for no reason.
    let sent: readonly string[] = [];
    const scanner = scannerWith(EMPTY, (coords) => {
      sent = coords;
    });

    await scanner.match([
      pkg({ componentId: 1 }),
      pkg({ componentId: 2, purl: "pkg:npm/lodash@4.17.15?foo=bar" }),
    ]);

    expect(sent).toEqual(["npm://lodash:4.17.15"]);
  });

  it("returns a finding to every component behind a shared coordinate", async () => {
    // The other half of deduplication: one answer has to reach both components, or the
    // second reads as clean.
    const scanner = scannerWith({
      status: "completed",
      vulnerabilities: [
        {
          issue_id: "XRAY-1",
          severity: "High",
          cves: [{ cve: "CVE-2020-8203" }],
          components: { "npm://lodash:4.17.15": { fixed_versions: ["4.17.19"] } },
        },
      ],
    });

    const result = await scanner.match([
      pkg({ componentId: 1 }),
      pkg({ componentId: 2, purl: "pkg:npm/lodash@4.17.15?foo=bar" }),
    ]);

    expect(result.findings.map((f) => f.componentId).sort()).toEqual([1, 2]);
    expect(result.findings[0]!.vulnerabilityId).toBe("CVE-2020-8203");
  });

  it("does not call Xray at all when nothing in the batch can be mapped", async () => {
    // A batch of OS packages on a deployment that cannot express them should cost no
    // request, and must still report nothing as assessed.
    const scanGraph = vi.fn(async () => EMPTY);
    const scanner = new XrayScanner(
      { baseUrl: "https://xray.example.org", username: "u", token: "t", allowSelfSigned: false },
      { logger, client: { version: async () => "3", scanGraph } as unknown as XrayClient },
    );

    const result = await scanner.match([
      pkg({ componentId: 1, ecosystem: "generic", purl: "pkg:generic/a@1" }),
    ]);

    expect(scanGraph).not.toHaveBeenCalled();
    expect(result.submittedComponentIds).toEqual([]);
    expect(result.findings).toEqual([]);
  });
});

describe("what the scanner reports about the database", () => {
  it("never invents a database build date", async () => {
    /*
      Xray publishes no build timestamp. Using the time of the last successful call would put
      a date on the admin screen that reads as a database age and is not one — and under
      Grype that same figure decides whether the estate needs re-scanning.
    */
    const status = await scannerWith(EMPTY).dbStatus();
    expect(status.builtAt).toBeNull();
    expect(status.present).toBe(true);
  });

  it("refuses a database update instead of quietly reporting success", async () => {
    // `already-current` would be the comfortable answer and a claim about a database this
    // platform cannot see. It would also appear in the update history as a completed check.
    const result = await scannerWith(EMPTY).updateDb();
    expect(result.outcome).toBe("failed");
    expect(result.message).toMatch(/managed on the Xray server/i);
  });
});

describe("probing what this Xray actually covers", () => {
  it("reports an ecosystem whose canary returned findings as covered", async () => {
    const scanner = scannerWith({
      status: "completed",
      vulnerabilities: [
        {
          issue_id: "XRAY-192503",
          cves: [{ cve: "CVE-2021-44228" }],
          severity: "Critical",
          components: { "gav://org.apache.logging.log4j:log4j-core:2.14.1": {} },
        },
      ],
    });

    const coverage = await scanner.probeCoverage();
    expect(coverage.covered).toContain("maven");
    // Everything else went unanswered, so it is uncovered — not clean.
    expect(coverage.uncovered).toContain("npm");
    expect(coverage.uncovered).toContain("deb");
  });

  it("reports every ecosystem as uncovered when the database answers nothing", async () => {
    /*
      The silent-failure case the original manual investigation was designed to rule out: an
      Xray that is reachable, authenticates, and returns a clean result for everything
      because its database never synchronised. Without this the platform would report an
      entire estate as vulnerability-free.
    */
    const coverage = await scannerWith(EMPTY).probeCoverage();
    expect(coverage.covered).toEqual([]);
    expect(coverage.uncovered.length).toBeGreaterThan(5);
  });
});
