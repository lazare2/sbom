import { beforeAll, describe, expect, it } from "vitest";
import { getDocument } from "pdfjs-dist/legacy/build/pdf.mjs";
import { INERT_VULN_FILTER, normalizeVulnFilter } from "@sbom/shared";
import type { AnalyticsReport, VulnerabilityReport } from "@sbom/shared";
import { renderReportPdf } from "../../src/modules/reports/pdf.js";

/**
 * Tests for the generated PDF.
 *
 * The layout in `pdf.ts` is hand-computed — pdfkit has no cell model — so the
 * failure modes are geometric: text that overflows its column, content that
 * collides with the footer band, and pages that pdfkit appends on its own. None
 * of those are visible in a byte-size assertion, so these tests read the finished
 * document back through pdf.js and assert on where the text actually landed.
 *
 * Two of the assertions below exist because the bug they describe was real:
 * writing the footer below the bottom margin made pdfkit append one page per
 * footer fragment, and `lineBreak: false` did not stop a platform summary from
 * wrapping onto the next table row.
 */

// Must match the constants in pdf.ts.
const PAGE_WIDTH = 595.28;
const PAGE_HEIGHT = 841.89;
const MARGIN = 44;
/** Height of the reserved footer band, measured from the bottom of the page. */
const FOOTER_BAND = 46;

interface TextItem {
  str: string;
  /** Distance from the left edge. */
  x: number;
  /** Baseline distance from the BOTTOM edge — pdf.js reports PDF-space coords. */
  y: number;
  width: number;
}

interface ExtractedPage {
  items: TextItem[];
  text: string;
}

async function extract(pdf: Buffer): Promise<ExtractedPage[]> {
  const doc = await getDocument({
    data: new Uint8Array(pdf),
    useSystemFonts: false,
    /*
     * Errors only.
     *
     * The report uses the standard-14 fonts and does not embed them — that is
     * the reason for choosing them — so pdf.js looks for its own copies of the
     * metrics and warns once per font per page when it cannot fetch them. It
     * does not need them for what these tests read: the strings and their
     * positions come from the page's content stream. Left at the default
     * verbosity, the warnings bury the actual test output.
     */
    verbosity: 0,
  }).promise;

  const pages: ExtractedPage[] = [];
  for (let p = 1; p <= doc.numPages; p++) {
    const content = await (await doc.getPage(p)).getTextContent();
    const items: TextItem[] = [];
    for (const item of content.items) {
      if (!("str" in item) || item.str.trim() === "") continue;
      items.push({
        str: item.str,
        x: item.transform[4] as number,
        y: item.transform[5] as number,
        width: item.width,
      });
    }
    pages.push({ items, text: items.map((i) => i.str).join(" ") });
  }
  return pages;
}

/**
 * A report with something in every section.
 *
 * Values are chosen to be individually recognisable in the output, so an
 * assertion that finds "8,421" is finding the figure it meant to.
 */
function fullReport(overrides: Partial<AnalyticsReport> = {}): AnalyticsReport {
  return {
    meta: {
      generatedAt: "2026-08-12T09:30:00.000Z",
      generatedBy: "reporter@sbom.local",
      periodDays: 30,
      periodStart: "2026-07-13T09:30:00.000Z",
      staleThresholdDays: 30,
    },
    totals: {
      applications: 412,
      activeApplications: 400,
      inactiveApplications: 9,
      pendingApplications: 3,
      scans: 8421,
      scansInPeriod: 1203,
      distinctPackages: 51234,
      packagesInUse: 22110,
      latestScanAt: "2026-08-12T08:00:00.000Z",
    },
    coverage: {
      eligible: 400,
      covered: 361,
      coveragePct: 90,
      stale: 39,
      neverScanned: 4,
      pendingConfirmation: 3,
      worstOffenders: [
        { applicationId: "a1", name: "legacy-batch-runner", lastScanAt: null, daysSinceScan: null },
        {
          applicationId: "a2",
          name: "reporting-etl",
          lastScanAt: "2025-11-02T00:00:00.000Z",
          daysSinceScan: 283,
        },
      ],
    },
    topPackages: [
      { componentId: "1", name: "libc6", version: "2.36-9+deb12u8", ecosystem: "deb", applications: 350 },
      { componentId: "2", name: "log4j-core", version: "2.24.1", ecosystem: "maven", applications: 120 },
    ],
    topProjects: [
      {
        applicationId: "p1",
        name: "checkout-web",
        packages: 1842,
        scanAt: "2026-08-12T07:00:00.000Z",
        // The exact string that used to wrap onto the next row.
        platform: "Alpine 3.20.3 · nginx 1.27.3 · Node.js 22.11.0",
      },
      {
        applicationId: "p2",
        name: "payments-api",
        packages: 940,
        scanAt: "2026-08-11T07:00:00.000Z",
        platform: null,
      },
    ],
    fragmentation: [
      {
        name: "openssl",
        ecosystem: "deb",
        versions: 5,
        applications: 210,
        examples: ["3.0.11-1", "3.0.14-1~deb12u2", "3.0.15-1~deb12u1"],
      },
    ],
    newPackages: [
      {
        componentId: "9",
        name: "fast-xml-parser",
        version: "4.5.0",
        ecosystem: "npm",
        firstSeenAt: "2026-08-01T00:00:00.000Z",
        applications: 6,
      },
    ],
    velocity: {
      scans: 1203,
      applicationsScanned: 288,
      applicationsCompared: 240,
      applicationsWithoutBaseline: 12,
      applicationsUnchanged: 36,
      packagesAdded: 431,
      packagesRemoved: 208,
      packagesUpgraded: 1675,
    },
    activity: [
      { bucketStart: "2026-07-13T00:00:00.000Z", scans: 12, applications: 9 },
      { bucketStart: "2026-07-14T00:00:00.000Z", scans: 0, applications: 0 },
      { bucketStart: "2026-07-15T00:00:00.000Z", scans: 44, applications: 30 },
    ],
    ecosystems: [
      { ecosystem: "npm", components: 12000, applications: 190 },
      { ecosystem: "deb", components: 4000, applications: 400 },
    ],
    platforms: {
      operatingSystems: [
        { name: "alpine", version: "3.20.3", applications: 210 },
        { name: "debian", version: "12", applications: 150 },
      ],
      runtimes: [
        { name: "node", version: "22.11.0", applications: 180 },
        { name: "java", version: "21.0.5", applications: 90 },
      ],
      unknown: 7,
    },
    /*
     * Null by default: the base fixture represents a platform with scanning off, which
     * is the shipped default and the state most existing assertions are written against.
     * `scannedReport()` below supplies the populated variant.
     */
    vulnerabilities: null,
    ...overrides,
  };
}

/**
 * The same estate with vulnerability scanning enabled.
 *
 * Numbers chosen to mirror the real shape rather than to be tidy: base-image findings
 * dwarf application-dependency findings (720 vs 161 in the demo estate, ~100:1 on a real
 * container image), and the ranking must ignore them. `identity-provider` exists in this
 * fixture specifically to prove that — it has the fewest app findings and by far the most
 * base-image ones, so a ranking that summed the two would put it at the top.
 */
function scannedReport(overrides: Partial<VulnerabilityReport> = {}): AnalyticsReport {
  return fullReport({
    vulnerabilities: {
      dbBuiltAt: "2026-08-12T06:38:08.000Z",
      dbAgeHours: 3.4,
      applicationsScanned: 400,
      applicationsPending: 0,
      filter: INERT_VULN_FILTER,
      app: {
        counts: { critical: 39, high: 128, medium: 240, low: 51, negligible: 5, unknown: 2 },
        fixable: 399,
        knownExploited: 2,
        affectedPackages: 64,
      },
      baseImage: {
        counts: { critical: 210, high: 460, medium: 800, low: 190, negligible: 60, unknown: 9 },
        fixable: 1210,
        knownExploited: 4,
        affectedPackages: 812,
      },
      applicationsAffected: 87,
      unfiltered: null,
      topVulnerableApplications: [
        {
          applicationId: "11111111-1111-4111-8111-111111111111",
          name: "checkout-web",
          status: "active",
          rankedBy: "app",
          findings: 74,
          critical: 8,
          high: 22,
          fixable: 70,
          knownExploited: 1,
          affectedPackages: 19,
          baseImageFindings: 57,
          dbBuiltAt: "2026-08-12T06:38:08.000Z",
        },
        {
          applicationId: "22222222-2222-4222-8222-222222222222",
          name: "identity-provider",
          status: "active",
          rankedBy: "app",
          findings: 12,
          critical: 0,
          high: 3,
          fixable: 11,
          knownExploited: 0,
          affectedPackages: 5,
          baseImageFindings: 903,
          dbBuiltAt: "2026-08-12T06:38:08.000Z",
        },
      ],
      topVulnerablePackages: [
        {
          componentId: 4071,
          name: "log4j-core",
          version: "2.14.1",
          ecosystem: "maven",
          baseImage: false,
          findings: 7,
          critical: 3,
          high: 2,
          knownExploited: 1,
          applications: 4,
          fixAvailable: true,
          fixVersions: ["2.15.0", "2.17.1"],
        },
        {
          componentId: 88,
          name: "no-fix-lib",
          version: "1.0.0",
          ecosystem: "npm",
          baseImage: false,
          findings: 2,
          critical: 0,
          high: 1,
          knownExploited: 0,
          applications: 2,
          fixAvailable: false,
          fixVersions: [],
        },
      ],
      baseImageExposure: [
        { osName: "debian", osVersion: "11", applications: 12, findings: 903, critical: 90, high: 210 },
        { osName: "alpine", osVersion: "3.20.3", applications: 40, findings: 57, critical: 2, high: 9 },
      ],
      ...overrides,
    },
  });
}

/** An estate with nothing in it — every list empty, every count zero. */
function emptyReport(): AnalyticsReport {
  return fullReport({
    totals: {
      applications: 0,
      activeApplications: 0,
      inactiveApplications: 0,
      pendingApplications: 0,
      scans: 0,
      scansInPeriod: 0,
      distinctPackages: 0,
      packagesInUse: 0,
      latestScanAt: null,
    },
    coverage: {
      eligible: 0,
      covered: 0,
      coveragePct: 0,
      stale: 0,
      neverScanned: 0,
      pendingConfirmation: 0,
      worstOffenders: [],
    },
    topPackages: [],
    topProjects: [],
    fragmentation: [],
    newPackages: [],
    velocity: {
      scans: 0,
      applicationsScanned: 0,
      applicationsCompared: 0,
      applicationsWithoutBaseline: 0,
      applicationsUnchanged: 0,
      packagesAdded: 0,
      packagesRemoved: 0,
      packagesUpgraded: 0,
    },
    activity: [],
    ecosystems: [],
    platforms: { operatingSystems: [], runtimes: [], unknown: 0 },
  });
}

describe("renderReportPdf", () => {
  let pdf: Buffer;
  let pages: ExtractedPage[];
  let allText: string;

  beforeAll(async () => {
    pdf = await renderReportPdf(fullReport());
    pages = await extract(pdf);
    allText = pages.map((p) => p.text).join("\n");
  });

  it("produces a structurally valid PDF", () => {
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.subarray(-1024).toString("latin1")).toContain("%%EOF");
    expect(pages.length).toBeGreaterThan(0);
  });

  it("stamps one footer per page, and the page count matches the document", () => {
    // The regression test for the footer bug: writing below the bottom margin
    // made pdfkit append a page per footer fragment, so the document ended up
    // with nine pages whose footers all read "of 3".
    const labels = pages.map((page) => {
      const found = page.items.filter((i) => /^Page \d+ of \d+$/.test(i.str));
      expect(found).toHaveLength(1);
      return found[0]!.str;
    });

    expect(labels).toEqual(pages.map((_p, i) => `Page ${i + 1} of ${pages.length}`));
  });

  it("keeps content out of the footer band", () => {
    // Anything this low on the page either is the footer or is colliding with it.
    for (const [index, page] of pages.entries()) {
      const low = page.items.filter((i) => i.y < FOOTER_BAND);
      for (const item of low) {
        const isFooter =
          /^Page \d+ of \d+$/.test(item.str) || item.str.startsWith("SBOM estate report");
        expect(isFooter, `page ${index + 1} has content in the footer band: "${item.str}"`).toBe(true);
      }
    }
  });

  it("keeps every line inside the page margins", () => {
    // Catches a column-width set that sums past 1.0, which would silently push
    // the last column off the right edge.
    for (const [index, page] of pages.entries()) {
      for (const item of page.items) {
        expect(item.x, `page ${index + 1}: "${item.str}" starts left of the margin`).toBeGreaterThanOrEqual(
          MARGIN - 1,
        );
        expect(
          item.x + item.width,
          `page ${index + 1}: "${item.str}" runs past the right margin`,
        ).toBeLessThanOrEqual(PAGE_WIDTH - MARGIN + 2);
      }
    }
  });

  it("renders a long platform summary on one line", () => {
    // The regression test for the wrap bug: pdfkit broke this string at its
    // middot separators despite `lineBreak: false`, and the overflow landed on
    // top of the row beneath.
    const platform = "Alpine 3.20.3 · nginx 1.27.3 · Node.js 22.11.0";
    const match = pages.flatMap((p) => p.items).find((i) => i.str === platform);
    expect(match, "the full platform summary should appear as a single text run").toBeDefined();

    // And nothing should share its baseline from a wrapped continuation: the row
    // below sits 15pt lower, so a fragment 8pt below would be an overflow line.
    const page = pages.find((p) => p.items.some((i) => i.str === platform))!;
    const strays = page.items.filter((i) => i.y > match!.y - 12 && i.y < match!.y - 3);
    expect(strays.map((s) => s.str)).toEqual([]);
  });

  it("says nothing was assessed, rather than omitting the section or showing zeros", () => {
    /*
     * The fixture has `vulnerabilities: null` — scanning disabled.
     *
     * The single most damaging thing this report could do is let a reader conclude an
     * unscanned estate is clean. Silence would do it, and so would a section full of
     * zeros, so the renderer has to state it outright. Both halves are asserted: that
     * the section exists, and that it disclaims itself.
     */
    expect(allText).toContain("Vulnerability findings");
    expect(allText).toContain("Not assessed");
    expect(allText).toContain("not a clean result");
    expect(allText).toContain("nothing was checked");
    // And the methodology note must agree with the section rather than contradict it.
    expect(allText).toContain("Vulnerability scanning is disabled on this platform");
  });

  it("prints provenance on the first page", () => {
    expect(pages[0]!.text).toContain("SBOM estate report");
    expect(pages[0]!.text).toContain("reporter@sbom.local");
    expect(pages[0]!.text).toContain("30-day window");
    expect(pages[0]!.text).toContain("12 Aug 2026");
  });

  it("qualifies the totals with the coverage gap on the first page", () => {
    expect(pages[0]!.text).toContain("Figures below describe only what has been scanned");
    expect(pages[0]!.text).toContain("39 active applications have not reported a build");
    // Grammar agreement, which a template with a hardcoded verb gets wrong.
    expect(pages[0]!.text).toContain("4 have never reported one");
  });

  it("renders every section heading", () => {
    for (const heading of [
      "Coverage gaps",
      "Top 2 most widely deployed packages",
      "Top 2 applications by package count",
      "Version fragmentation",
      "Dependency churn, last 30 days",
      "Packages new to the estate, last 30 days",
      "Platform inventory",
      "Ecosystem mix",
      "How to read this report",
    ]) {
      expect(allText, `missing section: ${heading}`).toContain(heading);
    }
  });

  it("renders the figures, formatted with thousands separators", () => {
    expect(allText).toContain("8,421");
    expect(allText).toContain("1,842");
    expect(allText).toContain("1,675");
    expect(allText).toContain("90%");
  });

  it("labels OS and runtime names rather than printing raw identifiers", () => {
    expect(allText).toContain("Alpine");
    expect(allText).toContain("Node.js");
    expect(allText).not.toContain("operating-system");
  });

  it("names never-scanned applications instead of showing a blank date", () => {
    expect(allText).toContain("legacy-batch-runner");
    expect(allText).toContain("never scanned");
  });
});

describe("renderReportPdf with vulnerability scanning enabled", () => {
  let allText: string;

  beforeAll(async () => {
    const pages = await extract(await renderReportPdf(scannedReport()));
    allText = pages.map((p) => p.text).join("\n");
  });

  it("prints both rankings and the base-image section", () => {
    expect(allText).toContain("vulnerable applications");
    expect(allText).toContain("vulnerable packages in use");
    expect(allText).toContain("Base image exposure");
    expect(allText).toContain("checkout-web");
    expect(allText).toContain("log4j-core");
  });

  it("names the database build so a stale figure is explainable", () => {
    // A report that circulates for weeks has to carry the date of the data behind it,
    // not just the date it was printed.
    expect(allText).toContain("12 Aug 2026");
    expect(allText).toContain("Grype database built");
  });

  it("drops the 'no vulnerability data' disclaimer it prints when disabled", () => {
    // The disclaimer is correct when scanning is off and a falsehood when it is on.
    // A methodology note that contradicts the tables above it discredits both.
    expect(allText).not.toContain("Not assessed");
    expect(allText).not.toContain("Vulnerability scanning is disabled on this platform");
    expect(allText).toContain("Findings come from Grype matching");
  });

  it("ranks applications on their own dependencies, not on base-image age", () => {
    /*
     * The property the whole app/base-image split exists to protect, asserted on
     * rendered output rather than on the query that produced it.
     *
     * `identity-provider` carries 903 base-image findings against `checkout-web`'s 57,
     * but only 12 application-dependency findings against 74. Summed, it would rank
     * first; ranked correctly it comes second. The fixture is built so that a regression
     * to a combined count flips this order and fails here.
     */
    const first = allText.indexOf("checkout-web");
    const second = allText.indexOf("identity-provider");
    expect(first).toBeGreaterThan(-1);
    expect(second).toBeGreaterThan(-1);
    expect(first).toBeLessThan(second);
  });

  it("prints the combined total and the split that explains it", () => {
    /*
     * 465 app + 1,729 base image = 2,194. All three are required.
     *
     * The combined figure is the one that gets quoted, and on this fixture — as on a real
     * container estate — it is roughly four fifths base image. Printing it without both
     * halves beside it would make the quotable number the misleading one; printing only
     * the halves leaves the reader to add them up themselves and get no warning that the
     * sum is dominated by base-image age.
     */
    expect(allText).toContain("465");
    expect(allText).toContain("1,729");
    expect(allText).toContain("2,194");
  });

  it("breaks both halves down by severity, and the five buckets sum to the half", () => {
    /*
     * Headers are rendered uppercase and abbreviated. The abbreviation is not cosmetic:
     * nine columns leave about 40pt each, and a full-length `MEDIUM` was silently clipped
     * by `truncate()` — so this asserts the short form that actually fits.
     */
    for (const header of ["SCOPE", "TOTAL", "CRIT", "HIGH", "MED", "LOW", "OTHER"]) {
      expect(allText).toContain(header);
    }
    expect(allText).toContain("Application dependencies");
    expect(allText).toContain("Base image and runtimes");
    /*
     * app: 39 + 128 + 240 + 51 + (5 negligible + 2 unrated) = 465, which the previous
     * assertion already pins. What matters here is that the fold is explained — a reader
     * who assumes "Other" means "not yet rated" will treat it as a queue of work that
     * does not exist.
     */
    expect(allText).toContain("Other combines negligible and unrated advisories");
  });

  it("ranks on one half, so the combined total never sets the order", () => {
    /*
     * `identity-provider` has 12 application findings and 903 base-image ones;
     * `checkout-web` has 74 and 57. Ranked on the combined figure identity-provider would
     * come first. This is the property the merged "app / base image" column makes it
     * easiest to get wrong, since the two numbers now sit side by side.
     */
    const appIndex = allText.indexOf("checkout-web");
    const osIndex = allText.indexOf("identity-provider");
    expect(appIndex).toBeGreaterThanOrEqual(0);
    expect(osIndex).toBeGreaterThan(appIndex);
  });

  it("states the filter on the cover and prints unfiltered totals alongside", async () => {
    const filtered = scannedReport({
      filter: normalizeVulnFilter({ scope: "app", severity: ["critical", "high"] }),
      app: {
        counts: { critical: 39, high: 128, medium: 0, low: 0, negligible: 0, unknown: 0 },
        fixable: 150,
        knownExploited: 2,
        affectedPackages: 31,
      },
      // Excluded by `scope: app`. Null, not zeroed — the report has to be able to say
      // "not counted" rather than implying a clean base image.
      baseImage: null,
      baseImageExposure: null,
      unfiltered: {
        app: { critical: 39, high: 128, medium: 240, low: 51, negligible: 5, unknown: 2 },
        baseImage: { critical: 210, high: 460, medium: 800, low: 190, negligible: 60, unknown: 9 },
      },
    });
    const pages = await extract(await renderReportPdf(filtered));
    const text = pages.map((p) => p.text).join("\n");

    // On the cover, because that is the page that survives being forwarded.
    expect(pages[0]!.text).toContain("Vulnerability figures filtered");
    expect(pages[0]!.text).toContain("Application dependencies · Critical, High");
    // And beside the figures themselves.
    expect(text).toContain("Filtered:");
    // The reference point, so the reader can see the size of what was excluded.
    expect(text).toContain("unfiltered totals");
    expect(text).toContain("1,729");
    // An excluded half is stated, never rendered as zero findings.
    expect(text).toContain("Base image exposure");
    expect(text).toContain("Not included");
    // The unfiltered inventory sections must not be described as filtered.
    expect(pages[0]!.text).toContain("Inventory, coverage and churn figures are unfiltered");
  });

  it("prints no filter statement and no reference block when nothing is narrowed", () => {
    // The inert case must stay clean: a "Filtered:" line on an unfiltered report would
    // make every reader wonder what they are not seeing.
    expect(allText).not.toContain("Filtered:");
    expect(allText).not.toContain("unfiltered totals");
  });

  it("distinguishes a package with no fix from one with a fix available", () => {
    // "no fix" is a different kind of work from "upgrade to 2.15.0", and a reader
    // scanning the column needs to see which is which.
    expect(allText).toContain("2.15.0");
    expect(allText).toContain("no fix");
  });

  it("says the counts are a lower bound when applications are still pending", async () => {
    const pages = await extract(await renderReportPdf(scannedReport({ applicationsPending: 37 })));
    const text = pages.map((p) => p.text).join("\n");
    // Otherwise two reports taken during a catch-up sweep look like a real improvement.
    expect(text).toContain("37 applications have not been matched yet");
    expect(text).toContain("lower bound");
  });

  it("states plainly when an assessed estate has no findings at all", async () => {
    const noCounts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 };
    const clean = scannedReport({
      app: { counts: noCounts, fixable: 0, knownExploited: 0, affectedPackages: 0 },
      baseImage: { counts: noCounts, fixable: 0, knownExploited: 0, affectedPackages: 0 },
      applicationsAffected: 0,
      topVulnerableApplications: [],
      topVulnerablePackages: [],
      baseImageExposure: [],
    });
    const pages = await extract(await renderReportPdf(clean));
    const text = pages.map((p) => p.text).join("\n");
    // A genuine clean result reads differently from an unassessed one — this is the
    // other side of the disabled-state test, and the pair is what makes either honest.
    expect(text).toContain("No application dependency has a known vulnerability");
    expect(text).not.toContain("Not assessed");
  });
});

describe("renderReportPdf edge cases", () => {
  it("renders an empty estate without claiming full coverage", async () => {
    const pages = await extract(await renderReportPdf(emptyReport()));
    const text = pages.map((p) => p.text).join("\n");

    // 0%, not 100%: "fully covered" with nothing registered would be the most
    // misleading number the report could print.
    expect(text).toContain("0%");
    expect(text).not.toContain("describe the whole estate");
    expect(text).toContain("No active application is stale or unscanned");
    expect(text).toContain("No package data yet");
  });

  it("suppresses the churn figures when there is nothing to compare against", async () => {
    // All-zero churn tiles would read as "nothing changed", which is the opposite
    // of "nothing was measured".
    const report = fullReport({
      velocity: {
        scans: 40,
        applicationsScanned: 8,
        applicationsCompared: 0,
        applicationsWithoutBaseline: 8,
        applicationsUnchanged: 0,
        packagesAdded: 0,
        packagesRemoved: 0,
        packagesUpgraded: 0,
      },
    });
    const text = (await extract(await renderReportPdf(report))).map((p) => p.text).join("\n");

    expect(text).toContain("nothing to compare against");
    expect(text).not.toContain("PACKAGES UPGRADED");
  });

  it("accounts for the applications that did not build inside the window", async () => {
    // These three buckets have to add up to every scanned application, or a
    // reader reconciling them against the application total finds a gap. The
    // count comes from the service, not from subtracting the other two off a
    // total computed with a different status filter — which is what it used to
    // do, across two different populations.
    const text = (await extract(await renderReportPdf(fullReport()))).map((p) => p.text).join("\n");
    expect(text).toContain("240 applications had builds on both sides");
    expect(text).toContain("12 applications were scanned for the first time");
    expect(text).toContain("A further 36 applications have not built inside the window");
  });

  it("omits the unchanged-applications note when there are none", async () => {
    const report = fullReport({
      velocity: { ...fullReport().velocity, applicationsUnchanged: 0 },
    });
    const text = (await extract(await renderReportPdf(report))).map((p) => p.text).join("\n");
    expect(text).not.toContain("A further");
  });

  it("reports full coverage differently from partial coverage", async () => {
    const report = fullReport({
      coverage: {
        eligible: 400,
        covered: 400,
        coveragePct: 100,
        stale: 0,
        neverScanned: 0,
        pendingConfirmation: 0,
        worstOffenders: [],
      },
    });
    const text = (await extract(await renderReportPdf(report))).map((p) => p.text).join("\n");
    expect(text).toContain("describe the whole estate");
  });

  it("truncates an over-long name instead of overflowing its column", async () => {
    const report = fullReport({
      topProjects: [
        {
          applicationId: "p1",
          name: "a".repeat(200),
          packages: 10,
          scanAt: "2026-08-12T07:00:00.000Z",
          platform: "b".repeat(200),
        },
      ],
    });
    const pages = await extract(await renderReportPdf(report));

    // The margin assertion is the real check; the ellipsis confirms it was cut
    // rather than merely happening to fit.
    for (const page of pages) {
      for (const item of page.items) {
        expect(item.x + item.width).toBeLessThanOrEqual(PAGE_WIDTH - MARGIN + 2);
      }
    }
    expect(pages.map((p) => p.text).join("\n")).toContain("…");
  });

  it("paginates a long report and keeps the footers consistent", async () => {
    // 53 weekly buckets and 50 rows per table: several page breaks, including
    // ones that land mid-table.
    const many = (n: number) => Array.from({ length: n }, (_v, i) => i);
    const report = fullReport({
      meta: { ...fullReport().meta, periodDays: 365 },
      topPackages: many(50).map((i) => ({
        componentId: String(i),
        name: `package-${i}`,
        version: `1.${i}.0`,
        ecosystem: "npm",
        applications: 50 - i,
      })),
      fragmentation: many(40).map((i) => ({
        name: `frag-${i}`,
        ecosystem: "npm",
        versions: 2 + (i % 5),
        applications: 40 - i,
        examples: ["1.0.0", "2.0.0"],
      })),
      newPackages: many(40).map((i) => ({
        componentId: String(1000 + i),
        name: `new-${i}`,
        version: "1.0.0",
        ecosystem: "pypi",
        firstSeenAt: "2026-08-01T00:00:00.000Z",
        applications: 1,
      })),
      activity: many(53).map((i) => ({
        bucketStart: new Date(Date.UTC(2025, 7, 1) + i * 7 * 86_400_000).toISOString(),
        scans: i % 7,
        applications: i % 3,
      })),
    });

    const pages = await extract(await renderReportPdf(report));
    expect(pages.length).toBeGreaterThan(3);

    for (const [index, page] of pages.entries()) {
      const labels = page.items.filter((i) => /^Page \d+ of \d+$/.test(i.str));
      expect(labels.map((l) => l.str)).toEqual([`Page ${index + 1} of ${pages.length}`]);
    }

    // A table broken across a page must reprint its header, or the columns on the
    // later page are unlabelled.
    const headerPages = pages.filter((p) => p.text.includes("PACKAGE") && p.text.includes("APPS"));
    expect(headerPages.length).toBeGreaterThan(1);
  });
});
