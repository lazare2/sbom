import { beforeAll, describe, expect, it } from "vitest";
import { getDocument } from "pdfjs-dist/legacy/build/pdf.mjs";
import { DEFAULT_ATTENTION_SETTINGS, EMPTY_TEAM_FILTER } from "@sbom/shared";
import type { AnalyticsReport, BuildDeltaPair, ProjectProgress } from "@sbom/shared";
import { renderReportPdf } from "../../src/modules/reports/pdf.js";

/**
 * Tests for the generated PDF.
 *
 * The layout in `pdf.ts` is hand-computed - pdfkit has no cell model - so the failure modes are
 * geometric: text that overflows its column, content that collides with the footer band, and
 * pages that pdfkit appends on its own. None of those are visible in a byte-size assertion, so
 * these tests read the finished document back through pdf.js and assert on where the text
 * actually landed.
 *
 * One of the assertions exists because the bug it describes was real: writing the footer below
 * the bottom margin made pdfkit append one page per footer fragment.
 */

// Must match the constants in pdf-layout.ts.
const PAGE_WIDTH = 595.28;
const MARGIN = 44;
/** Height of the reserved footer band, measured from the bottom of the page. */
const FOOTER_BAND = 46;

interface TextItem {
  str: string;
  x: number;
  /** Baseline distance from the BOTTOM edge - pdf.js reports PDF-space coords. */
  y: number;
  width: number;
}

interface ExtractedPage {
  items: TextItem[];
  text: string;
}

async function extract(pdf: Buffer): Promise<ExtractedPage[]> {
  // Errors only: the standard-14 fonts are not embedded, and pdf.js warns per font per page.
  const doc = await getDocument({ data: new Uint8Array(pdf), useSystemFonts: false, verbosity: 0 }).promise;
  const pages: ExtractedPage[] = [];
  for (let p = 1; p <= doc.numPages; p++) {
    const content = await (await doc.getPage(p)).getTextContent();
    const items: TextItem[] = [];
    for (const item of content.items) {
      if (!("str" in item) || item.str.trim() === "") continue;
      items.push({ str: item.str, x: item.transform[4] as number, y: item.transform[5] as number, width: item.width });
    }
    pages.push({ items, text: items.map((i) => i.str).join(" ") });
  }
  return pages;
}

const textOf = (pages: ExtractedPage[]) => pages.map((p) => p.text).join("\n");

function delta(over: (d: BuildDeltaPair) => void): BuildDeltaPair {
  const counts = () => ({ total: 0, critical: 0, high: 0 });
  const side = () => ({ fixed: counts(), introduced: counts(), unchanged: counts() });
  const d = { app: side(), os: side() };
  over(d);
  return d;
}

function project(name: string, over: Partial<ProjectProgress> = {}): ProjectProgress {
  return {
    applicationId: name,
    name,
    status: "active",
    squads: ["Payments"],
    tribes: ["Money"],
    builds: { inWindow: 6, lastBuildAt: "2026-11-01T00:00:00.000Z", daysSinceLastBuild: 10, cadenceBuilds: 9, averageDaysBetweenBuilds: 4.5 },
    vulnerabilities: {
      comparedBuilds: 5,
      fixed: 7421,
      introduced: 12,
      net: -7409,
      fixedCriticalHigh: 4,
      introducedCriticalHigh: 1,
      openCritical: 3,
      openHigh: 9,
      criticalHighAtStart: 20,
      criticalHighChange: -8,
      meanDaysToFix: 17.5,
      fixesTimed: 4,
    },
    ...over,
  };
}

/** A report with something in every section; figures are individually recognisable. */
function fullReport(overrides: Partial<AnalyticsReport> = {}): AnalyticsReport {
  const projects = [project("payments-api"), project("ledger-service", { squads: [] })];
  return {
    meta: {
      generatedAt: "2026-11-11T10:00:00.000Z",
      generatedBy: "lead@example.com",
      periodDays: 30,
      periodStart: "2026-10-12T10:00:00.000Z",
      staleThresholdDays: 30,
      environmentName: "Production",
      filter: EMPTY_TEAM_FILTER,
      filterLabel: null,
      vulnScanningEnabled: true,
      attentionSettings: DEFAULT_ATTENTION_SETTINGS,
    },
    totals: {
      applications: 412,
      activeApplications: 400,
      inactiveApplications: 12,
      pendingApplications: 3,
      scans: 8421,
      scansInPeriod: 977,
      distinctPackages: 50000,
      packagesInUse: 31000,
      latestScanAt: "2026-11-10T00:00:00.000Z",
    },
    coverage: {
      eligible: 400,
      covered: 352,
      coveragePct: 88,
      stale: 36,
      neverScanned: 12,
      pendingConfirmation: 3,
      worstOffenders: [{ applicationId: "x", name: "forgotten-service", lastScanAt: null, daysSinceScan: null }],
    },
    progress: {
      projects,
      squads: [
        {
          name: "Payments",
          applications: 1,
          buildsInWindow: 6,
          averageDaysBetweenBuilds: 4.5,
          flaggedApplications: 1,
          vulnerabilities: {
            comparedBuilds: 5,
            fixed: 7421,
            introduced: 12,
            net: -7409,
            openCritical: 3,
            openHigh: 9,
            criticalHighChange: -8,
            meanDaysToFix: 17.5,
          },
        },
        {
          name: null,
          applications: 1,
          buildsInWindow: 6,
          averageDaysBetweenBuilds: 4.5,
          flaggedApplications: 0,
          vulnerabilities: null,
        },
      ],
      tribes: [],
    },
    attention: {
      projects: [
        {
          applicationId: "payments-api",
          name: "payments-api",
          squads: ["Payments"],
          tribes: [],
          flags: [
            { kind: "known_exploited", reason: "1 known-exploited advisory open in the current build (CVE-2026-0001)." },
            {
              kind: "build_overdue",
              reason:
                "Usually built every 4.5 days (9 builds in the last 90 days); flagged after 1.5x that, 7 days. Last build 10 days ago.",
            },
          ],
        },
      ],
      packages: [
        {
          name: "jackson-databind",
          ecosystem: "maven",
          applications: 14,
          applicationList: [],
          critical: 8,
          knownExploited: 1,
          versionsInUse: 3,
          fixVersions: ["2.17.3", "2.18.1"],
          reason: "",
        },
      ],
      fragmentationRising: [{ name: "lodash", ecosystem: "npm", versionsAtStart: 2, versionsNow: 5, applications: 9 }],
    },
    buildDeltas: {
      projects: [
        {
          applicationId: "payments-api",
          name: "payments-api",
          comparedBuilds: 5,
          average: delta((d) => {
            d.app.fixed = { total: 2.4, critical: 0.2, high: 0.6 };
            d.os.unchanged = { total: 312.5, critical: 4, high: 20 };
          }),
          last: {
            ...delta((d) => {
              d.app.introduced = { total: 3, critical: 1, high: 1 };
            }),
            scanId: "s1",
            buildNumber: "88",
            at: "2026-11-01T00:00:00.000Z",
          },
        },
      ],
      estateAverage: delta((d) => {
        d.app.fixed = { total: 2.4, critical: 0.2, high: 0.6 };
      }),
      comparedBuilds: 5,
      identicalRebuildsSkipped: 3,
    },
    newPackages: [
      { componentId: "1", name: "left-pad", version: "1.3.0", ecosystem: "npm", firstSeenAt: "2026-10-20T00:00:00.000Z", applications: 2 },
    ],
    velocity: {
      scans: 977,
      applicationsScanned: 288,
      applicationsCompared: 240,
      applicationsWithoutBaseline: 12,
      applicationsUnchanged: 36,
      packagesAdded: 120,
      packagesRemoved: 80,
      packagesUpgraded: 600,
    },
    activity: [
      { bucketStart: "2026-10-12T00:00:00.000Z", scans: 30, applications: 10 },
      { bucketStart: "2026-10-13T00:00:00.000Z", scans: 45, applications: 12 },
    ],
    ...overrides,
  };
}

describe("renderReportPdf", () => {
  let pdf: Buffer;
  let pages: ExtractedPage[];
  let allText: string;

  beforeAll(async () => {
    pdf = await renderReportPdf(fullReport());
    pages = await extract(pdf);
    allText = textOf(pages);
  });

  it("produces a structurally valid PDF", () => {
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.subarray(-1024).toString("latin1")).toContain("%%EOF");
    expect(pages.length).toBeGreaterThan(0);
  });

  it("stamps one footer per page, and the page count matches the document", () => {
    const labels = pages.map((page) => {
      const found = page.items.filter((i) => /^Page \d+ of \d+$/.test(i.str));
      expect(found).toHaveLength(1);
      return found[0]!.str;
    });
    expect(labels).toEqual(pages.map((_p, i) => `Page ${i + 1} of ${pages.length}`));
  });

  it("keeps content out of the footer band", () => {
    for (const [index, page] of pages.entries()) {
      for (const item of page.items.filter((i) => i.y < FOOTER_BAND)) {
        const isFooter = /^Page \d+ of \d+$/.test(item.str) || item.str.startsWith("SBOM analytics report");
        expect(isFooter, `page ${index + 1} has content in the footer band: "${item.str}"`).toBe(true);
      }
    }
  });

  it("keeps every line inside the page margins", () => {
    for (const [index, page] of pages.entries()) {
      for (const item of page.items) {
        expect(item.x, `page ${index + 1}: "${item.str}" starts left of the margin`).toBeGreaterThanOrEqual(MARGIN - 1);
        expect(item.x + item.width, `page ${index + 1}: "${item.str}" runs past the right margin`).toBeLessThanOrEqual(
          PAGE_WIDTH - MARGIN + 2,
        );
      }
    }
  });

  it("prints provenance and the environment on the first page", () => {
    expect(pages[0]!.text).toContain("Analytics: Production");
    expect(pages[0]!.text).toContain("lead@example.com");
    expect(pages[0]!.text).toContain("30-day window");
  });

  it("puts the window's movement on the cover", () => {
    expect(pages[0]!.text).toContain("FINDINGS FIXED");
    expect(pages[0]!.text).toContain("14,842"); // 7,421 fixed in each of two projects
    expect(pages[0]!.text).toContain("-14,818");
    expect(pages[0]!.text).toContain("today's vulnerability database");
  });

  it("states every flag with its reason", () => {
    expect(allText).toContain("Projects that need attention");
    expect(allText).toContain("CVE-2026-0001");
    expect(allText).toContain("Usually built every 4.5 days");
  });

  it("renders every section heading", () => {
    for (const heading of [
      "Progress by project",
      "Progress by squad",
      "Build to build: application dependencies",
      "Build to build: base image",
      "Packages to upgrade first",
      "Fragmentation getting worse",
      "Coverage gaps",
      "Dependency churn",
      "How to read this report",
    ]) {
      expect(allText, heading).toContain(heading);
    }
  });

  it("prints build-to-build movement as fixed / new / unchanged, with critical and high apart", () => {
    expect(allText).toContain("2.4 / 0 / 0"); // average, all severities, app half
    expect(allText).toContain("0.8 / 0 / 0"); // average, critical + high
    expect(allText).toContain("0 / 0 / 312.5"); // base-image half
    expect(allText).toContain("(3 in this window)"); // identical rebuilds skipped
  });

  it("explains the thresholds the flags were decided with", () => {
    expect(allText).toContain("1.5 times its own average gap");
    expect(allText).toContain("fixed 30-day limit");
  });

  it("omits a squad table whose only row is the unassigned one", () => {
    expect(allText).not.toContain("Progress by tribe");
    expect(allText).toContain("(no squad)");
  });
});

describe("renderReportPdf edge cases", () => {
  it("shows build activity only, with no finding figures, when scanning is off", async () => {
    const report = fullReport({
      meta: { ...fullReport().meta, vulnScanningEnabled: false },
      buildDeltas: null,
      progress: {
        projects: [project("payments-api", { vulnerabilities: null })],
        squads: [],
        tribes: [],
      },
      attention: { projects: [], packages: [], fragmentationRising: [] },
    });
    const text = textOf(await extract(await renderReportPdf(report)));
    expect(text).not.toContain("FINDINGS FIXED");
    expect(text).not.toContain("Build to build");
    expect(text).not.toContain("Packages to upgrade first");
    expect(text).toContain("Vulnerability scanning is switched off");
    expect(text).toContain("No project is flagged");
  });

  it("states a team filter on the cover", async () => {
    const report = fullReport({
      meta: { ...fullReport().meta, filter: { squad: ["Payments"], tribe: [], group: [] }, filterLabel: "squad Payments" },
    });
    const pages = await extract(await renderReportPdf(report));
    expect(pages[0]!.text).toContain("Only applications in squad Payments.");
  });

  it("reports full coverage differently from partial coverage", async () => {
    const full = fullReport({
      coverage: { eligible: 400, covered: 400, coveragePct: 100, stale: 0, neverScanned: 0, pendingConfirmation: 0, worstOffenders: [] },
    });
    expect(textOf(await extract(await renderReportPdf(full)))).toContain("describe the whole estate");
    expect(textOf(await extract(await renderReportPdf(fullReport())))).not.toContain("describe the whole estate");
  });

  it("truncates an over-long name instead of overflowing its column", async () => {
    const pages = await extract(
      await renderReportPdf(fullReport({ progress: { projects: [project("a".repeat(200))], squads: [], tribes: [] } })),
    );
    for (const page of pages) {
      for (const item of page.items) expect(item.x + item.width).toBeLessThanOrEqual(PAGE_WIDTH - MARGIN + 2);
    }
    expect(textOf(pages)).toContain("…");
  });

  it("paginates a long report and keeps the footers consistent", async () => {
    const many = Array.from({ length: 60 }, (_v, i) => project(`service-${i}`));
    const pages = await extract(
      await renderReportPdf(
        fullReport({
          progress: { projects: many, squads: [], tribes: [] },
          attention: {
            ...fullReport().attention,
            projects: many.map((p) => ({ ...fullReport().attention.projects[0]!, applicationId: p.applicationId, name: p.name })),
          },
        }),
      ),
    );
    expect(pages.length).toBeGreaterThan(4);
    for (const [index, page] of pages.entries()) {
      const labels = page.items.filter((i) => /^Page \d+ of \d+$/.test(i.str));
      expect(labels.map((l) => l.str)).toEqual([`Page ${index + 1} of ${pages.length}`]);
    }
    // A table broken across a page reprints its header.
    expect(pages.filter((p) => p.text.includes("PROJECT") && p.text.includes("FIXED")).length).toBeGreaterThan(1);
  });
});
