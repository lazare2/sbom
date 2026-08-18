import { describe, expect, it } from "vitest";
import { getDocument } from "pdfjs-dist/legacy/build/pdf.mjs";
import {
  REPORT_SNAPSHOT_VERSION,
  type ReportRunSummary,
  type ReportSnapshot,
} from "@sbom/shared";
import { computeDelta, findingKey } from "../../src/modules/reports/delta.js";
import { buildMonthlyView } from "../../src/modules/reports/monthly-view.js";
import { renderMonthlyReportPdf } from "../../src/modules/reports/monthly-pdf.js";

/**
 * What the monthly report tells management.
 *
 * The delta tests pin the attribution; these pin the presentation of it, which is where an
 * accurate figure can still mislead. Two failures matter most and both are covered here: a
 * first report implying that the entire estate's findings appeared this month, and a fall
 * caused by the vulnerability database being presented as work somebody did.
 */

const APP_A = "11111111-1111-1111-1111-111111111111";
const APP_B = "22222222-2222-2222-2222-222222222222";

function run(over: Partial<ReportRunSummary> = {}): ReportRunSummary {
  return {
    id: "aaaaaaaa-0000-0000-0000-000000000000",
    kind: "monthly",
    periodStart: "2026-06-30T20:00:00.000Z",
    periodEnd: "2026-07-31T20:00:00.000Z",
    periodLabel: "2026-07",
    timeZone: "Asia/Tbilisi",
    generatedAt: "2026-08-03T05:00:00.000Z",
    generatedBy: null,
    vulnDbBuiltAt: "2026-08-01T00:00:00.000Z",
    baselineRunId: null,
    hasPdf: false,
    sentAt: null,
    recipients: null,
    deliveryError: null,
    totals: { applications: 2, components: 3, findings: 3 },
    ...over,
  };
}

/**
 * An estate with one application dependency and two base-image packages, which is the shape
 * that matters: base-image findings outnumber real ones in every real deployment, so any
 * figure that merges them is dominated by packages no application team can change.
 */
function snapshot(over: Partial<ReportSnapshot> = {}): ReportSnapshot {
  const base: ReportSnapshot = {
    version: REPORT_SNAPSHOT_VERSION,
    takenAt: "2026-08-03T05:00:00.000Z",
    vulnDbBuiltAt: "2026-08-01T00:00:00.000Z",
    applications: [
      { id: APP_A, name: "checkout-web", status: "active", lastScanAt: null },
      { id: APP_B, name: "payments-api", status: "active", lastScanAt: null },
    ],
    components: [
      { id: 1, name: "log4j-core", version: "2.14.1", ecosystem: "maven", kind: "library", scope: "app" },
      { id: 2, name: "openssl", version: "3.0.11", ecosystem: "deb", kind: "library", scope: "os" },
      { id: 3, name: "curl", version: "7.88.1", ecosystem: "deb", kind: "library", scope: "os" },
    ],
    dependencies: { [APP_A]: [1, 2], [APP_B]: [2, 3] },
    findings: [
      findingKey(APP_A, 1, "CVE-2021-44228"),
      findingKey(APP_A, 2, "CVE-2024-0001"),
      findingKey(APP_B, 2, "CVE-2024-0001"),
    ],
    severities: { "CVE-2021-44228": "critical", "CVE-2024-0001": "high" },
    totals: {
      applications: 2,
      components: 3,
      findings: 3,
      bySeverity: { critical: 1, high: 2 },
    },
    ...over,
  };
  return base;
}

async function textOf(pdf: Buffer): Promise<string[]> {
  const doc = await getDocument({ data: new Uint8Array(pdf), useSystemFonts: true }).promise;
  const pages: string[] = [];
  for (let i = 1; i <= doc.numPages; i += 1) {
    const page = await doc.getPage(i);
    const content = await page.getTextContent();
    pages.push(
      content.items
        .map((item) => ("str" in item ? item.str : ""))
        .join(" ")
        .replace(/\s+/g, " "),
    );
  }
  return pages;
}

describe("monthly report view", () => {
  it("separates base-image findings from application dependencies", () => {
    const view = buildMonthlyView({ run: run(), snapshot: snapshot(), delta: null });

    // One finding a team can act on; two inherited from images. Merging them would put the
    // report's headline entirely at the mercy of the base image.
    expect(view.headline.appFindings).toBe(1);
    expect(view.headline.baseFindings).toBe(2);
    expect(view.headline.totalFindings).toBe(3);
  });

  it("shows no comparison at all when there is no baseline", () => {
    const view = buildMonthlyView({ run: run(), snapshot: snapshot(), delta: null });

    expect(view.comparable).toBe(false);
    // Zero here would render as "critical: now 1, last report 0, change +1", which states
    // that a critical finding appeared this month. It did not; there is simply no baseline.
    for (const row of view.severityMovement) {
      expect(row.before).toBeNull();
      expect(row.change).toBeNull();
    }
    expect(view.dependencyMovement.previousTotal).toBeNull();
  });

  it("lists every cause including the ones at zero", () => {
    const before = snapshot();
    const after = snapshot({
      // log4j upgraded away; the base-image findings are untouched.
      dependencies: { [APP_A]: [2], [APP_B]: [2, 3] },
      findings: [findingKey(APP_A, 2, "CVE-2024-0001"), findingKey(APP_B, 2, "CVE-2024-0001")],
      totals: { applications: 2, components: 3, findings: 2, bySeverity: { high: 2 } },
    });

    const view = buildMonthlyView({
      run: run(),
      snapshot: after,
      delta: computeDelta(before, after),
      baseline: before,
    });

    const causes = Object.fromEntries(view.resolvedByCause.map((c) => [c.label, c.count]));
    expect(causes["Fixed by upgrade or removal"]).toBe(1);
    // Present and zero, not absent. "Advisory withdrawn: 0" is what tells the reader the
    // fix above is real, and a missing row cannot say that.
    expect(causes["Advisory withdrawn or re-scored"]).toBe(0);
    expect(causes["Application no longer tracked"]).toBe(0);
  });

  it("orders packages by how many applications one upgrade would fix", () => {
    const view = buildMonthlyView({ run: run(), snapshot: snapshot(), delta: null });

    // openssl is in both applications; log4j in one. The upgrade worth doing first is the
    // one that clears two applications at once, so it leads.
    expect(view.widestPackages[0]?.name).toBe("openssl");
    expect(view.widestPackages[0]?.applications).toBe(2);
    expect(view.widestPackages[0]?.scope).toBe("os");
  });

  it("reports a new application's findings as new rather than as a regression", () => {
    const before = snapshot({
      applications: [{ id: APP_A, name: "checkout-web", status: "active", lastScanAt: null }],
      dependencies: { [APP_A]: [1, 2] },
      findings: [findingKey(APP_A, 1, "CVE-2021-44228"), findingKey(APP_A, 2, "CVE-2024-0001")],
      totals: { applications: 1, components: 3, findings: 2, bySeverity: { critical: 1, high: 1 } },
    });
    const after = snapshot();

    const view = buildMonthlyView({
      run: run(),
      snapshot: after,
      delta: computeDelta(before, after),
      baseline: before,
    });

    const arrived = view.riskiestApplications.find((a) => a.name === "payments-api");
    // Null, not +1: the application did not get worse, it started being measured.
    expect(arrived?.change).toBeNull();
    expect(view.riskiestApplications.find((a) => a.name === "checkout-web")?.change).toBe(0);
  });

  it("refuses to credit a database change as a fix, in the summary itself", () => {
    const before = snapshot();
    const after = snapshot({
      // Same packages, same versions, newer database: the advisory stopped matching.
      vulnDbBuiltAt: "2026-09-01T00:00:00.000Z",
      findings: [findingKey(APP_A, 2, "CVE-2024-0001"), findingKey(APP_B, 2, "CVE-2024-0001")],
      totals: { applications: 2, components: 3, findings: 2, bySeverity: { high: 2 } },
    });

    const view = buildMonthlyView({
      run: run(),
      snapshot: after,
      delta: computeDelta(before, after),
      baseline: before,
    });

    expect(view.databaseCaveat).not.toBeNull();
    // The caveat is worthless if the sentence next to the number still claims a fix.
    expect(view.summary).toContain("None of them were fixed by upgrading");
  });
});

describe("monthly report PDF", () => {
  it("puts the database caveat on the first page, above the figures", async () => {
    const before = snapshot();
    const after = snapshot({
      vulnDbBuiltAt: "2026-09-01T00:00:00.000Z",
      findings: [findingKey(APP_A, 2, "CVE-2024-0001"), findingKey(APP_B, 2, "CVE-2024-0001")],
      totals: { applications: 2, components: 3, findings: 2, bySeverity: { high: 2 } },
    });
    const view = buildMonthlyView({
      run: run(),
      snapshot: after,
      delta: computeDelta(before, after),
      baseline: before,
    });

    const pages = await textOf(await renderMonthlyReportPdf(view));
    const first = pages[0]!;

    expect(first).toContain("Read this first");
    /*
      Ordering is the assertion. A caveat printed after the numbers is technically present
      and practically useless, because the figure above it is what gets quoted.
    */
    expect(first.indexOf("Read this first")).toBeLessThan(first.indexOf("RESOLVED"));
  });

  it("omits comparison columns entirely on a first report", async () => {
    const view = buildMonthlyView({ run: run(), snapshot: snapshot(), delta: null });
    const pages = await textOf(await renderMonthlyReportPdf(view));
    const all = pages.join(" ");

    expect(all).toContain("first report in the series");
    // The column headers themselves must be gone. Present-but-empty still invites the
    // reader to read a comparison that does not exist.
    expect(all).not.toContain("LAST REPORT");
    expect(all).toContain("OPEN FINDINGS");
  });

  it("names the period and the applications a reader has to chase", async () => {
    const before = snapshot();
    const after = snapshot({
      dependencies: { [APP_A]: [2], [APP_B]: [2, 3] },
      findings: [findingKey(APP_A, 2, "CVE-2024-0001"), findingKey(APP_B, 2, "CVE-2024-0001")],
      totals: { applications: 2, components: 3, findings: 2, bySeverity: { high: 2 } },
    });
    const view = buildMonthlyView({
      run: run(),
      snapshot: after,
      delta: computeDelta(before, after),
      baseline: before,
    });

    const all = (await textOf(await renderMonthlyReportPdf(view))).join(" ");

    expect(all).toContain("July 2026");
    expect(all).toContain("checkout-web");
    expect(all).toContain("payments-api");
    expect(all).toContain("Fixed by upgrade or removal");
  });

  it("states the truncation instead of silently dropping rows", async () => {
    // More introduced findings than the report prints, so the count in the summary and the
    // number of rows below it disagree unless the document says why.
    const many: string[] = [];
    const severities: Record<string, string> = {};
    for (let i = 0; i < 60; i += 1) {
      const id = `CVE-2026-${String(i).padStart(4, "0")}`;
      many.push(findingKey(APP_A, 1, id));
      severities[id] = "high";
    }

    const before = snapshot({ findings: [], totals: { applications: 2, components: 3, findings: 0, bySeverity: {} } });
    const after = snapshot({
      findings: many,
      severities,
      totals: { applications: 2, components: 3, findings: many.length, bySeverity: { high: many.length } },
    });

    const view = buildMonthlyView({
      run: run(),
      snapshot: after,
      delta: computeDelta(before, after),
      baseline: before,
    });
    const all = (await textOf(await renderMonthlyReportPdf(view))).join(" ");

    expect(all).toContain("Showing the 40 most severe of 60");
  });
});
