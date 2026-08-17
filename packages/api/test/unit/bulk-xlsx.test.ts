import { describe, expect, it } from "vitest";
import ExcelJS from "exceljs";
import type { BulkRollupRow, BulkSearchResult, ComponentSearchHit } from "@sbom/shared";
import { renderBulkXlsx } from "../../src/modules/components/bulk-xlsx.js";

/**
 * Tests for the exported workbook.
 *
 * Read back through exceljs rather than asserted on bytes, because the properties
 * that matter are structural: the sheets that exist, the verdict each row carries,
 * and whether a truncated export admits it. A byte-length check would pass on a
 * workbook with the wrong answer in it.
 */

async function read(buffer: Buffer): Promise<ExcelJS.Workbook> {
  const book = new ExcelJS.Workbook();
  await book.xlsx.load(buffer);
  return book;
}

function textOf(sheet: ExcelJS.Worksheet): string {
  const parts: string[] = [];
  sheet.eachRow((row) => {
    row.eachCell({ includeEmpty: false }, (cell) => parts.push(String(cell.value ?? "")));
  });
  return parts.join(" | ");
}

function rollupRow(overrides: Partial<BulkRollupRow> & { name: string }): BulkRollupRow {
  return {
    line: 1,
    raw: overrides.name,
    version: null,
    versionKind: "any",
    found: false,
    nameFound: false,
    ecosystems: [],
    versionsFound: [],
    versionsTruncated: false,
    currentApplications: 0,
    historicalApplications: 0,
    ...overrides,
  };
}

function hit(overrides: Partial<ComponentSearchHit> = {}): ComponentSearchHit {
  return {
    applicationId: "app-1",
    applicationName: "payments-api",
    applicationStatus: "active",
    componentId: "1",
    componentName: "express",
    componentVersion: "4.19.2",
    ecosystem: "npm",
    purl: "pkg:npm/express@4.19.2",
    usage: "current",
    lastSeenScanId: "scan-1",
    lastSeenAt: "2026-08-11T12:00:00.000Z",
    lastSeenBuildNumber: "107",
    ...overrides,
  };
}

function result(overrides: Partial<BulkSearchResult> = {}): BulkSearchResult {
  return {
    queryId: "11111111-1111-1111-1111-111111111111",
    scope: "current",
    parse: {
      lines: 4,
      entries: 4,
      duplicatesCollapsed: 0,
      constraintsDropped: 0,
      problems: [],
      truncated: false,
    },
    summary: { found: 2, notFound: 2, inCurrentUse: 1, applicationsAffected: 3 },
    rollup: [
      // One row per verdict, so the labelling of all four is asserted at once.
      rollupRow({
        name: "express",
        found: true,
        nameFound: true,
        ecosystems: ["npm"],
        versionsFound: ["4.19.2"],
        currentApplications: 3,
      }),
      rollupRow({
        line: 2,
        name: "commons-io",
        found: true,
        nameFound: true,
        ecosystems: ["maven"],
        versionsFound: ["2.11.0"],
        historicalApplications: 1,
      }),
      rollupRow({
        line: 3,
        name: "express",
        raw: "express@4.0.0",
        version: "4.0.0",
        versionKind: "exact",
        found: false,
        nameFound: true,
        ecosystems: ["npm"],
        versionsFound: ["4.18.2", "4.19.2"],
      }),
      rollupRow({ line: 4, name: "logaas" }),
    ],
    ...overrides,
  };
}

async function build(overrides: Partial<BulkSearchResult> = {}, matches = [hit()], truncated = false) {
  return read(
    await renderBulkXlsx({
      result: result(overrides),
      matches,
      matchesTruncated: truncated,
      generatedAt: new Date("2026-08-12T09:30:00.000Z"),
      generatedBy: "auditor@sbom.local",
      vulnScanningEnabled: false,
    listUrl: "http://localhost:5173/search/list/11111111-1111-1111-1111-111111111111",
    }),
  );
}

describe("renderBulkXlsx", () => {
  it("produces a workbook Excel will open, with the expected sheets", async () => {
    const book = await build();
    expect(book.worksheets.map((s) => s.name)).toEqual(["Summary", "Packages", "Matches"]);
  });

  it("carries its own provenance", async () => {
    // A spreadsheet gets forwarded and renamed; one whose scope and date are
    // unknown is one whose numbers get misattributed.
    const text = textOf((await build()).getWorksheet("Summary")!);
    expect(text).toContain("2026-08-12 09:30 UTC");
    expect(text).toContain("auditor@sbom.local");
    expect(text).toContain("Current builds only");
    expect(text).toContain("/search/list/11111111-1111-1111-1111-111111111111");
  });

  it("states that it is not vulnerability data", async () => {
    expect(textOf((await build()).getWorksheet("Summary")!)).toContain(
      "does not match packages against CVE feeds",
    );
  });

  it("distinguishes all four outcomes for a listed package", async () => {
    const sheet = (await build()).getWorksheet("Packages")!;
    const verdicts: string[] = [];
    sheet.eachRow((row, n) => {
      if (n === 1) return;
      verdicts.push(String(row.getCell(6).value ?? ""));
    });

    // "Other version" must not collapse into "Not found": having the package but
    // not the named version is a different, and much more interesting, answer.
    expect(verdicts).toEqual(["In use", "Removed", "Other version", "Not found"]);
  });

  it("keeps not-found rows rather than filtering them out", async () => {
    // If three of forty packages are present, the other thirty-seven are the
    // answer. A sheet that dropped them would leave the reader diffing by hand.
    expect(textOf((await build()).getWorksheet("Packages")!)).toContain("logaas");
  });

  it("names the versions that ARE present on a miss", async () => {
    const sheet = (await build()).getWorksheet("Packages")!;
    const row = sheet.getRow(4);
    expect(String(row.getCell(4).value)).toBe("4.0.0");
    expect(String(row.getCell(8).value)).toBe("4.18.2, 4.19.2");
  });

  it("freezes the header and enables filtering on the data sheets", async () => {
    // The first thing anyone does with a 200-row audit is filter it to the
    // not-found rows.
    const book = await build();
    for (const name of ["Packages", "Matches"]) {
      const sheet = book.getWorksheet(name)!;
      expect(sheet.views[0]?.state, name).toBe("frozen");
      expect(sheet.autoFilter, name).toBeTruthy();
    }
  });

  it("adds a problems sheet only when lines failed to parse", async () => {
    const withProblems = await build({
      parse: {
        lines: 5,
        entries: 4,
        duplicatesCollapsed: 0,
        constraintsDropped: 0,
        truncated: false,
        problems: [{ line: 5, raw: "this is not a package", reason: "more than two fields" }],
      },
    });
    expect(withProblems.worksheets.map((s) => s.name)).toContain("Not understood");
    const text = textOf(withProblems.getWorksheet("Not understood")!);
    expect(text).toContain("this is not a package");
    expect(text).toContain("more than two fields");

    // An empty sheet in every export trains people to ignore the one that matters.
    const clean = await build();
    expect(clean.worksheets.map((s) => s.name)).not.toContain("Not understood");
  });

  it("says so when the matches sheet was truncated", async () => {
    // A truncated export that looks complete is worse than none, because it gets
    // treated as the full picture.
    const book = await build({}, [hit()], true);
    expect(textOf(book.getWorksheet("Matches")!)).toContain("Truncated");
  });

  it("says so when nothing matched at all", async () => {
    const book = await build({}, []);
    expect(textOf(book.getWorksheet("Matches")!)).toContain("No application matched");
  });

  it("renders an empty list without throwing", async () => {
    const book = await build({
      rollup: [],
      parse: { lines: 0, entries: 0, duplicatesCollapsed: 0, constraintsDropped: 0, problems: [], truncated: false },
      summary: { found: 0, notFound: 0, inCurrentUse: 0, applicationsAffected: 0 },
    }, []);
    expect(book.getWorksheet("Packages")).toBeDefined();
  });
});
