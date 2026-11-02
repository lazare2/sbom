import { describe, expect, it } from "vitest";
import ExcelJS from "exceljs";
import { columnLetter, writeXlsx, XLSX_MAX_CELL_CHARS, type DeflateRaw } from "@sbom/shared";

/**
 * Tests for the hand-written workbook writer behind every table's "Export table" button.
 *
 * Read back through exceljs, an independent implementation of the format, because the
 * failure that matters is Excel refusing the file - and a byte comparison against our own
 * expectations would share any misunderstanding of the format that produced the bytes.
 */

async function read(bytes: Uint8Array): Promise<ExcelJS.Workbook> {
  const book = new ExcelJS.Workbook();
  await book.xlsx.load(Buffer.from(bytes));
  return book;
}

/** The browser path: CompressionStream, which Node 22 also has. */
const deflateRaw: DeflateRaw = async (data) => {
  const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
};

describe("writeXlsx", () => {
  for (const [mode, options] of [
    ["stored", {}],
    ["deflated", { deflateRaw }],
  ] as const) {
    it(`round-trips headers, text, numbers, booleans and dates (${mode})`, async () => {
      const when = new Date(2026, 10, 2, 14, 30);
      const bytes = await writeXlsx(
        [
          {
            name: "Applications",
            columns: [{ header: "Application", width: 30 }, { header: "Findings" }, { header: "Stale" }, { header: "Last scan" }],
            rows: [
              ["checkout-web", 12, false, when],
              ["ünïcødé & <tags> \"quoted\"", 0, true, null],
            ],
          },
        ],
        options,
      );
      const book = await read(bytes);
      const sheet = book.getWorksheet("Applications")!;
      expect(sheet.getRow(1).values).toEqual([undefined, "Application", "Findings", "Stale", "Last scan"]);
      expect(sheet.getCell("A2").value).toBe("checkout-web");
      expect(sheet.getCell("B2").value).toBe(12);
      expect(sheet.getCell("C2").value).toBe(false);
      // exceljs reads serials back as UTC; the writer stores local wall-clock time.
      const back = sheet.getCell("D2").value as Date;
      expect(back.getUTCHours()).toBe(14);
      expect(back.getUTCMinutes()).toBe(30);
      expect(sheet.getCell("A3").value).toBe('ünïcødé & <tags> "quoted"');
      expect(sheet.getCell("D3").value).toBeNull();
      expect(sheet.getRow(1).font?.bold ?? sheet.getCell("A1").font?.bold).toBe(true);
      expect(sheet.autoFilter).toBeTruthy();
      expect(sheet.views[0]).toMatchObject({ state: "frozen", ySplit: 1 });
      expect(sheet.getColumn(1).width).toBe(30);
    });
  }

  it("keeps formula-looking text as text", async () => {
    const bytes = await writeXlsx([
      { name: "S", columns: [{ header: "Branch" }], rows: [["=HYPERLINK(\"http://evil\",\"x\")"], ["+1"], ["@SUM(A1)"]] },
    ]);
    const sheet = (await read(bytes)).worksheets[0]!;
    expect(sheet.getCell("A2").value).toBe('=HYPERLINK("http://evil","x")');
    expect(sheet.getCell("A2").type).toBe(ExcelJS.ValueType.String);
    expect(sheet.getCell("A3").value).toBe("+1");
  });

  it("drops characters XML cannot carry and caps cell length", async () => {
    const long = "x".repeat(XLSX_MAX_CELL_CHARS + 50);
    const bytes = await writeXlsx([{ name: "S", columns: [{ header: "A" }], rows: [["a\u0000b\u0007c"], [long]] }]);
    const sheet = (await read(bytes)).worksheets[0]!;
    expect(sheet.getCell("A2").value).toBe("abc");
    expect(String(sheet.getCell("A3").value).length).toBe(XLSX_MAX_CELL_CHARS);
  });

  it("sanitises and de-duplicates sheet names", async () => {
    const bytes = await writeXlsx([
      { name: "Findings: a/b [x]", columns: [{ header: "A" }], rows: [] },
      { name: "findings: a/b [x]", columns: [{ header: "A" }], rows: [] },
      { name: "", columns: [], rows: [], headerRow: false },
    ]);
    const names = (await read(bytes)).worksheets.map((s) => s.name);
    expect(names).toHaveLength(3);
    expect(names[0]).toBe("Findings  a b  x");
    expect(names[1]).not.toBe(names[0]);
    expect(names[1]!.length).toBeLessThanOrEqual(31);
    expect(names[2]).toBe("Sheet3");
  });

  it("names columns past Z the way Excel does", () => {
    expect(columnLetter(0)).toBe("A");
    expect(columnLetter(25)).toBe("Z");
    expect(columnLetter(26)).toBe("AA");
    expect(columnLetter(701)).toBe("ZZ");
    expect(columnLetter(702)).toBe("AAA");
  });

  it("writes a large sheet", async () => {
    const rows = Array.from({ length: 20_000 }, (_, i) => [`app-${i}`, i, new Date(2026, 0, 1)]);
    const bytes = await writeXlsx([{ name: "Big", columns: [{ header: "A" }, { header: "B" }, { header: "C" }], rows }], { deflateRaw });
    const sheet = (await read(bytes)).worksheets[0]!;
    expect(sheet.rowCount).toBe(20_001);
    expect(sheet.getCell("B20001").value).toBe(19_999);
  });
});
