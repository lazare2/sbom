/**
 * A minimal `.xlsx` writer: one or more sheets of plain values, a bold frozen header row,
 * an autofilter, column widths and real date cells.
 *
 * ## Why hand-written
 *
 * The table export runs in the browser, on the rows the reader is already looking at, so the
 * data never makes a round trip to the API. The libraries that write xlsx in a browser are
 * hundreds of kilobytes for a feature that needs a few hundred lines; the format itself is a
 * zip of six small XML files.
 *
 * ## Why every string is an inline string cell
 *
 * A value like `=HYPERLINK(...)` in a package name or a CI branch is data, not a formula. In a
 * CSV, Excel would evaluate it; in an xlsx, a cell written with `t="inlineStr"` is text and is
 * never evaluated, so nothing here needs escaping or mangling to be safe to open.
 *
 * Environment-neutral on purpose (no DOM, no Node APIs beyond `TextEncoder`), so the same code
 * is exercised by the API's unit tests and shipped to the browser.
 */

declare const TextEncoder: { new (): { encode(input: string): Uint8Array } };

export type XlsxCell = string | number | boolean | Date | null | undefined;

export interface XlsxSheet {
  name: string;
  columns: { header: string; width?: number }[];
  rows: readonly XlsxCell[][];
  /** Freeze the first row and add filter buttons to it. Default true. */
  headerRow?: boolean;
}

/** Compresses one zip entry with raw DEFLATE. Without one, entries are stored uncompressed. */
export type DeflateRaw = (data: Uint8Array) => Promise<Uint8Array>;

/** Excel's own limit on a cell's text. Longer text makes Excel refuse the whole file. */
export const XLSX_MAX_CELL_CHARS = 32_767;

/** Excel's limit on rows per sheet, header included. */
export const XLSX_MAX_ROWS = 1_048_576;

const MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships";

/** Style indexes into `cellXfs` in STYLES below. */
const STYLE_HEADER = 1;
const STYLE_DATE = 2;

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="${MAIN_NS}"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm"/></numFmts><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;

/** Characters XML 1.0 cannot carry at all, even escaped. Dropped rather than failing the file. */
// eslint-disable-next-line no-control-regex
const INVALID_XML_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g;

function escapeXml(value: string): string {
  return value
    .replace(INVALID_XML_CHARS, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** `0` → `A`, `25` → `Z`, `26` → `AA`. */
export function columnLetter(index: number): string {
  let n = index + 1;
  let out = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    out = String.fromCharCode(65 + rem) + out;
    n = Math.floor((n - 1) / 26);
  }
  return out;
}

/**
 * A sheet name Excel will accept: at most 31 characters, none of `[]:*?/\`, not blank, and
 * unique within the workbook (case-insensitively, as Excel compares them).
 */
function sheetNames(sheets: readonly XlsxSheet[]): string[] {
  const used = new Set<string>();
  return sheets.map((sheet, i) => {
    let base = sheet.name.replace(/[[\]:*?/\\]/g, " ").replace(/^'+|'+$/g, "").trim().slice(0, 31);
    if (!base) base = `Sheet${i + 1}`;
    let name = base;
    for (let n = 2; used.has(name.toLowerCase()); n++) {
      const suffix = ` (${n})`;
      name = base.slice(0, 31 - suffix.length) + suffix;
    }
    used.add(name.toLowerCase());
    return name;
  });
}

/**
 * Excel's date serial, in the reader's local time.
 *
 * Local rather than UTC because the table being exported shows local times, and an export
 * whose timestamps are all shifted by the UTC offset would disagree with the screen it was
 * taken from.
 */
function excelSerial(date: Date): number {
  const local = date.getTime() - date.getTimezoneOffset() * 60_000;
  return local / 86_400_000 + 25_569;
}

function cellXml(ref: string, value: XlsxCell, style?: number): string {
  const s = style ? ` s="${style}"` : "";
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "number") {
    return Number.isFinite(value) ? `<c r="${ref}"${s}><v>${value}</v></c>` : "";
  }
  if (typeof value === "boolean") {
    return `<c r="${ref}"${s} t="b"><v>${value ? 1 : 0}</v></c>`;
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return "";
    return `<c r="${ref}" s="${style ?? STYLE_DATE}"><v>${excelSerial(value)}</v></c>`;
  }
  const text = value.length > XLSX_MAX_CELL_CHARS ? value.slice(0, XLSX_MAX_CELL_CHARS) : value;
  // xml:space keeps leading and trailing spaces, which Excel otherwise strips.
  return `<c r="${ref}"${s} t="inlineStr"><is><t xml:space="preserve">${escapeXml(text)}</t></is></c>`;
}

function sheetXml(sheet: XlsxSheet): { xml: string; filterRef: string | null } {
  const header = sheet.headerRow !== false;
  const colCount = Math.max(1, sheet.columns.length);
  const lastCol = columnLetter(colCount - 1);
  const rowLimit = XLSX_MAX_ROWS - (header ? 1 : 0);
  const rows = sheet.rows.length > rowLimit ? sheet.rows.slice(0, rowLimit) : sheet.rows;

  const parts: string[] = [];
  parts.push(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`);
  parts.push(`<worksheet xmlns="${MAIN_NS}" xmlns:r="${REL_NS}">`);
  const lastRow = rows.length + (header ? 1 : 0);
  parts.push(`<dimension ref="A1:${lastCol}${Math.max(1, lastRow)}"/>`);
  parts.push(
    header
      ? `<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`
      : `<sheetViews><sheetView workbookViewId="0"/></sheetViews>`,
  );
  parts.push(`<sheetFormatPr defaultRowHeight="15"/>`);
  if (sheet.columns.length > 0) {
    parts.push("<cols>");
    sheet.columns.forEach((column, i) => {
      const width = Math.min(100, Math.max(6, column.width ?? 16));
      parts.push(`<col min="${i + 1}" max="${i + 1}" width="${width}" customWidth="1"/>`);
    });
    parts.push("</cols>");
  }
  parts.push("<sheetData>");
  let r = 1;
  if (header) {
    parts.push(`<row r="1">`);
    sheet.columns.forEach((column, i) => parts.push(cellXml(`${columnLetter(i)}1`, column.header, STYLE_HEADER)));
    parts.push("</row>");
    r = 2;
  }
  for (const row of rows) {
    parts.push(`<row r="${r}">`);
    for (let i = 0; i < colCount; i++) parts.push(cellXml(`${columnLetter(i)}${r}`, row[i]));
    parts.push("</row>");
    r++;
  }
  parts.push("</sheetData>");
  const filterRef = header && sheet.columns.length > 0 ? `A1:${lastCol}${Math.max(1, lastRow)}` : null;
  if (filterRef) parts.push(`<autoFilter ref="${filterRef}"/>`);
  parts.push("</worksheet>");
  return { xml: parts.join(""), filterRef };
}

// --- zip ---------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** DOS date and time fields, which is all a zip entry can carry. */
function dosDateTime(date: Date): { time: number; date: number } {
  return {
    time: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
    date: ((Math.max(1980, date.getFullYear()) - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
  };
}

async function zip(entries: { name: string; data: Uint8Array }[], deflateRaw?: DeflateRaw): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const stamp = dosDateTime(new Date());
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;

  for (const entry of entries) {
    const name = encoder.encode(entry.name);
    const crc = crc32(entry.data);
    let body = entry.data;
    let method = 0;
    if (deflateRaw) {
      const compressed = await deflateRaw(entry.data);
      if (compressed.length < entry.data.length) {
        body = compressed;
        method = 8;
      }
    }

    const local = new Uint8Array(30 + name.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0, true);
    lv.setUint16(8, method, true);
    lv.setUint16(10, stamp.time, true);
    lv.setUint16(12, stamp.date, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, body.length, true);
    lv.setUint32(22, entry.data.length, true);
    lv.setUint16(26, name.length, true);
    lv.setUint16(28, 0, true);
    local.set(name, 30);

    const central = new Uint8Array(46 + name.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0, true);
    cv.setUint16(10, method, true);
    cv.setUint16(12, stamp.time, true);
    cv.setUint16(14, stamp.date, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, body.length, true);
    cv.setUint32(24, entry.data.length, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(42, offset, true);
    central.set(name, 46);

    locals.push(local, body);
    centrals.push(central);
    offset += local.length + body.length;
  }

  const centralSize = centrals.reduce((sum, c) => sum + c.length, 0);
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);

  const out = new Uint8Array(offset + centralSize + end.length);
  let at = 0;
  for (const part of [...locals, ...centrals, end]) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** Builds the workbook. The bytes are a complete `.xlsx` file. */
export async function writeXlsx(sheets: readonly XlsxSheet[], options: { deflateRaw?: DeflateRaw } = {}): Promise<Uint8Array> {
  if (sheets.length === 0) throw new Error("a workbook needs at least one sheet");
  const encoder = new TextEncoder();
  const names = sheetNames(sheets);
  const rendered = sheets.map(sheetXml);

  const definedNames = rendered
    .map((sheet, i) =>
      sheet.filterRef
        ? `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">'${escapeXml(
            names[i]!.replace(/'/g, "''"),
          )}'!${sheet.filterRef.replace(/([A-Z]+)(\d+)/g, "$$$1$$$2")}</definedName>`
        : "",
    )
    .join("");

  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="${MAIN_NS}" xmlns:r="${REL_NS}"><sheets>${names
    .map((name, i) => `<sheet name="${escapeXml(name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`)
    .join("")}</sheets>${definedNames ? `<definedNames>${definedNames}</definedNames>` : ""}</workbook>`;

  const workbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="${PKG_REL_NS}">${names
    .map(
      (_, i) =>
        `<Relationship Id="rId${i + 1}" Type="${REL_NS}/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`,
    )
    .join("")}<Relationship Id="rId${names.length + 1}" Type="${REL_NS}/styles" Target="styles.xml"/></Relationships>`;

  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>${names
    .map(
      (_, i) =>
        `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`,
    )
    .join("")}<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;

  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="${PKG_REL_NS}"><Relationship Id="rId1" Type="${REL_NS}/officeDocument" Target="xl/workbook.xml"/></Relationships>`;

  const entries = [
    { name: "[Content_Types].xml", data: encoder.encode(contentTypes) },
    { name: "_rels/.rels", data: encoder.encode(rootRels) },
    { name: "xl/workbook.xml", data: encoder.encode(workbook) },
    { name: "xl/_rels/workbook.xml.rels", data: encoder.encode(workbookRels) },
    { name: "xl/styles.xml", data: encoder.encode(STYLES) },
    ...rendered.map((sheet, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, data: encoder.encode(sheet.xml) })),
  ];
  return zip(entries, options.deflateRaw);
}

/** The MIME type to serve or download an `.xlsx` as. */
export const XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
