/**
 * Page furniture shared by every PDF this platform renders.
 *
 * Extracted rather than duplicated: the estate report and the monthly management report are
 * different documents with different content, but a reader who receives both should not be
 * able to tell they were built by different code. Margins, rules, zebra striping and the
 * footer are the parts that would drift apart first, so they live here and neither renderer
 * owns them.
 *
 * Only the standard-14 fonts are used, so no font files ship with the build. Those cover
 * Latin-1; a package name in Cyrillic or CJK would render as substituted glyphs. Package
 * names are ASCII in every ecosystem the platform ingests, and the alternative — embedding a
 * full Unicode TTF — costs several megabytes on every report for a case that has not
 * occurred.
 */

// A4 at 72 dpi, with a margin wide enough that a two-column table never looks
// like it is falling off the page.
export const PAGE = { width: 595.28, height: 841.89 };
export const MARGIN = 44;
export const CONTENT_WIDTH = PAGE.width - MARGIN * 2;
/** Where the footer starts. Content must never enter this band. */
export const FOOTER_TOP = PAGE.height - 46;

export const COLOR = {
  text: "#111827",
  muted: "#6b7280",
  faint: "#9ca3af",
  rule: "#e5e7eb",
  accent: "#2563eb",
  warn: "#b45309",
  ok: "#15803d",
  headerFill: "#f3f4f6",
};

export type Doc = PDFKit.PDFDocument;

/** A column in a rendered table. */
export interface Column<T> {
  header: string;
  /** Fraction of the content width. The set should sum to 1. */
  width: number;
  align?: "left" | "right";
  /** Rendered text. Return "—" for absent values rather than an empty cell. */
  value: (row: T, index: number) => string;
  /** Monospace-ish treatment for versions and identifiers. */
  mono?: boolean;
}

/**
 * Cursor and page management.
 *
 * pdfkit tracks `doc.y` itself, but its automatic flow breaks pages wherever the
 * cursor happens to land — which puts a section heading alone at the bottom of a
 * page and splits three-row tables across two. This wrapper makes the break
 * decision explicit at each block boundary instead.
 */
export class Layout {
  constructor(readonly doc: Doc) {}

  get y(): number {
    return this.doc.y;
  }

  set y(value: number) {
    this.doc.y = value;
  }

  /** Starts a new page if `height` more points would run into the footer. */
  ensureSpace(height: number): void {
    if (this.doc.y + height > FOOTER_TOP) {
      this.doc.addPage();
      this.doc.y = MARGIN;
    }
  }

  gap(height: number): void {
    this.doc.y += height;
  }

  rule(): void {
    this.doc
      .moveTo(MARGIN, this.doc.y)
      .lineTo(MARGIN + CONTENT_WIDTH, this.doc.y)
      .lineWidth(0.5)
      .strokeColor(COLOR.rule)
      .stroke();
    this.doc.y += 1;
  }

  /**
   * Section heading with its explanatory line.
   *
   * The subtitle is not decoration. Every section of this report is a count that
   * could be misread as something stronger than it is, and the one place a reader
   * is guaranteed to look is directly under the heading.
   */
  heading(text: string, subtitle?: string): void {
    // Enough room for the heading, its subtitle, and the first two rows of
    // whatever follows — a heading stranded at the foot of a page is worse than
    // an early break.
    this.ensureSpace(subtitle ? 78 : 62);
    this.doc
      .font("Helvetica-Bold")
      .fontSize(12)
      .fillColor(COLOR.text)
      .text(text, MARGIN, this.doc.y, { width: CONTENT_WIDTH });
    if (subtitle) {
      this.doc.moveDown(0.25);
      this.doc
        .font("Helvetica")
        .fontSize(8)
        .fillColor(COLOR.muted)
        .text(subtitle, MARGIN, this.doc.y, { width: CONTENT_WIDTH, lineGap: 1 });
    }
    this.gap(6);
  }

  paragraph(text: string, opts: { color?: string; size?: number } = {}): void {
    this.ensureSpace(30);
    this.doc
      .font("Helvetica")
      .fontSize(opts.size ?? 9)
      .fillColor(opts.color ?? COLOR.text)
      .text(text, MARGIN, this.doc.y, { width: CONTENT_WIDTH, lineGap: 1.5 });
  }

  /** "Nothing to report" — stated, never left as an empty gap under a heading. */
  emptyNote(text: string): void {
    this.ensureSpace(26);
    this.doc
      .font("Helvetica-Oblique")
      .fontSize(9)
      .fillColor(COLOR.faint)
      .text(text, MARGIN, this.doc.y, { width: CONTENT_WIDTH });
    this.gap(4);
  }
}

// ---------------------------------------------------------------------------
// primitives
// ---------------------------------------------------------------------------

export function fmt(value: number): string {
  return value.toLocaleString("en-US");
}

/**
 * Truncates text to fit `width` at the font and size currently set on `doc`.
 *
 * pdfkit's own `ellipsis` option is not dependable here. With `lineBreak: false`
 * it still breaks a platform summary at its middot separators, and the overflow
 * line lands on top of the next table row — a defect that reads as corrupted
 * output rather than as truncation. Measuring and cutting the string ourselves is
 * the only way to guarantee a single-line cell.
 *
 * Must be called after `font()` and `fontSize()`, since the measurement depends
 * on both.
 */
export function fit(doc: Doc, text: string, width: number): string {
  if (width <= 0) return "";
  if (doc.widthOfString(text) <= width) return text;

  const ellipsis = "…";
  if (doc.widthOfString(ellipsis) > width) return "";

  // Largest prefix length whose rendering, plus the ellipsis, still fits.
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (doc.widthOfString(text.slice(0, mid) + ellipsis) <= width) lo = mid;
    else hi = mid - 1;
  }
  return text.slice(0, lo).trimEnd() + ellipsis;
}

export function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  // Fixed en-GB style rather than the server's locale: a report archived on one
  // machine and read on another must not change meaning, and 11/08/2026 is
  // ambiguous in a way "11 Aug 2026" is not.
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

export function fmtDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${fmtDate(iso)}, ${d.toISOString().slice(11, 16)} UTC`;
}

/**
 * A row of large figures.
 *
 * Laid out on an explicit grid rather than with pdfkit's column support, so the
 * tiles line up across the two rows of the summary block.
 */
export function statRow(
  ctx: Layout,
  tiles: Array<{ label: string; value: string; note?: string; tone?: "warn" | "ok" }>,
): void {
  if (tiles.length === 0) return;
  const { doc } = ctx;
  const gutter = 8;
  const boxWidth = (CONTENT_WIDTH - gutter * (tiles.length - 1)) / tiles.length;
  const boxHeight = 52;

  ctx.ensureSpace(boxHeight + 8);
  const top = doc.y;

  tiles.forEach((tile, i) => {
    const x = MARGIN + i * (boxWidth + gutter);
    const inner = boxWidth - 16;
    doc.roundedRect(x, top, boxWidth, boxHeight, 3).lineWidth(0.5).strokeColor(COLOR.rule).stroke();

    doc.font("Helvetica").fontSize(6.5).fillColor(COLOR.faint);
    doc.text(fit(doc, tile.label.toUpperCase(), inner), x + 8, top + 7, {
      width: inner,
      characterSpacing: 0.4,
      lineBreak: false,
    });

    doc
      .font("Helvetica-Bold")
      .fontSize(15)
      .fillColor(tile.tone === "warn" ? COLOR.warn : tile.tone === "ok" ? COLOR.ok : COLOR.text);
    doc.text(fit(doc, tile.value, inner), x + 8, top + 18, { width: inner, lineBreak: false });

    if (tile.note) {
      doc.font("Helvetica").fontSize(6.5).fillColor(COLOR.muted);
      doc.text(fit(doc, tile.note, inner), x + 8, top + 38, { width: inner, lineBreak: false });
    }
  });

  // pdfkit leaves the cursor wherever the last `text` call ended, which is
  // partway up the box. Reset it below the whole row.
  doc.y = top + boxHeight + 10;
}

/**
 * Renders a table, breaking pages between rows and repeating the header.
 *
 * `lineBreak: false` with `ellipsis: true` on every cell is what keeps rows
 * exactly one line tall: a long purl or a 90-character image reference would
 * otherwise wrap and silently overlap the row beneath it.
 */
export function table<T>(ctx: Layout, columns: readonly Column<T>[], rows: readonly T[]): void {
  const { doc } = ctx;
  const rowHeight = 15;
  const headerHeight = 16;

  const widths = columns.map((c) => c.width * CONTENT_WIDTH);
  const xs = widths.reduce<number[]>((acc, w, i) => {
    acc.push(i === 0 ? MARGIN : acc[i - 1]! + widths[i - 1]!);
    return acc;
  }, []);

  function header(): void {
    ctx.ensureSpace(headerHeight + rowHeight * 2);
    const top = doc.y;
    doc.rect(MARGIN, top, CONTENT_WIDTH, headerHeight).fillColor(COLOR.headerFill).fill();
    columns.forEach((col, i) => {
      const cellWidth = widths[i]! - 10;
      doc.font("Helvetica-Bold").fontSize(7).fillColor(COLOR.muted);
      doc.text(fit(doc, col.header.toUpperCase(), cellWidth), xs[i]! + 5, top + 5, {
        width: cellWidth,
        align: col.align ?? "left",
        characterSpacing: 0.3,
        lineBreak: false,
      });
    });
    doc.y = top + headerHeight;
  }

  header();

  rows.forEach((row, index) => {
    // A break mid-table needs the header again on the new page, or the columns
    // downstream are unlabelled.
    if (doc.y + rowHeight > FOOTER_TOP) {
      doc.addPage();
      doc.y = MARGIN;
      header();
    }

    const top = doc.y;
    // Zebra striping instead of horizontal rules: with 15pt rows, rules read as
    // a grid and compete with the numbers for attention.
    if (index % 2 === 1) {
      doc.rect(MARGIN, top, CONTENT_WIDTH, rowHeight).fillColor("#fafafa").fill();
    }

    columns.forEach((col, i) => {
      const cellWidth = widths[i]! - 10;
      doc
        .font(col.mono ? "Courier" : "Helvetica")
        .fontSize(col.mono ? 7.5 : 8)
        .fillColor(col.mono ? COLOR.muted : COLOR.text);
      doc.text(fit(doc, col.value(row, index), cellWidth), xs[i]! + 5, top + 4, {
        width: cellWidth,
        align: col.align ?? "left",
        lineBreak: false,
      });
    });

    doc.y = top + rowHeight;
  });

  doc
    .moveTo(MARGIN, doc.y)
    .lineTo(MARGIN + CONTENT_WIDTH, doc.y)
    .lineWidth(0.5)
    .strokeColor(COLOR.rule)
    .stroke();
  ctx.gap(12);
}

export function stampFooters(doc: Doc, title: string, generatedAt: string): void {
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    doc.page.margins.bottom = 0;

    doc
      .moveTo(MARGIN, FOOTER_TOP + 8)
      .lineTo(MARGIN + CONTENT_WIDTH, FOOTER_TOP + 8)
      .lineWidth(0.5)
      .strokeColor(COLOR.rule)
      .stroke();

    doc
      .font("Helvetica")
      .fontSize(7)
      .fillColor(COLOR.faint)
      .text(`${title} · generated ${fmtDateTime(generatedAt)}`, MARGIN, FOOTER_TOP + 14, {
        width: CONTENT_WIDTH * 0.7,
        lineBreak: false,
        ellipsis: true,
      })
      .text(`Page ${i + 1} of ${range.count}`, MARGIN + CONTENT_WIDTH * 0.7, FOOTER_TOP + 14, {
        width: CONTENT_WIDTH * 0.3,
        align: "right",
        lineBreak: false,
      });
  }
}
