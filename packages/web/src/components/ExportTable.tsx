import { useState } from "react";
import {
  writeXlsx,
  XLSX_MIME,
  type ComponentLocation,
  type DeflateRaw,
  type Paginated,
  type SeverityCounts,
  type XlsxCell,
} from "@sbom/shared";
import { api, toQueryString } from "../lib/api.ts";
import { Button } from "./ui.tsx";

/**
 * "Export table": the table the reader is looking at, as an Excel workbook.
 *
 * ## What "as it is" means
 *
 * The rows on screen, in the order on screen, under the filters on screen. For a table the
 * API returns whole, that is exactly the array being rendered - already filtered and sorted.
 * For a paginated table it is NOT the fifty rows on the current page: it is every page of
 * the same query, fetched with the same filters and the same sort. Exporting one page of a
 * filtered list would hand somebody a file that silently answers a narrower question than the
 * screen did.
 *
 * Rows come from the same API calls the table makes, under the reader's own session and
 * environment, so an export can never contain anything its reader could not already see.
 *
 * ## Columns are declared, not scraped
 *
 * Each table states what its export columns are. Copying the rendered text would glue badges,
 * chips and links into one cell; a severity breakdown that reads well as four coloured
 * numbers is four columns in a spreadsheet, because the first thing anybody does with it is
 * sort by one of them.
 */

export interface ExportColumn<T> {
  header: string;
  value: (row: T) => XlsxCell;
  /** Excel character width. Defaults to 16. */
  width?: number;
}

/** An ISO timestamp from the API as a real date cell, so Excel can sort and filter on it. */
export function exportDate(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Several names in one cell, the way a reader would type them. */
export function exportList(values: readonly (string | null | undefined)[] | null | undefined): string {
  return (values ?? []).filter(Boolean).join(", ");
}

/** An application attribute as text. Absent stays empty rather than becoming the screen's " - ". */
export function attributeText(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  return Array.isArray(value) ? value.join(", ") : String(value);
}

/** Where a package sits in a build: its origin, install paths and immediate dependants. */
export function locationColumns<T>(locationOf: (row: T) => ComponentLocation): ExportColumn<T>[] {
  return [
    { header: "Origin", value: (r) => locationOf(r).origin, width: 12 },
    { header: "Paths", value: (r) => exportList(locationOf(r).paths), width: 50 },
    { header: "Pulled in by", value: (r) => exportList(locationOf(r).pulledInBy), width: 32 },
  ];
}

/** A build's Critical / High / Medium / Low counts as four sortable columns. */
export function severityColumns<T>(prefix: string, countsOf: (row: T) => SeverityCounts | null | undefined): ExportColumn<T>[] {
  return (["critical", "high", "medium", "low"] as const).map((level) => ({
    header: prefix ? `${prefix} ${level}` : level[0]!.toUpperCase() + level.slice(1),
    value: (r: T) => countsOf(r)?.[level] ?? null,
    width: Math.max(10, prefix.length + level.length + 2),
  }));
}

/**
 * The most rows one export will gather.
 *
 * A paginated export is one request per 200 rows, so this is 250 requests at most - long
 * enough for every real list here, short enough that a mistaken click on an unfiltered audit
 * log does not hammer the API for minutes. Hitting it is stated in the file, never silent.
 */
export const EXPORT_ROW_CAP = 50_000;

const EXPORT_PAGE_SIZE = 200;
const PARALLEL_PAGES = 4;

export interface FetchedRows<T> {
  rows: T[];
  /** How many rows matched, which exceeds `rows.length` only when the cap was hit. */
  total: number;
}

/**
 * Every page of a paginated list endpoint, with the caller's filters and sort.
 *
 * `page` and `pageSize` in `params` are replaced: the export walks the whole result at the
 * largest page size the API accepts.
 */
export async function fetchAllPages<T>(
  path: string,
  params: Record<string, unknown>,
  onProgress?: (loaded: number, total: number) => void,
): Promise<FetchedRows<T>> {
  const query = (page: number) =>
    `${path}${toQueryString({ ...params, page, pageSize: EXPORT_PAGE_SIZE })}`;

  const first = await api.get<Paginated<T>>(query(1));
  const pageCount = Math.min(first.totalPages, Math.ceil(EXPORT_ROW_CAP / EXPORT_PAGE_SIZE));
  const pages: T[][] = [first.items];
  onProgress?.(first.items.length, first.total);

  let loaded = first.items.length;
  for (let start = 2; start <= pageCount; start += PARALLEL_PAGES) {
    const batch = [];
    for (let page = start; page < start + PARALLEL_PAGES && page <= pageCount; page++) {
      batch.push(api.get<Paginated<T>>(query(page)));
    }
    for (const result of await Promise.all(batch)) {
      pages.push(result.items);
      loaded += result.items.length;
    }
    onProgress?.(loaded, first.total);
  }

  return { rows: pages.flat().slice(0, EXPORT_ROW_CAP), total: first.total };
}

/** The browser's own DEFLATE. Absent in old browsers, which then get an uncompressed file. */
const deflateRaw: DeflateRaw | undefined =
  typeof CompressionStream === "function"
    ? async (data) => {
        const stream = new Blob([data as BlobPart]).stream().pipeThrough(new CompressionStream("deflate-raw"));
        return new Uint8Array(await new Response(stream).arrayBuffer());
      }
    : undefined;

function stamp(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function download(bytes: Uint8Array, filename: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: XLSX_MIME }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoked on the next tick: some browsers start the download asynchronously.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * The export button.
 *
 * Pass `rows` for a table the API returned whole (already filtered and sorted, as rendered),
 * or `fetchRows` for a paginated one - usually `(p) => fetchAllPages(path, params, p)` with
 * the exact params the table's own query uses.
 */
export function ExportTableButton<T>({
  title,
  filename,
  columns,
  rows,
  fetchRows,
  size = "sm",
  label = "Export table",
}: {
  /** What the table is, for the workbook's info sheet: "Applications", "Audit log". */
  title: string;
  /** File name stem; the date and `.xlsx` are appended. */
  filename: string;
  columns: ExportColumn<T>[];
  rows?: readonly T[];
  fetchRows?: (onProgress: (loaded: number, total: number) => void) => Promise<FetchedRows<T>>;
  size?: "sm" | "md";
  /** Button text, for a card that offers more than one export. */
  label?: string;
}) {
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setError(null);
    setProgress("Exporting…");
    try {
      const fetched: FetchedRows<T> = fetchRows
        ? await fetchRows((loaded, total) =>
            setProgress(`Exporting… ${Math.min(100, Math.round((loaded / Math.max(1, Math.min(total, EXPORT_ROW_CAP))) * 100))}%`),
          )
        : { rows: [...(rows ?? [])], total: rows?.length ?? 0 };

      const now = new Date();
      const capped = fetched.total > fetched.rows.length;
      const info: XlsxCell[][] = [
        ["Table", title],
        ["Exported at", now],
        ["Rows", fetched.rows.length],
        ["Matching rows", fetched.total],
        ["View", window.location.href],
      ];
      if (capped) {
        info.push([
          "Note",
          `Only the first ${fetched.rows.length.toLocaleString()} of ${fetched.total.toLocaleString()} matching rows are included. Narrow the filters to export the rest.`,
        ]);
      }

      const bytes = await writeXlsx(
        [
          {
            name: title,
            columns: columns.map((c) => ({ header: c.header, width: c.width })),
            rows: fetched.rows.map((row) => columns.map((c) => c.value(row))),
          },
          {
            name: "Export info",
            columns: [{ header: "Field", width: 16 }, { header: "Value", width: 90 }],
            rows: info,
          },
        ],
        { deflateRaw },
      );
      download(bytes, `${filename}-${stamp(now)}.xlsx`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setProgress(null);
    }
  };

  return (
    <span className="inline-flex items-center gap-2">
      {error ? (
        <span className="text-[11px] text-danger" role="alert">
          Export failed: {error}
        </span>
      ) : null}
      <Button
        size={size}
        variant="secondary"
        onClick={() => void run()}
        disabled={progress !== null || (!fetchRows && (rows?.length ?? 0) === 0)}
        title="Download this table, with its current filters and sort, as an Excel workbook"
      >
        {progress ?? label}
      </Button>
    </span>
  );
}
