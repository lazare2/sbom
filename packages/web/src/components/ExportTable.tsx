import { createContext, useContext, useState, type ReactNode } from "react";
import { EXPANDABLE_LIST_CAP } from "@sbom/shared";
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
  options: { fullLists?: boolean } = {},
): Promise<FetchedRows<T>> {
  const get = (url: string) => (options.fullLists ? api.getFull<Paginated<T>>(url) : api.get<Paginated<T>>(url));
  const query = (page: number) =>
    `${path}${toQueryString({ ...params, page, pageSize: EXPORT_PAGE_SIZE })}`;

  const first = await get(query(1));
  const pageCount = Math.min(first.totalPages, Math.ceil(EXPORT_ROW_CAP / EXPORT_PAGE_SIZE));
  const pages: T[][] = [first.items];
  onProgress?.(first.items.length, first.total);

  let loaded = first.items.length;
  for (let start = 2; start <= pageCount; start += PARALLEL_PAGES) {
    const batch = [];
    for (let page = start; page < start + PARALLEL_PAGES && page <= pageCount; page++) {
      batch.push(get(query(page)));
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

// --- full lists ------------------------------------------------------------------------------

/**
 * Where a page's whole report can be fetched again with every list whole.
 *
 * Screens cut the lists inside a row ("payments-api, ledger-service and 30 more"); an export
 * should not be. A page that shows a report wraps its tables in this provider with a fetcher of
 * the same report with full lists, and every export button inside can then offer "full lists".
 */
const FullListsContext = createContext<(() => Promise<unknown>) | null>(null);

export function FullListsProvider({ fetchFull, children }: { fetchFull: () => Promise<unknown>; children: ReactNode }) {
  return <FullListsContext.Provider value={fetchFull}>{children}</FullListsContext.Provider>;
}

/** A row's identity without its lists: the same row in the cut and the full report. */
function withoutLists(value: unknown): unknown {
  if (Array.isArray(value)) return undefined;
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => !Array.isArray(v))
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, withoutLists(v)]),
    );
  }
  return value;
}
const identity = (value: unknown) => JSON.stringify(withoutLists(value));

/** Every object in a payload, by identity, so a screen row can find its full twin. */
function indexObjects(payload: unknown, into = new Map<string, unknown>()): Map<string, unknown> {
  if (Array.isArray(payload)) payload.forEach((v) => indexObjects(v, into));
  else if (payload && typeof payload === "object") {
    const key = identity(payload);
    if (!into.has(key)) into.set(key, payload);
    Object.values(payload as Record<string, unknown>).forEach((v) => indexObjects(v, into));
  }
  return into;
}

/** The row with its lists replaced by the full report's, wherever it (or a part of it) is found. */
function complete<T>(row: T, index: Map<string, unknown>): T {
  if (row && typeof row === "object" && !Array.isArray(row)) {
    const found = index.get(identity(row));
    if (found) return found as T;
    return Object.fromEntries(
      Object.entries(row as Record<string, unknown>).map(([k, v]) => [k, complete(v, index)]),
    ) as T;
  }
  return row;
}

/** Whether any list in the rows is at the screen's cap - which is when it may have been cut. */
function hasCutList(value: unknown): boolean {
  if (Array.isArray(value)) return value.length >= EXPANDABLE_LIST_CAP || value.some(hasCutList);
  if (value && typeof value === "object") return Object.values(value as Record<string, unknown>).some(hasCutList);
  return false;
}

export function ExportTableButton<T>({
  title,
  filename,
  columns,
  rows,
  pageRows,
  fetchRows,
  listsMayBeCut,
  size = "sm",
  label = "Export table",
}: {
  /** What the table is, for the workbook's info sheet: "Applications", "Audit log". */
  title: string;
  /** File name stem; the date and `.xlsx` are appended. */
  filename: string;
  columns: ExportColumn<T>[];
  rows?: readonly T[];
  /**
   * The rows on the page being shown, for a paged table. When it is fewer than `rows`, the reader
   * chooses: this page, or every row (the default) - sorted and filtered as on screen either way.
   */
  pageRows?: readonly T[];
  fetchRows?: (
    onProgress: (loaded: number, total: number) => void,
    options: { fullLists: boolean },
  ) => Promise<FetchedRows<T>>;
  /**
   * For `fetchRows` exports whose rows carry lists the server cuts for the screen: offer "full
   * lists" (fetched with X-List-Detail: full) or "as on screen".
   */
  listsMayBeCut?: boolean;
  size?: "sm" | "md";
  /** Button text, for a card that offers more than one export. */
  label?: string;
}) {
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const paged = pageRows !== undefined && rows !== undefined && pageRows.length < rows.length;
  const [which, setWhich] = useState<"all" | "page">("all");
  const fetchFull = useContext(FullListsContext);
  // Offered only where a list may actually have been cut; full is the default.
  const cut = fetchRows ? listsMayBeCut === true : fetchFull !== null && hasCutList(rows ?? []);
  const [lists, setLists] = useState<"full" | "screen">("full");

  const run = async () => {
    setError(null);
    setProgress("Exporting…");
    try {
      const full = cut && lists === "full";
      let fetched: FetchedRows<T> = fetchRows
        ? await fetchRows(
            (loaded, total) =>
              setProgress(`Exporting… ${Math.min(100, Math.round((loaded / Math.max(1, Math.min(total, EXPORT_ROW_CAP))) * 100))}%`),
            { fullLists: full },
          )
        : paged && which === "page"
          ? { rows: [...pageRows!], total: pageRows!.length }
          : { rows: [...(rows ?? [])], total: rows?.length ?? 0 };
      if (full && !fetchRows && fetchFull) {
        setProgress("Exporting… fetching full lists");
        const index = indexObjects(await fetchFull());
        fetched = { ...fetched, rows: fetched.rows.map((row) => complete(row, index)) };
      }

      const now = new Date();
      const capped = fetched.total > fetched.rows.length;
      const info: XlsxCell[][] = [
        ["Table", title],
        ["Exported at", now],
        ["Rows", fetched.rows.length],
        ...(paged ? [["Exported", which === "page" ? "the page on screen" : "every row"] as XlsxCell[]] : []),
        ...(cut
          ? [["Lists", lists === "full" ? "complete" : `as on screen: at most ${EXPANDABLE_LIST_CAP} names per cell`] as XlsxCell[]]
          : []),
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
      {cut ? (
        <select
          aria-label="Lists in the export"
          value={lists}
          onChange={(e) => setLists(e.target.value as "full" | "screen")}
          className="h-[26px] rounded-md border border-border-strong bg-bg-raised px-1 text-xs text-text-base"
          title={`On screen, lists in a cell stop at ${EXPANDABLE_LIST_CAP} names`}
        >
          <option value="full">Full lists</option>
          <option value="screen">Lists as on screen</option>
        </select>
      ) : null}
      {paged ? (
        <select
          aria-label="Rows to export"
          value={which}
          onChange={(e) => setWhich(e.target.value as "all" | "page")}
          className="h-[26px] rounded-md border border-border-strong bg-bg-raised px-1 text-xs text-text-base"
        >
          <option value="all">All {rows!.length} rows</option>
          <option value="page">This page ({pageRows!.length})</option>
        </select>
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
