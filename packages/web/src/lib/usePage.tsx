import { useEffect, useMemo, useState } from "react";

/** Rows per page on the Analytics and Inventory tables. */
export const TABLE_PAGE_SIZE = 20;

export interface Paged<T> {
  rows: T[];
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  setPage: (page: number) => void;
}

/**
 * One page of rows that are already sorted and filtered, so sorting and filters apply to every
 * row and paging only decides which twenty are drawn. Goes back to page 1 when the rows change
 * (a new sort, a new filter), since the old page number then means nothing.
 */
export function usePage<T>(all: readonly T[], pageSize = TABLE_PAGE_SIZE): Paged<T> {
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(all.length / pageSize));
  // Keyed on what the rows are, not on the array itself: a list filtered inline is a new array
  // on every render, and resetting on identity would throw the reader back to page 1 each time.
  useEffect(() => setPage(1), [all.length, all[0], all[all.length - 1]]);
  const current = Math.min(page, totalPages);
  const rows = useMemo(() => all.slice((current - 1) * pageSize, current * pageSize), [all, current, pageSize]);
  return { rows, page: current, totalPages, total: all.length, pageSize, setPage };
}

/** The page numbers to show: always the first and last, and two either side of the current one. */
export function pageNumbers(page: number, totalPages: number): Array<number | "…"> {
  const wanted = new Set([1, totalPages, page - 2, page - 1, page, page + 1, page + 2]);
  const list = [...wanted].filter((n) => n >= 1 && n <= totalPages).sort((a, b) => a - b);
  const out: Array<number | "…"> = [];
  list.forEach((n, i) => {
    if (i > 0 && n - list[i - 1]! > 1) out.push("…");
    out.push(n);
  });
  return out;
}

/** Previous, page numbers, next - under a table. Nothing when everything fits on one page. */
export function PageNumbers<T>({ paged }: { paged: Paged<T> }) {
  if (paged.totalPages <= 1) return null;
  const first = (paged.page - 1) * paged.pageSize + 1;
  const last = Math.min(paged.page * paged.pageSize, paged.total);
  const button = (active: boolean) =>
    `nums min-w-7 rounded px-2 py-1 text-xs ${
      active ? "bg-accent font-semibold text-white" : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
    }`;
  return (
    <nav aria-label="Pages" className="flex flex-wrap items-center justify-between gap-2 border-t border-border-base px-4 py-2">
      <span className="nums text-xs text-text-muted">
        {first}-{last} of {paged.total}
      </span>
      <span className="flex items-center gap-1">
        <button type="button" className={button(false)} disabled={paged.page <= 1} onClick={() => paged.setPage(paged.page - 1)}>
          ← Previous
        </button>
        {pageNumbers(paged.page, paged.totalPages).map((n, i) =>
          n === "…" ? (
            <span key={`gap-${i}`} className="px-1 text-xs text-text-faint">…</span>
          ) : (
            <button
              key={n}
              type="button"
              aria-current={n === paged.page ? "page" : undefined}
              className={button(n === paged.page)}
              onClick={() => paged.setPage(n)}
            >
              {n}
            </button>
          ),
        )}
        <button
          type="button"
          className={button(false)}
          disabled={paged.page >= paged.totalPages}
          onClick={() => paged.setPage(paged.page + 1)}
        >
          Next →
        </button>
      </span>
    </nav>
  );
}
