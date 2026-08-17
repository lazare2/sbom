import type { Paginated } from "@sbom/shared";

export interface PageArgs {
  page: number;
  pageSize: number;
}

export function offsetOf(args: PageArgs): number {
  return (args.page - 1) * args.pageSize;
}

/**
 * Wraps a page of rows with its total.
 *
 * List queries obtain `total` via `count(*) OVER ()` in the same statement rather
 * than a second COUNT query: it keeps the filter predicate defined in exactly one
 * place, so the count can never drift from the rows it is counting.
 */
export function paginate<T>(items: T[], total: number, args: PageArgs): Paginated<T> {
  return {
    items,
    page: args.page,
    pageSize: args.pageSize,
    total,
    totalPages: args.pageSize > 0 ? Math.max(1, Math.ceil(total / args.pageSize)) : 1,
  };
}

/**
 * Reads the window-function total off the first row.
 *
 * An empty result set carries no window value at all, which correctly means a
 * total of zero.
 */
export function totalFromRows(rows: Array<{ total?: number | string | null }>): number {
  const raw = rows[0]?.total;
  if (raw === undefined || raw === null) return 0;
  return typeof raw === "number" ? raw : Number(raw);
}
