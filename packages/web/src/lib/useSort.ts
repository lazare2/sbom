import { useCallback, useMemo, useState } from "react";
import {
  firstDirectionFor,
  sortRows,
  type SortColumnKind,
  type SortDirection,
  type SortTable,
} from "@sbom/shared";

/**
 * Column sorting for tables, in the two flavours the app needs.
 *
 * `useServerSort` drives a paginated query: the click changes `sortBy`/`sortDir` in the URL
 * and the server returns a differently ordered page. `useClientSort` reorders a full array
 * the API already returned whole.
 *
 * Which one a table needs is not a style preference. Sorting one page of a paginated
 * table in the browser reorders the 50 rows on screen and leaves the other 4,000 where they
 * were — the control looks like it works and silently answers a different question. So the
 * rule is: paginated means server-side, always.
 *
 * ## The click cycle
 *
 * Unsorted (`↕`) → first click sorts in the column's *natural* direction → second click
 * reverses → and it alternates from there. There is no third click back to unsorted,
 * because a table is always in some order; the neutral caret means "not sorting by this
 * column", not "unordered".
 *
 * Natural direction comes from the column's kind, declared once in the shared sort table:
 * text opens A→Z, numbers and dates open at the largest and newest. That is the click that
 * answers the question the column is usually opened for — "which application has the most
 * findings" wants the most, and "which package is this" wants the alphabet.
 */

export interface SortControl<F extends string> {
  sortBy: F;
  sortDir: SortDirection;
  /** Pass to `<Th onSort>`. Toggles direction on the active column, switches to any other. */
  toggle: (field: F) => void;
  /** Pass to `<Th sorted>`. `false` renders the neutral caret. */
  stateOf: (field: F) => SortDirection | false;
}

/**
 * Sort state for a server-paginated table.
 *
 * Takes the setter from `useUrlState` so the sort lives in the URL alongside the filters —
 * a sorted view is as worth pasting into a ticket as a filtered one.
 */
export function useServerSort<F extends string>(
  table: SortTable<F>,
  current: { sortBy: F; sortDir: SortDirection },
  setState: (patch: { sortBy?: F; sortDir?: SortDirection }) => void,
): SortControl<F> {
  const toggle = useCallback(
    (field: F) => {
      if (current.sortBy === field) {
        setState({ sortDir: current.sortDir === "asc" ? "desc" : "asc" });
      } else {
        // A new column starts in its natural direction rather than inheriting the previous
        // column's — carrying "descending" from a date onto a name column would answer
        // Z→A to a click that meant "sort by name".
        setState({ sortBy: field, sortDir: table.firstDirectionFor(field) });
      }
    },
    [current.sortBy, current.sortDir, setState, table],
  );

  const stateOf = useCallback(
    (field: F): SortDirection | false => (current.sortBy === field ? current.sortDir : false),
    [current.sortBy, current.sortDir],
  );

  return { sortBy: current.sortBy, sortDir: current.sortDir, toggle, stateOf };
}

/**
 * Sort state and sorted rows for a table the API returns in full.
 *
 * `valueOf` maps a field to the value to compare. It is given the field so one function
 * covers every column, which keeps the mapping next to the table it belongs to instead of
 * spread across per-column callbacks.
 *
 * `tiebreak` should be something unique per row — the id, or the name. Without it, rows
 * with equal values can swap position between renders as the underlying data changes.
 */
export function useClientSort<T, C extends Readonly<Record<string, SortColumnKind>>>(
  rows: readonly T[] | undefined,
  // The field union is inferred from these keys. Inferring it from `initial.sortBy` — a
  // single literal — would narrow it to that one name and reject every other column, the
  // same trap `defineSortTable` documents.
  columns: C,
  initial: { sortBy: keyof C & string; sortDir?: SortDirection },
  valueOf: (row: T, field: keyof C & string) => string | number | Date | null | undefined,
  tiebreak?: (row: T) => string | number,
): SortControl<keyof C & string> & { rows: T[] } {
  type F = keyof C & string;
  const kinds = columns as unknown as Record<F, SortColumnKind>;
  const [sortBy, setSortBy] = useState<F>(initial.sortBy);
  const [sortDir, setSortDir] = useState<SortDirection>(
    initial.sortDir ?? firstDirectionFor(kinds[initial.sortBy]),
  );

  const toggle = useCallback(
    (field: F) => {
      if (field === sortBy) {
        setSortDir(sortDir === "asc" ? "desc" : "asc");
      } else {
        setSortBy(field);
        setSortDir(firstDirectionFor(kinds[field]));
      }
    },
    [kinds, sortBy, sortDir],
  );

  const stateOf = useCallback(
    (field: F): SortDirection | false => (field === sortBy ? sortDir : false),
    [sortBy, sortDir],
  );

  const sorted = useMemo(
    () => (rows ? sortRows(rows, (row) => valueOf(row, sortBy), sortDir, tiebreak) : []),
    // `valueOf` and `tiebreak` are defined inline at every call site, so including them
    // would recompute on every render and defeat the memo. The field and direction are
    // what actually change the result.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [rows, sortBy, sortDir],
  );

  return { rows: sorted, sortBy, sortDir, toggle, stateOf };
}
