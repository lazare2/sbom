import { z } from "zod";

/**
 * Table sorting, defined once per table and consumed by both ends.
 *
 * The API needs the set of sortable fields to validate `sortBy` against — a sort column
 * arriving from the client is interpolated into an ORDER BY, so an unvalidated one is an
 * injection. The web needs the same set to decide which headers are clickable, plus each
 * column's kind to decide which direction its first click sorts.
 *
 * Declaring that in one place is the point. Two copies drift, and the failure is quiet:
 * a header that looks clickable, sorts nothing, and reports no error because the API
 * silently fell back to its default ordering.
 */

export const sortDirections = ["asc", "desc"] as const;
export type SortDirection = (typeof sortDirections)[number];

/**
 * What a column holds, which is all that is needed to pick a sensible first click.
 *
 * Names read naturally A→Z, while counts and timestamps are almost always asked about
 * from the top — "which application has the most findings", "what came in most recently".
 * Making the first click land on the useful end means the common question takes one click
 * rather than two.
 */
export type SortColumnKind = "text" | "number" | "date";

export function firstDirectionFor(kind: SortColumnKind): SortDirection {
  return kind === "text" ? "asc" : "desc";
}

export interface SortTable<F extends string> {
  /** Every sortable field, in declaration order. */
  readonly fields: readonly F[];
  readonly kind: Readonly<Record<F, SortColumnKind>>;
  readonly defaultField: F;
  readonly defaultDirection: SortDirection;
  /** The direction a first click on this column should choose. */
  firstDirectionFor(field: F): SortDirection;
  /** Narrows an untrusted value — a URL parameter, say — to a known field. */
  isField(value: unknown): value is F;
  /**
   * `{ sortBy, sortDir }` with defaults applied, to be spread into a query schema.
   *
   * Defaults rather than optionals: every list query has *some* order, so the resolved
   * value is always meaningful and no caller has to decide what `undefined` means.
   */
  readonly querySchema: z.ZodObject<{
    sortBy: z.ZodDefault<z.ZodEnum<[F, ...F[]]>>;
    sortDir: z.ZodDefault<z.ZodEnum<["asc", "desc"]>>;
  }>;
}

/**
 * Declares a table's sortable columns.
 *
 * `defaultDirection` defaults to the default field's natural direction, so a table whose
 * default sort is a timestamp lands on newest-first without restating it.
 */
export function defineSortTable<K extends Record<string, SortColumnKind>>(
  // Inferred from this object's keys, not from `defaultField` — a single literal there
  // would narrow the field union to that one name and reject every other column.
  kind: K,
  defaultField: keyof K & string,
  defaultDirection?: SortDirection,
): SortTable<keyof K & string> {
  type F = keyof K & string;
  /*
    `K extends Record<string, SortColumnKind>` keeps an index signature in scope, so under
    noUncheckedIndexedAccess every lookup would widen to `| undefined`. Re-viewing it as a
    mapped type over the literal key union removes the index signature, and with it the
    phantom undefined — the keys are exactly F by construction.
  */
  const kinds = kind as unknown as Record<F, SortColumnKind>;
  const fields = Object.keys(kind) as F[];
  if (fields.length === 0) throw new Error("a sort table needs at least one field");
  if (!fields.includes(defaultField)) {
    throw new Error(`default sort field ${defaultField} is not one of: ${fields.join(", ")}`);
  }

  const resolvedDirection = defaultDirection ?? firstDirectionFor(kinds[defaultField]);
  const fieldSet = new Set<string>(fields);

  return {
    fields,
    kind: kinds,
    defaultField,
    defaultDirection: resolvedDirection,
    firstDirectionFor: (field) => firstDirectionFor(kinds[field]),
    isField: (value): value is F => typeof value === "string" && fieldSet.has(value),
    querySchema: z.object({
      sortBy: z.enum(fields as [F, ...F[]]).default(defaultField),
      sortDir: z.enum(sortDirections).default(resolvedDirection),
    }),
  };
}

/** The resolved sort on a query, once defaults have been applied. */
export interface SortState<F extends string> {
  sortBy: F;
  sortDir: SortDirection;
}

/**
 * Client-side sort for tables the API returns whole.
 *
 * Only for full result sets. Sorting one page of a server-paginated table reorders the
 * rows on screen and nothing else, which reads as a broken control rather than a limited
 * one.
 *
 * `null` and `undefined` sort last in both directions rather than being treated as
 * smallest. "No last scan" is absent data, not the oldest date, and floating it to the
 * top of a descending sort would be actively misleading.
 */
export function sortRows<T>(
  rows: readonly T[],
  valueOf: (row: T) => string | number | Date | null | undefined,
  direction: SortDirection,
  tiebreak?: (row: T) => string | number,
): T[] {
  const factor = direction === "asc" ? 1 : -1;

  return [...rows].sort((a, b) => {
    const av = valueOf(a);
    const bv = valueOf(b);

    const aMissing = av === null || av === undefined || av === "";
    const bMissing = bv === null || bv === undefined || bv === "";
    if (aMissing && bMissing) return compareTiebreak(a, b, tiebreak);
    if (aMissing) return 1;
    if (bMissing) return -1;

    const primary = compareValues(av, bv);
    if (primary !== 0) return primary * factor;

    /*
      Ties broken by a stable secondary key so equal rows keep a fixed order. Array#sort
      is stable in modern engines, but the incoming row order is the server's, which
      changes as data changes — without this, two rows with the same value can swap places
      between renders for no visible reason.
    */
    return compareTiebreak(a, b, tiebreak);
  });
}

function compareTiebreak<T>(a: T, b: T, tiebreak?: (row: T) => string | number): number {
  if (!tiebreak) return 0;
  return compareValues(tiebreak(a), tiebreak(b));
}

function compareValues(a: string | number | Date, b: string | number | Date): number {
  if (a instanceof Date || b instanceof Date) {
    return Number(a instanceof Date ? a.getTime() : a) - Number(b instanceof Date ? b.getTime() : b);
  }
  if (typeof a === "number" && typeof b === "number") return a - b;

  /*
    `numeric` so version-ish and count-ish text sorts the way a reader expects: without
    it "10" sorts before "9", and a package list ordered 1, 10, 2, 20, 3 looks broken.
    `sensitivity: "base"` makes it case-insensitive, so "Express" and "express" sit
    together instead of all capitals sorting ahead of all lowercase.
  */
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
}
