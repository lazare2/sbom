import { sql, type SQL } from "drizzle-orm";
import type { SortDirection } from "@sbom/shared";

/**
 * ORDER BY construction for sortable, paginated tables.
 *
 * Two rules, both enforced here rather than remembered at each call site.
 *
 * **A sort column is never interpolated from client input.** Column names cannot be
 * parameterised, so every service maps its validated `sortBy` through a `switch` over
 * literals. The Zod enum already constrains the value; the switch is the line of defence
 * that survives someone widening that enum without thinking about SQL.
 *
 * **Every ORDER BY ends in a unique column.** Without one, sorting on a column with
 * duplicate values leaves the order of tied rows up to the plan, and offset pagination
 * then genuinely loses data: the same row can appear on page 1 and page 2 while another
 * appears on neither. It is invisible in testing — you need ties *and* a page boundary
 * falling inside them — and it looks like a data bug rather than a sorting one. Hence
 * `orderBy` requiring the tiebreaker as a separate argument, so it cannot be forgotten by
 * omission.
 */

/** `ASC` / `DESC`, safe because it comes from a two-value union rather than a string. */
export function direction(dir: SortDirection): SQL {
  return dir === "desc" ? sql.raw("DESC") : sql.raw("ASC");
}

/**
 * `ASC NULLS LAST` / `DESC NULLS LAST`.
 *
 * For nullable columns, in both directions. Postgres defaults to NULLS LAST for ASC and
 * NULLS FIRST for DESC, which would float "never scanned" or "no fix available" to the
 * top of a descending sort as though it were the largest value. Absent data is not an
 * extreme value, and a reader scanning from the top wants rows that have data.
 */
export function directionNullsLast(dir: SortDirection): SQL {
  return dir === "desc" ? sql.raw("DESC NULLS LAST") : sql.raw("ASC NULLS LAST");
}

/**
 * Assembles the clause, appending the unique tiebreaker.
 *
 * @param keys       The chosen sort key, plus any secondary keys that make the result
 *                   read sensibly (name within a status, say).
 * @param tiebreaker A column unique across the result set — a primary key. Not optional:
 *                   see the note above on what its absence costs.
 */
export function orderBy(keys: SQL[], tiebreaker: SQL): SQL {
  return sql`ORDER BY ${sql.join([...keys, tiebreaker], sql`, `)}`;
}
