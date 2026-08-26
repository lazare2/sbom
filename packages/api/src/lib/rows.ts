/**
 * Result-shape helpers for raw `db.execute` queries.
 *
 * Lives here rather than in applications.service, which is where it grew, because
 * environment.service needs it too -- and applications.service needs environment.service for
 * its scope filters. Importing across those two directly is a cycle, and a cycle between
 * modules that both run at startup is the kind of fault that shows up as an undefined
 * function long after the edit that caused it.
 */

/**
 * Drizzle's `execute<T>` constrains T to `Record<string, unknown>`, which a plain
 * interface does not satisfy without an index signature. This adds one without
 * polluting the row interfaces themselves -- they stay precise for consumers.
 */
export type Row<T> = T & Record<string, unknown>;

/**
 * Normalises the driver's result shape.
 *
 * `db.execute` on node-postgres resolves to a pg QueryResult (`{ rows }`), but other drizzle
 * drivers return a bare array. Typing the parameter as the union rather than `unknown` is
 * what lets callers write `rowsOf(result)` and keep full type inference on the row.
 */
export function rowsOf<T>(result: { rows: T[] } | T[]): T[] {
  return Array.isArray(result) ? result : result.rows;
}
