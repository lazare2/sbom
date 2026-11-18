import { AsyncLocalStorage } from "node:async_hooks";
import { EXPANDABLE_LIST_CAP } from "@sbom/shared";
import { sql, type SQL } from "drizzle-orm";

/**
 * How long the lists inside a response may be.
 *
 * A screen shows the first EXPANDABLE_LIST_CAP names in a cell ("payments-api, ledger-service
 * and 30 more"), which keeps a table of hundreds of rows small. An export must not be cut like
 * that, so a request carrying `X-List-Detail: full` gets every name in every list - the same
 * query, only without the slice. Set per request in app.ts; read wherever a list is capped.
 */
const store = new AsyncLocalStorage<{ full: boolean }>();

/** Effectively no limit, kept as a number so the SQL keeps one shape. */
const FULL = 1_000_000;

export const LIST_DETAIL_HEADER = "x-list-detail";

export function runWithListDetail<T>(full: boolean, fn: () => T): T {
  return store.run({ full }, fn);
}

export function fullLists(): boolean {
  return store.getStore()?.full === true;
}

/** The cap for lists inside one row: EXPANDABLE_LIST_CAP on screen, everything for an export. */
export function listCap(): number {
  return fullLists() ? FULL : EXPANDABLE_LIST_CAP;
}

/** The same, for an array slice in SQL: `(array_agg(...))[1:${listCapSql()}]`. */
export function listCapSql(): SQL {
  return sql.raw(String(listCap()));
}

/** A larger cap (e.g. 500 applications on an advisory page), lifted the same way. */
export function capOr(screenCap: number): number {
  return fullLists() ? FULL : screenCap;
}
