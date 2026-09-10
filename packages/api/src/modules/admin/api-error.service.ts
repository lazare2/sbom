import { sql, type SQL } from "drizzle-orm";
import type {
  ApiErrorEntry,
  ApiErrorLogSummary,
  ListApiErrorsQuery,
  Paginated,
  SortDirection,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { apiError } from "../../db/schema.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";

/**
 * How long a failure stays readable.
 *
 * Long enough to cover "it broke on Friday and I am looking on Monday", short enough that a
 * pipeline stuck in a retry loop cannot fill a disk. Not configurable: another setting on the
 * configuration screen buys very little here, and the wrong value is silently expensive.
 */
export const ERROR_LOG_RETENTION_DAYS = 14;

/** How often the retention sweep is allowed to run, however many errors arrive. */
const PRUNE_INTERVAL_MS = 60 * 60_000;

/**
 * Field and query-parameter names whose value is never safe to keep.
 *
 * Matched as a substring against a lowercased name, so `apiToken`, `smtpPassword` and
 * `SECRETS_KEY` are all caught. Deliberately broad: the cost of redacting a field that was
 * harmless is a slightly less useful log line, and the cost of missing one is a table of
 * credentials that nobody knew they were writing.
 */
const SECRET_NAME_PARTS = ["token", "password", "secret", "credential", "apikey", "api_key", "auth"];

function looksSecret(name: string): boolean {
  const lower = name.toLowerCase();
  return SECRET_NAME_PARTS.some((part) => lower.includes(part));
}

/**
 * Strip anything a message might have quoted back.
 *
 * Redaction is by field *name*, not by inspecting the value, because the shapes arriving here
 * are more varied than they first appear. `parseOrThrow` maps an issue path to a message, but
 * `ConflictError` also carries structured details -- the duplicate-SBOM refusal passes the
 * existing scan's id, timestamp, build number and whether it is the latest -- and any error
 * raised later may carry something else again. Matching on the name holds regardless of what
 * a future caller decides to attach, which matching on the value would not.
 *
 * Scalars are stringified rather than dropped. Dropping them silently loses real detail: the
 * duplicate refusal's `existingIsLatest` is a boolean, and it vanished from the log entirely
 * until this was noticed on screen. Nested objects and nulls still go, because a shape nobody
 * reasoned about is a shape that should not be stored.
 */
export function redactDetails(
  details: unknown,
): Record<string, string[]> | null {
  if (!details || typeof details !== "object" || Array.isArray(details)) return null;

  /** One value from a details payload, as a line of text, or null if it is not one. */
  const asLine = (v: unknown): string | null => {
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    return null;
  };

  const out: Record<string, string[]> = {};
  for (const [field, value] of Object.entries(details as Record<string, unknown>)) {
    const messages = (Array.isArray(value) ? value : [value])
      .map(asLine)
      .filter((v): v is string => v !== null);
    if (messages.length === 0) continue;
    // The field *name* is the useful half and is safe -- it is what the screen labels.
    out[field] = looksSecret(field) ? ["(rejected; reason withheld because the field is a secret)"] : messages;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * Blank the value of any query parameter named like a secret.
 *
 * No endpoint takes a credential in the query string today -- ingest uses an Authorization
 * header -- but a URL is the one field here copied verbatim from the request, so it gets the
 * same treatment as the body.
 */
export function redactPath(path: string): string {
  const split = path.indexOf("?");
  if (split === -1) return path.slice(0, 500);

  const base = path.slice(0, split);
  const params = new URLSearchParams(path.slice(split + 1));
  let touched = false;
  for (const key of [...params.keys()]) {
    if (looksSecret(key)) {
      params.set(key, "REDACTED");
      touched = true;
    }
  }
  const query = touched ? params.toString() : path.slice(split + 1);
  return `${base}?${query}`.slice(0, 500);
}

/**
 * Sort clause for the error log.
 *
 * Every branch keeps `occurred_at DESC` as its secondary key: within one status or one path
 * the rows still read newest-first, which is the order the question is asked in. `id` is the
 * unique tail, because a burst of identical failures shares a timestamp.
 */
function errorOrderBy(sortBy: ListApiErrorsQuery["sortBy"], dir: SortDirection): SQL {
  const dir_ = direction(dir);
  const byNewest = sql`ae.occurred_at DESC`;

  switch (sortBy) {
    case "statusCode":
      return orderBy([sql`ae.status_code ${dir_}`, byNewest], sql`ae.id`);
    case "code":
      return orderBy([sql`ae.code ${dir_}`, byNewest], sql`ae.id`);
    case "path":
      return orderBy([sql`ae.path ${directionNullsLast(dir)}`, byNewest], sql`ae.id`);
    case "occurredAt":
    default:
      return orderBy([sql`ae.occurred_at ${dir_}`], sql`ae.id`);
  }
}

/**
 * The record of requests that failed.
 *
 * Exists because this platform is deployed on machines with no developer tooling. A screen
 * that says "Body validation failed" is not debuggable from a browser without a network tab,
 * and the server logged a status code and nothing else -- so the one piece of information
 * that would have resolved it, the name of the rejected field, was produced, serialised, sent
 * and then discarded at every layer that could have shown it.
 */
export class ApiErrorService {
  /** Wall clock of the last retention sweep. In memory: a missed prune costs nothing. */
  private lastPrunedAt = 0;

  constructor(private readonly deps: { db: Database }) {}

  /**
   * Record one failure. Never throws.
   *
   * Called from the error handler, which is the last thing standing between a failure and the
   * client. A logger that can turn a 400 into a crash, or into a request that never answers,
   * is worse than no logger -- so every failure here is swallowed, including the case where
   * the database is itself the reason the request failed.
   */
  async record(entry: {
    method: string;
    path: string;
    statusCode: number;
    code: string;
    message: string;
    details?: unknown;
    actor?: { id: string; email: string } | null;
  }): Promise<void> {
    try {
      await this.deps.db.insert(apiError).values({
        method: entry.method.slice(0, 10),
        path: redactPath(entry.path),
        statusCode: entry.statusCode,
        code: entry.code.slice(0, 64),
        message: entry.message.slice(0, 2000),
        details: redactDetails(entry.details),
        actorUserId: entry.actor?.id ?? null,
        actorEmail: entry.actor?.email ?? null,
      });
      await this.pruneIfDue();
    } catch {
      // Deliberately silent. Logging the logging failure through the same request that is
      // already failing produces two confusing errors where there was one.
    }
  }

  /** Delete rows past the retention window, at most once an hour. */
  private async pruneIfDue(): Promise<void> {
    const now = Date.now();
    if (now - this.lastPrunedAt < PRUNE_INTERVAL_MS) return;
    this.lastPrunedAt = now;
    await this.deps.db.execute(sql`
      DELETE FROM api_error
      WHERE occurred_at < now() - ${`${ERROR_LOG_RETENTION_DAYS} days`}::interval
    `);
  }

  async list(query: ListApiErrorsQuery): Promise<Paginated<ApiErrorEntry>> {
    const conditions: SQL[] = [sql`TRUE`];
    if (query.code) conditions.push(sql`ae.code = ${query.code}`);
    if (query.statusCode) conditions.push(sql`ae.status_code = ${query.statusCode}`);
    if (query.serverOnly) conditions.push(sql`ae.status_code >= 500`);
    if (query.path) {
      // Substring rather than prefix: the useful search is "everything under /xray", and the
      // interesting part of a path is rarely at its start.
      conditions.push(sql`ae.path ILIKE ${`%${query.path}%`}`);
    }

    const rows = await this.deps.db.execute<Row<ApiErrorRow>>(sql`
      SELECT
        ae.id, ae.occurred_at, ae.method, ae.path, ae.status_code,
        ae.code, ae.message, ae.details, ae.actor_user_id, ae.actor_email,
        count(*) OVER () AS total
      FROM api_error ae
      WHERE ${sql.join(conditions, sql` AND `)}
      ${errorOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const items = rowsOf(rows).map(
      (r): ApiErrorEntry => ({
        id: r.id,
        occurredAt: toIso(r.occurred_at)!,
        method: r.method,
        path: r.path,
        statusCode: Number(r.status_code),
        code: r.code,
        message: r.message,
        details: r.details ?? null,
        actorUserId: r.actor_user_id,
        actorEmail: r.actor_email,
      }),
    );

    return paginate(items, totalFromRows(rowsOf(rows)), query);
  }

  /**
   * The counts above the list.
   *
   * `oldestOccurredAt` is here so an empty log reads correctly. "No errors" and "errors are
   * not being recorded" look identical otherwise, and the first is the good news.
   */
  async summary(): Promise<ApiErrorLogSummary> {
    const rows = await this.deps.db.execute<Row<SummaryRow>>(sql`
      SELECT
        count(*)::int AS total,
        count(*) FILTER (WHERE status_code >= 500)::int AS server_errors,
        min(occurred_at) AS oldest
      FROM api_error
    `);
    const row = rowsOf(rows)[0];
    return {
      total: Number(row?.total ?? 0),
      serverErrors: Number(row?.server_errors ?? 0),
      retentionDays: ERROR_LOG_RETENTION_DAYS,
      oldestOccurredAt: toIso(row?.oldest ?? null),
    };
  }

  /** Empty the log. Returns how many rows went, which is what the audit row records. */
  async clear(): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ count: number | string }>>(sql`
      WITH removed AS (DELETE FROM api_error RETURNING 1)
      SELECT count(*)::int AS count FROM removed
    `);
    return Number(rowsOf(rows)[0]?.count ?? 0);
  }
}

interface ApiErrorRow {
  id: string;
  occurred_at: Date | string;
  method: string;
  path: string;
  status_code: number | string;
  code: string;
  message: string;
  details: Record<string, string[]> | null;
  actor_user_id: string | null;
  actor_email: string | null;
  total?: number | string;
}

interface SummaryRow {
  total: number | string;
  server_errors: number | string;
  oldest: Date | string | null;
}
