import { sql, type SQL } from "drizzle-orm";
import type {
  ApplicationDetail,
  ApplicationStatus,
  ApplicationSummary,
  Attributes,
  ComponentRef,
  ListApplicationsQuery,
  ListScanComponentsQuery,
  Paginated,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { toScanPlatform, type PlatformRow } from "../ingestion/platform-row.js";

/**
 * Read side for applications.
 *
 * Written as tagged SQL rather than the query builder for the list and search
 * paths. Two reasons: the `count(*) OVER ()` total has no builder equivalent, and
 * the attribute filters must compile to jsonb containment (`@>`) to hit the GIN
 * index — a `->>` comparison silently degrades to a sequential scan over every
 * application, which is precisely the regression that is easy to introduce and
 * hard to notice.
 */
export class ApplicationsService {
  constructor(
    private readonly deps: { db: Database; config: Config },
  ) {}

  private get staleInterval(): SQL {
    return sql.raw(`interval '${this.deps.config.STALE_APP_THRESHOLD_DAYS} days'`);
  }

  async list(query: ListApplicationsQuery): Promise<Paginated<ApplicationSummary>> {
    const { db } = this.deps;

    const conditions: SQL[] = [];

    /**
     * Default visibility: active plus pending_confirmation.
     *
     * Per the access model, unconfirmed applications are visible to every
     * authenticated user — a scan arriving for an unknown repo should be
     * discoverable immediately, not hidden until an admin gets to it. Inactive
     * apps are the ones that stay out of the way unless explicitly requested.
     */
    const statuses: ApplicationStatus[] = query.status ?? ["active", "pending_confirmation"];
    /**
     * Built as an explicit `IN (...)` bind list rather than `= ANY($1::text[])`.
     *
     * Drizzle expands a JS array inside a `sql` template into a tuple — `($1,
     * $2)` — not a single array parameter, so the array form fails at runtime
     * with "cannot cast type record to text[]". One bind per value sidesteps the
     * ambiguity and does not depend on how the driver serialises arrays.
     */
    const statusList = sql.join(
      statuses.map((s) => sql`${s}`),
      sql`, `,
    );
    conditions.push(sql`a.status IN (${statusList})`);

    if (query.search) {
      // Name search only; component search is a separate, indexed endpoint.
      conditions.push(sql`a.name ILIKE ${"%" + query.search + "%"}`);
    }

    // Attribute filters as jsonb containment so the GIN index applies.
    for (const [key, value] of [
      ["squad", query.squad],
      ["owner", query.owner],
      ["severity", query.severity],
    ] as const) {
      if (value) {
        conditions.push(sql`a.attributes @> ${JSON.stringify({ [key]: value })}::jsonb`);
      }
    }

    /**
     * Platform filters, matched against the CURRENT build via the join to
     * `latest_scan_id` below. This is the "which applications are still on
     * Debian 11 or Node 18" query.
     */
    if (query.os) {
      conditions.push(sql`lower(s.os_name) = lower(${query.os})`);
    }
    if (query.osVersion) {
      // Prefix match, so `3.20` finds `3.20.3`. Distro versions carry a patch
      // component that nobody filtering by "Alpine 3.20" wants to type.
      conditions.push(sql`s.os_version LIKE ${query.osVersion + "%"}`);
    }
    if (query.runtime) {
      /**
       * jsonb containment, not `->>`. The runtimes column is an ARRAY of
       * objects, and `@>` with a single-element array asks "does this array
       * contain an element with these fields" — which is both correct and the
       * only form the GIN index on the column can serve. Extracting an element
       * by position would also silently miss an image with two runtimes.
       */
      const probe = query.runtimeVersion
        ? [{ name: query.runtime.toLowerCase(), version: query.runtimeVersion }]
        : [{ name: query.runtime.toLowerCase() }];
      conditions.push(sql`s.runtimes @> ${JSON.stringify(probe)}::jsonb`);
    }

    if (query.staleOnly) {
      conditions.push(sql`a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${this.staleInterval}`);
    }

    const where = sql.join([sql`WHERE `, sql.join(conditions, sql` AND `)]);

    const orderBy = this.orderByClause(query.sortBy, query.sortDir);
    const limit = query.pageSize;
    const offset = offsetOf(query);

    const rows = await db.execute<Row<ApplicationListRow>>(sql`
      SELECT
        a.id,
        a.name,
        a.status,
        a.attributes,
        a.latest_scan_id,
        a.last_scan_at,
        a.scan_count,
        a.created_at,
        s.component_count AS latest_component_count,
        s.os_name, s.os_version, s.os_pretty, s.runtimes,
        (a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${this.staleInterval}) AS is_stale,
        count(*) OVER () AS total
      FROM application a
      LEFT JOIN scan s ON s.id = a.latest_scan_id
      ${where}
      ${orderBy}
      LIMIT ${limit} OFFSET ${offset}
    `);

    const items = rowsOf(rows).map(toApplicationSummary);
    return paginate(items, totalFromRows(rowsOf(rows)), query);
  }

  /**
   * Sort clause.
   *
   * Built from a closed set of literals rather than interpolating the incoming
   * value — the column name cannot be parameterised, so a whitelist is the only
   * safe construction. `sortBy` is already constrained by the Zod schema; this is
   * the second line of defence that survives someone widening that enum later.
   */
  private orderByClause(sortBy: ListApplicationsQuery["sortBy"], dir: "asc" | "desc"): SQL {
    const direction = dir === "desc" ? sql.raw("DESC") : sql.raw("ASC");
    switch (sortBy) {
      case "createdAt":
        return sql`ORDER BY a.created_at ${direction}, a.name ASC`;
      case "lastScanAt":
        // NULLS LAST in both directions: a never-scanned application is not
        // "the oldest scan", it is the absence of one, and burying it at the
        // bottom is what a reader expects either way.
        return sql`ORDER BY a.last_scan_at ${direction} NULLS LAST, a.name ASC`;
      case "status":
        return sql`ORDER BY a.status ${direction}, a.name ASC`;
      case "name":
      default:
        // Case-insensitive, so `Zebra` does not sort before `apple`.
        return sql`ORDER BY lower(a.name) ${direction}`;
    }
  }

  async getById(id: string): Promise<ApplicationDetail> {
    const { db } = this.deps;

    const rows = await db.execute<Row<ApplicationListRow & { aliases: string[] | null; updated_at: Date }>>(sql`
      SELECT
        a.id,
        a.name,
        a.status,
        a.attributes,
        a.latest_scan_id,
        a.last_scan_at,
        a.scan_count,
        a.created_at,
        a.updated_at,
        s.component_count AS latest_component_count,
        s.os_name, s.os_version, s.os_pretty, s.runtimes,
        (a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${this.staleInterval}) AS is_stale,
        COALESCE(
          (SELECT array_agg(al.alias_name ORDER BY al.alias_name)
           FROM application_alias al WHERE al.application_id = a.id),
          ARRAY[]::text[]
        ) AS aliases
      FROM application a
      LEFT JOIN scan s ON s.id = a.latest_scan_id
      WHERE a.id = ${id}::uuid
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Application");

    return {
      ...toApplicationSummary(row),
      aliases: row.aliases ?? [],
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }

  /**
   * Components of the application's current state.
   *
   * Resolves `latest_scan_id` and delegates, so "current dependencies" and
   * "dependencies of scan X" run the identical query and cannot disagree.
   */
  async listLatestComponents(
    applicationId: string,
    query: ListScanComponentsQuery,
  ): Promise<Paginated<ComponentRef> & { scanId: string | null }> {
    const { db } = this.deps;

    const appRows = await db.execute<Row<{ latest_scan_id: string | null }>>(sql`
      SELECT latest_scan_id FROM application WHERE id = ${applicationId}::uuid
    `);
    const app = rowsOf(appRows)[0];
    if (!app) throw new NotFoundError("Application");

    if (!app.latest_scan_id) {
      // Pre-registered but never scanned. An empty page is the honest answer;
      // a 404 would wrongly imply the application does not exist.
      return { ...paginate<ComponentRef>([], 0, query), scanId: null };
    }

    const page = await this.listComponentsOfScan(app.latest_scan_id, query);
    return { ...page, scanId: app.latest_scan_id };
  }

  /** Shared by the current-state view and the historical-scan view. */
  async listComponentsOfScan(
    scanId: string,
    query: ListScanComponentsQuery,
  ): Promise<Paginated<ComponentRef>> {
    const { db } = this.deps;

    const conditions: SQL[] = [sql`sc.scan_id = ${scanId}::uuid`];

    if (query.search) {
      // A single scan is a bounded set (thousands, not millions), so a plain
      // ILIKE is the right tool here — the trigram index exists for the global
      // search that spans every component in the organisation.
      conditions.push(sql`c.name ILIKE ${"%" + query.search + "%"}`);
    }
    if (query.ecosystem) {
      conditions.push(sql`c.ecosystem = ${query.ecosystem}`);
    }

    const where = sql.join([sql`WHERE `, sql.join(conditions, sql` AND `)]);
    const direction = query.sortDir === "desc" ? sql.raw("DESC") : sql.raw("ASC");
    const orderBy =
      query.sortBy === "version"
        ? sql`ORDER BY c.version ${direction} NULLS LAST, lower(c.name) ASC`
        : query.sortBy === "ecosystem"
          ? sql`ORDER BY c.ecosystem ${direction}, lower(c.name) ASC`
          : sql`ORDER BY lower(c.name) ${direction}, c.version ASC NULLS LAST`;

    const rows = await db.execute<Row<ComponentQueryRow>>(sql`
      SELECT c.id, c.name, c.version, c.ecosystem, c.purl, count(*) OVER () AS total
      FROM scan_component sc
      JOIN component c ON c.id = sc.component_id
      ${where}
      ${orderBy}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    return paginate(rowsOf(rows).map(toComponentRef), totalFromRows(rowsOf(rows)), query);
  }

  /** Distinct ecosystems present in a scan, for the filter dropdown. */
  async listEcosystemsOfScan(scanId: string): Promise<Array<{ ecosystem: string; count: number }>> {
    const rows = await this.deps.db.execute<Row<{ ecosystem: string; count: number }>>(sql`
      SELECT c.ecosystem, count(*)::int AS count
      FROM scan_component sc
      JOIN component c ON c.id = sc.component_id
      WHERE sc.scan_id = ${scanId}::uuid
      GROUP BY c.ecosystem
      ORDER BY count DESC, c.ecosystem ASC
    `);
    return rowsOf(rows).map((r) => ({ ecosystem: r.ecosystem, count: Number(r.count) }));
  }

  /** Distinct attribute values across all applications, for filter dropdowns. */
  async listAttributeValues(key: string): Promise<string[]> {
    // `key` reaches SQL as a bind parameter, never interpolated.
    const rows = await this.deps.db.execute<Row<{ value: string }>>(sql`
      SELECT DISTINCT a.attributes ->> ${key} AS value
      FROM application a
      WHERE a.attributes ? ${key} AND a.attributes ->> ${key} <> ''
      ORDER BY value ASC
      LIMIT 500
    `);
    return rowsOf(rows)
      .map((r) => r.value)
      .filter((v): v is string => v !== null);
  }
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

/**
 * Drizzle's `execute<T>` constrains T to `Record<string, unknown>`, which a plain
 * interface does not satisfy without an index signature. This adds one without
 * polluting the row interfaces themselves — they stay precise for consumers.
 */
export type Row<T> = T & Record<string, unknown>;

/**
 * Normalises the driver's result shape.
 *
 * `db.execute` on node-postgres resolves to a pg QueryResult (`{ rows }`), but
 * other drizzle drivers return a bare array. Typing the parameter as the union
 * rather than `unknown` is what lets callers write `rowsOf(result)` and keep full
 * type inference on the row.
 */
export function rowsOf<T>(result: { rows: T[] } | T[]): T[] {
  return Array.isArray(result) ? result : result.rows;
}

interface ApplicationListRow extends PlatformRow {
  id: string;
  name: string;
  status: ApplicationStatus;
  attributes: Attributes | null;
  latest_scan_id: string | null;
  last_scan_at: Date | string | null;
  scan_count: number | string;
  created_at: Date | string;
  latest_component_count: number | string | null;
  is_stale: boolean;
  total?: number | string;
}

interface ComponentQueryRow {
  id: number | string;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
  total?: number | string;
}

function toIso(value: Date | string | null): string | null {
  if (value === null) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toApplicationSummary(row: ApplicationListRow): ApplicationSummary {
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    attributes: row.attributes ?? {},
    latestScanId: row.latest_scan_id,
    lastScanAt: toIso(row.last_scan_at),
    latestComponentCount:
      row.latest_component_count === null || row.latest_component_count === undefined
        ? null
        : Number(row.latest_component_count),
    scanCount: Number(row.scan_count),
    isStale: row.is_stale === true,
    createdAt: toIso(row.created_at)!,
    // Null when the application has never been scanned. Distinct from a scan
    // whose SBOM revealed no platform, which yields an object of nulls — a
    // scratch image is not the same as no data.
    platform: row.latest_scan_id === null ? null : toScanPlatform(row),
  };
}

function toComponentRef(row: ComponentQueryRow): ComponentRef {
  return {
    // bigint ids cross the wire as strings so they survive JSON round-tripping
    // regardless of how large the component table eventually grows.
    id: String(row.id),
    name: row.name,
    version: row.version,
    ecosystem: row.ecosystem,
    purl: row.purl,
  };
}

export { toIso };
