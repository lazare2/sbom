import { sql, type SQL } from "drizzle-orm";
import type {
  ApplicationDetail,
  ApplicationStatus,
  ApplicationSummary,
  ApplicationVulnCounts,
  Attributes,
  ComponentRef,
  ListApplicationsQuery,
  ListScanComponentsQuery,
  Paginated,
  SortDirection,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import type { SettingsService } from "../settings/settings.service.js";
import { NotFoundError } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
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
    private readonly deps: { db: Database; config: Config; settings: SettingsService },
  ) {}

  /**
   * Delegates to the settings service so the threshold has one definition.
   *
   * It used to read the environment directly, which made it a deployment constant. It is now
   * an administrator's setting, and three separate queries compare against it -- if they
   * resolved it independently the applications list could disagree with the overview about
   * which applications are stale.
   */
  private staleInterval(): Promise<SQL> {
    return this.deps.settings.staleInterval();
  }

  async list(query: ListApplicationsQuery): Promise<Paginated<ApplicationSummary>> {
    const { db } = this.deps;
    const staleInterval = await this.staleInterval();
    /*
      Read once per request, not per row. Findings are reported as null while scanning is off
      even though the summary rows survive being switched off: those counts were produced by
      a database of some unknown age, and presenting them as current after the feature was
      disabled would be stating a fact the platform is no longer checking.
    */
    const vulnEnabled = await this.deps.settings.vulnScanningEnabled();

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

    /*
      Membership filter. EXISTS rather than a join so an application in two of the selected
      group's overlapping sets still appears once — a join would emit it per matching row.
    */
    if (query.group) {
      conditions.push(sql`EXISTS (
        SELECT 1 FROM application_group_member gm
        WHERE gm.application_id = a.id AND gm.group_id = ${query.group}::uuid
      )`);
    }

    if (query.staleOnly) {
      conditions.push(sql`a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${staleInterval}`);
    }

    const where = sql.join([sql`WHERE `, sql.join(conditions, sql` AND `)]);

    const orderByClause = this.orderByClause(query);
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
        /*
          Group chips. A correlated aggregate rather than a join, for the same reason as the
          filter above: joining would multiply the row by its group count and break both the
          window-function total and the page size.
        */
        COALESCE(
          (SELECT json_agg(json_build_object('id', g.id, 'name', g.name) ORDER BY lower(g.name))
           FROM application_group_member gm
           JOIN application_group g ON g.id = gm.group_id
           WHERE gm.application_id = a.id),
          '[]'::json
        ) AS groups,
        s.os_name, s.os_version, s.os_pretty, s.runtimes,
        vs.app_findings, vs.os_findings,
        vs.app_critical, vs.os_critical,
        vs.app_high, vs.os_high,
        (a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${staleInterval}) AS is_stale,
        count(*) OVER () AS total
      FROM application a
      LEFT JOIN scan s ON s.id = a.latest_scan_id
      /*
        The frozen per-scan summary, not a live join over findings. One primary-key lookup
        per row against a table with one row per scan, where the alternative is joining
        millions of scan_component rows to produce a number that is already computed.

        LEFT because a summary row only exists once the scan has been matched against the
        database. Its absence is the "not assessed" state and is preserved as null rather
        than coalesced to zero.
      */
      LEFT JOIN scan_vuln_summary vs ON vs.scan_id = a.latest_scan_id
      ${where}
      ${orderByClause}
      LIMIT ${limit} OFFSET ${offset}
    `);

    const items = rowsOf(rows).map((row) => toApplicationSummary(row, vulnEnabled));
    return paginate(items, totalFromRows(rowsOf(rows)), query);
  }

  /**
   * Sort clause for the applications list.
   *
   * A `switch` over literals, not interpolation of the incoming value: see the notes in
   * lib/sorting.ts for why the column can never come from the client and why every branch
   * ends in `a.id`.
   */
  private orderByClause(query: ListApplicationsQuery): SQL {
    const { sortBy, sortDir: dir } = query;
    const dir_ = direction(dir);
    const nulls = directionNullsLast(dir);
    // Case-insensitive, so `Zebra` does not sort before `apple`.
    const byName = sql`lower(a.name) ASC`;

    switch (sortBy) {
      case "attribute": {
        /*
          The only sort whose target comes from the request. Safe because a jsonb key is a
          value: `sql.param` binds it, so it cannot become SQL. Falls back to name when no
          attribute was named rather than ordering by a null expression, which would make
          the whole sort a no-op and look like the header did nothing.
        */
        if (!query.sortAttribute) return orderBy([sql`lower(a.name) ${dir_}`], sql`a.id`);
        return orderBy(
          [sql`lower(a.attributes->>${sql.param(query.sortAttribute)}) ${nulls}`, byName],
          sql`a.id`,
        );
      }
      case "createdAt":
        return orderBy([sql`a.created_at ${dir_}`], sql`a.id`);
      case "lastScanAt":
        return orderBy([sql`a.last_scan_at ${nulls}`, byName], sql`a.id`);
      case "status":
        return orderBy([sql`a.status ${dir_}`, byName], sql`a.id`);
      case "platform":
        // Sorts on the current build's OS. Applications with no scan have no platform at
        // all, which is why this is nullable rather than an empty string.
        return orderBy([sql`s.os_pretty ${nulls}`, byName], sql`a.id`);
      case "componentCount":
        return orderBy([sql`s.component_count ${nulls}`, byName], sql`a.id`);
      case "vulnFindings":
        /*
          The combined total, matching what the column displays.

          NULLS LAST in both directions. An application whose current build has no summary row
          has not been assessed, and ranking it either first or last on a numeric scale would
          assert something the data does not support — so it sorts out of the way instead,
          exactly as `lastScanAt` treats "never scanned".

          Sorting on the sum does not use `scan_vuln_summary_rank_idx`, which is on
          `app_findings` alone. That is acceptable here and nowhere else: this query is already
          limited to one page of applications, of which there are hundreds rather than
          millions. A ranking over the whole findings table must still use the index.
        */
        return orderBy([sql`(vs.app_findings + vs.os_findings) ${nulls}`, byName], sql`a.id`);
      case "scanCount":
        return orderBy([sql`a.scan_count ${dir_}`, byName], sql`a.id`);
      case "name":
      default:
        return orderBy([sql`lower(a.name) ${dir_}`], sql`a.id`);
    }
  }

  async getById(id: string): Promise<ApplicationDetail> {
    const { db } = this.deps;
    const staleInterval = await this.staleInterval();

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
        /*
          Group chips. A correlated aggregate rather than a join, for the same reason as the
          filter above: joining would multiply the row by its group count and break both the
          window-function total and the page size.
        */
        COALESCE(
          (SELECT json_agg(json_build_object('id', g.id, 'name', g.name) ORDER BY lower(g.name))
           FROM application_group_member gm
           JOIN application_group g ON g.id = gm.group_id
           WHERE gm.application_id = a.id),
          '[]'::json
        ) AS groups,
        s.os_name, s.os_version, s.os_pretty, s.runtimes,
        vs.app_findings, vs.os_findings,
        vs.app_critical, vs.os_critical,
        vs.app_high, vs.os_high,
        (a.last_scan_at IS NOT NULL AND a.last_scan_at < now() - ${staleInterval}) AS is_stale,
        COALESCE(
          (SELECT array_agg(al.alias_name ORDER BY al.alias_name)
           FROM application_alias al WHERE al.application_id = a.id),
          ARRAY[]::text[]
        ) AS aliases
      FROM application a
      LEFT JOIN scan s ON s.id = a.latest_scan_id
      LEFT JOIN scan_vuln_summary vs ON vs.scan_id = a.latest_scan_id
      WHERE a.id = ${id}::uuid
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Application");

    return {
      ...toApplicationSummary(row, await this.deps.settings.vulnScanningEnabled()),
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

    const rows = await db.execute<Row<ComponentQueryRow>>(sql`
      SELECT c.id, c.name, c.version, c.ecosystem, c.purl, count(*) OVER () AS total
      FROM scan_component sc
      JOIN component c ON c.id = sc.component_id
      ${where}
      ${componentOrderBy(query.sortBy, query.sortDir)}
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

/**
 * Sort clause for a component list — a scan's inventory, or an application's history.
 *
 * Exported and shared by every component table rather than repeated per query: they are
 * the same columns over the same join, and one function is what stops the same header
 * sorting differently on two pages. `c.id` is the unique tail, since a package name
 * repeats across its versions.
 */
export function componentOrderBy(sortBy: ListScanComponentsQuery["sortBy"], dir: SortDirection): SQL {
  const dir_ = direction(dir);
  const nulls = directionNullsLast(dir);
  const byName = sql`lower(c.name) ASC, c.version ASC NULLS LAST`;

  switch (sortBy) {
    case "version":
      return orderBy([sql`c.version ${nulls}`, sql`lower(c.name) ASC`], sql`c.id`);
    case "ecosystem":
      return orderBy([sql`c.ecosystem ${dir_}`, byName], sql`c.id`);
    case "purl":
      return orderBy([sql`c.purl ${nulls}`, byName], sql`c.id`);
    case "name":
    default:
      return orderBy([sql`lower(c.name) ${dir_}`, sql`c.version ASC NULLS LAST`], sql`c.id`);
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
  /** Always an array — the aggregate coalesces to `[]` rather than null for an ungrouped app. */
  groups: Array<{ id: string; name: string }> | null;
  /*
    All six are null together when the current build has no summary row, which is the
    "not assessed" state. Typed as `number | string` because the driver returns integers
    as strings on some column types and every other count here is normalised the same way.
  */
  app_findings: number | string | null;
  os_findings: number | string | null;
  app_critical: number | string | null;
  os_critical: number | string | null;
  app_high: number | string | null;
  os_high: number | string | null;
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

/**
 * Findings of the current build, or null when the number is not known.
 *
 * Exported for the unit tests, which is the only way to reach it: the query it belongs to
 * needs a database, while the mapping from "no summary row" to "not assessed" is the part
 * that would break silently and is pure.
 *
 * The three null branches are deliberately not distinguished in the payload. A reader does
 * not act differently on "the sweep has not run yet" than on "scanning is off"; what matters
 * is that neither is reported as zero, because zero is a clean bill of health.
 */
export function toVulnCounts(
  row: Pick<
    ApplicationListRow,
    "app_findings" | "os_findings" | "app_critical" | "os_critical" | "app_high" | "os_high"
  >,
  vulnEnabled: boolean,
): ApplicationVulnCounts | null {
  if (!vulnEnabled) return null;
  // The whole row is absent or present together, so one column decides it.
  if (row.app_findings === null || row.app_findings === undefined) return null;

  const app = Number(row.app_findings);
  const os = Number(row.os_findings ?? 0);

  return {
    total: app + os,
    app,
    os,
    // Spanning both halves, to match `total`. A critical in the base image is still a
    // critical; which half it came from is what `app` and `os` are for.
    critical: Number(row.app_critical ?? 0) + Number(row.os_critical ?? 0),
    high: Number(row.app_high ?? 0) + Number(row.os_high ?? 0),
  };
}

function toApplicationSummary(row: ApplicationListRow, vulnEnabled: boolean): ApplicationSummary {
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
    vulnerabilities: toVulnCounts(row, vulnEnabled),
    groups: row.groups ?? [],
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
