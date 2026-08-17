import { sql, type SQL } from "drizzle-orm";
import type {
  ComponentSearchHit,
  ComponentSearchQuery,
  ComponentSuggestion,
  ComponentSuggestQuery,
  Paginated,
  SortDirection,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";

/**
 * Upper bound on how many distinct `component` rows a single search will consider.
 *
 * A two-character substring search can match a very large slice of the component
 * table, and joining all of it against `scan_component` is what would turn a
 * typo into a table scan over the biggest table in the system. Capping the
 * matched set keeps the join bounded and lets the API tell the user their query
 * was too broad instead of just being slow.
 */
const MATCH_CAP = 2000;

export interface ComponentSearchResult extends Paginated<ComponentSearchHit> {
  /** True when the query matched more distinct packages than MATCH_CAP. */
  truncated: boolean;
  /** Distinct packages considered, for the "N packages across M apps" summary. */
  matchedComponents: number;
}

export class ComponentsService {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * Global cross-application package search.
   *
   * The query is a two-stage CTE, and the shape is deliberate:
   *
   *  1. `matched` narrows `component` by name first. That is the only stage that
   *     touches the text indexes — `component_name_lower_idx` for exact matches,
   *     the `pg_trgm` GIN index for substring matches — and it collapses the
   *     search space from millions of rows to at most MATCH_CAP.
   *
   *  2. `usage` finds, for each (component, application) pair, the most recent
   *     scan that contained it. `DISTINCT ON` with a matching ORDER BY reads
   *     straight down `scan_component_search_idx (component_id, application_id,
   *     scan_id)`, so this never scans the table.
   *
   * The `current` vs `historical` distinction then falls out of one comparison:
   * `last_seen_scan_id = application.latest_scan_id`. If a package is in the
   * latest scan then that scan IS its most recent occurrence; if it has been
   * removed, its most recent occurrence is necessarily some earlier build. No
   * second query, no NOT EXISTS subquery over the large table.
   */
  async search(query: ComponentSearchQuery): Promise<ComponentSearchResult> {
    const { db } = this.deps;

    const nameCondition =
      query.match === "exact"
        ? sql`lower(c.name) = lower(${query.name})`
        : sql`c.name ILIKE ${"%" + query.name + "%"}`;

    const matchConditions: SQL[] = [nameCondition];
    if (query.version) {
      matchConditions.push(sql`c.version = ${query.version}`);
    }
    if (query.ecosystem) {
      matchConditions.push(sql`c.ecosystem = ${query.ecosystem}`);
    }
    const matchWhere = sql.join(matchConditions, sql` AND `);

    // Fetch one extra row to detect truncation without a second count.
    const matchLimit = MATCH_CAP + 1;

    const scopeCondition =
      query.scope === "current"
        ? sql`AND u.last_seen_scan_id = a.latest_scan_id`
        : query.scope === "historical"
          ? sql`AND (a.latest_scan_id IS NULL OR u.last_seen_scan_id <> a.latest_scan_id)`
          : sql``;

    const statusCondition = query.includeInactive
      ? sql``
      : sql`AND a.status <> 'inactive'`;

    const rows = await db.execute<Row<SearchRow>>(sql`
      WITH matched AS (
        SELECT c.id, c.name, c.version, c.ecosystem, c.purl
        FROM component c
        WHERE ${matchWhere}
        ORDER BY lower(c.name) ASC, c.version ASC NULLS LAST
        LIMIT ${matchLimit}
      ),
      usage AS (
        SELECT DISTINCT ON (sc.component_id, sc.application_id)
               sc.component_id,
               sc.application_id,
               sc.scan_id   AS last_seen_scan_id,
               sc.created_at AS last_seen_at
        FROM scan_component sc
        WHERE sc.component_id IN (SELECT id FROM matched)
        -- Must mirror the DISTINCT ON key, then pick the newest occurrence.
        -- scan_id breaks ties when two scans share a timestamp.
        ORDER BY sc.component_id, sc.application_id, sc.created_at DESC, sc.scan_id DESC
      )
      SELECT
        a.id      AS application_id,
        a.name    AS application_name,
        a.status  AS application_status,
        m.id      AS component_id,
        m.name    AS component_name,
        m.version AS component_version,
        m.ecosystem,
        m.purl,
        (u.last_seen_scan_id = a.latest_scan_id) AS in_latest,
        u.last_seen_scan_id,
        u.last_seen_at,
        s.build_number AS last_seen_build_number,
        count(*) OVER () AS total,
        (SELECT count(*) FROM matched) AS matched_components
      FROM usage u
      JOIN matched m     ON m.id = u.component_id
      JOIN application a ON a.id = u.application_id
      JOIN scan s        ON s.id = u.last_seen_scan_id
      WHERE true ${scopeCondition} ${statusCondition}
      ${searchOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const resultRows = rowsOf(rows);
    const matchedComponents = resultRows[0] ? Number(resultRows[0].matched_components) : 0;

    return {
      ...paginate(resultRows.map(toSearchHit), totalFromRows(resultRows), query),
      truncated: matchedComponents > MATCH_CAP,
      matchedComponents: Math.min(matchedComponents, MATCH_CAP),
    };
  }

  /**
   * Typeahead for the search box.
   *
   * Groups by name and ecosystem only, and never joins `scan_component` — a
   * suggestion list does not need usage counts, and keeping the query inside the
   * `component` table is what makes it fast enough to fire on every keystroke.
   */
  async suggest(query: ComponentSuggestQuery): Promise<ComponentSuggestion[]> {
    const rows = await this.deps.db.execute<Row<{
      name: string;
      ecosystem: string;
      version_count: number | string;
    }>>(sql`
      SELECT c.name, c.ecosystem, count(DISTINCT c.version)::int AS version_count
      FROM component c
      WHERE c.name ILIKE ${"%" + query.q + "%"}
      GROUP BY c.name, c.ecosystem
      -- Prefix matches first: typing "expr" should surface "express" above
      -- "my-express-wrapper".
      ORDER BY (lower(c.name) LIKE ${query.q.toLowerCase() + "%"}) DESC,
               length(c.name) ASC,
               lower(c.name) ASC
      LIMIT ${query.limit}
    `);

    return rowsOf(rows).map((r) => ({
      name: r.name,
      ecosystem: r.ecosystem,
      versionCount: Number(r.version_count),
    }));
  }

  /** All ecosystems present in the component table, for the filter dropdown. */
  async listEcosystems(): Promise<Array<{ ecosystem: string; count: number }>> {
    const rows = await this.deps.db.execute<Row<{ ecosystem: string; count: number | string }>>(sql`
      SELECT ecosystem, count(*)::int AS count
      FROM component
      GROUP BY ecosystem
      ORDER BY count DESC, ecosystem ASC
    `);
    return rowsOf(rows).map((r) => ({
      ecosystem: r.ecosystem,
      count: Number(r.count),
    }));
  }

  /**
   * Every version of a package that appears anywhere, with how many applications
   * currently ship each one. Drives the "which version is where" view.
   */
  async listVersions(name: string): Promise<
    Array<{ componentId: string; version: string | null; ecosystem: string; currentApplications: number; totalApplications: number }>
  > {
    const rows = await this.deps.db.execute<Row<{
      component_id: number | string;
      version: string | null;
      ecosystem: string;
      current_applications: number | string;
      total_applications: number | string;
    }>>(sql`
      WITH matched AS (
        SELECT id, version, ecosystem FROM component WHERE lower(name) = lower(${name})
      ),
      usage AS (
        SELECT DISTINCT ON (sc.component_id, sc.application_id)
               sc.component_id, sc.application_id, sc.scan_id AS last_seen_scan_id
        FROM scan_component sc
        WHERE sc.component_id IN (SELECT id FROM matched)
        ORDER BY sc.component_id, sc.application_id, sc.created_at DESC, sc.scan_id DESC
      )
      SELECT
        m.id AS component_id,
        m.version,
        m.ecosystem,
        count(*) FILTER (WHERE u.last_seen_scan_id = a.latest_scan_id)::int AS current_applications,
        count(*)::int AS total_applications
      FROM matched m
      LEFT JOIN usage u ON u.component_id = m.id
      LEFT JOIN application a ON a.id = u.application_id
      GROUP BY m.id, m.version, m.ecosystem
      ORDER BY m.version DESC NULLS LAST
    `);

    return rowsOf(rows).map((r) => ({
      componentId: String(r.component_id),
      version: r.version,
      ecosystem: r.ecosystem,
      currentApplications: Number(r.current_applications),
      totalApplications: Number(r.total_applications),
    }));
  }
}

interface SearchRow {
  application_id: string;
  application_name: string;
  application_status: "active" | "inactive" | "pending_confirmation";
  component_id: number | string;
  component_name: string;
  component_version: string | null;
  ecosystem: string;
  purl: string | null;
  in_latest: boolean;
  last_seen_scan_id: string;
  last_seen_at: Date | string;
  last_seen_build_number: string | null;
  total?: number | string;
  matched_components: number | string;
}

/**
 * Sort clause for the search results.
 *
 * The rows are a package × application cross product, so the two obvious readings need
 * different secondary keys: sorting by package should group an application's versions
 * together underneath it, and sorting by application should group its packages. Each
 * branch therefore names the *other* axis as its secondary key.
 *
 * The final tiebreaker is the (component, application) pair, which is exactly the
 * DISTINCT ON key of the `usage` CTE and so is unique per row. Without it, an estate with
 * many same-named packages would shuffle rows across page boundaries.
 */
function searchOrderBy(sortBy: ComponentSearchQuery["sortBy"], dir: SortDirection): SQL {
  const dir_ = direction(dir);
  const nulls = directionNullsLast(dir);
  const byPackage = sql`lower(m.name) ASC, m.version ASC NULLS LAST`;
  const byApp = sql`lower(a.name) ASC`;
  const unique = sql`m.id, a.id`;

  switch (sortBy) {
    case "applicationStatus":
      return orderBy([sql`a.status ${dir_}`, byApp, byPackage], unique);
    case "componentName":
      return orderBy([sql`lower(m.name) ${dir_}`, sql`m.version ASC NULLS LAST`, byApp], unique);
    case "componentVersion":
      return orderBy([sql`m.version ${nulls}`, byPackage, byApp], unique);
    case "ecosystem":
      return orderBy([sql`m.ecosystem ${dir_}`, byPackage, byApp], unique);
    case "usage":
      // `in_latest` is a boolean; sorting it descending puts current usage first, which is
      // the reading that matches the column's label.
      return orderBy([sql`(u.last_seen_scan_id = a.latest_scan_id) ${dir_}`, byApp, byPackage], unique);
    case "lastSeenAt":
      return orderBy([sql`u.last_seen_at ${nulls}`, byApp, byPackage], unique);
    case "applicationName":
    default:
      return orderBy([sql`lower(a.name) ${dir_}`, byPackage], unique);
  }
}

function toSearchHit(row: SearchRow): ComponentSearchHit {
  return {
    applicationId: row.application_id,
    applicationName: row.application_name,
    applicationStatus: row.application_status,
    componentId: String(row.component_id),
    componentName: row.component_name,
    componentVersion: row.component_version,
    ecosystem: row.ecosystem,
    purl: row.purl,
    usage: row.in_latest === true ? "current" : "historical",
    lastSeenScanId: row.last_seen_scan_id,
    lastSeenAt: toIso(row.last_seen_at)!,
    lastSeenBuildNumber: row.last_seen_build_number,
  };
}
