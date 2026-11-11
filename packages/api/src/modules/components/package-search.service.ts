import { sql, type SQL } from "drizzle-orm";
import type {
  PackageAdvisoryCounts,
  PackageApplicationEntry,
  PackageDetail,
  PackageDetailQuery,
  PackageSearchQuery,
  PackageSearchResult,
  PackageSearchRow,
  PackageVersionEntry,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import { applicationInAnyScope, type ReadScope } from "../environments/environment.service.js";
import { NOT_SUPPRESSED } from "../vulnerabilities/scope.js";

/**
 * Upper bound on distinct package versions one search considers.
 *
 * The same cap, for the same reason, as the per-application search: a two-letter substring
 * can match a large slice of the catalogue, and everything after the first stage joins the
 * largest table in the schema. Exceeding it is reported, never silently trimmed.
 */
const MATCH_CAP = 2000;

/**
 * Package-first search: which packages match, and where each one is used.
 *
 * The per-application search answers "list every application and package pair", which is
 * the right shape for an export and the wrong one for reading - a search for `log4` lists
 * applications first and makes the reader assemble the package picture themselves. This
 * service collapses that into one row per package (name within an ecosystem, per estate)
 * and a drill-down per package.
 *
 * ## Identity
 *
 * A package is `lower(name)` within an ecosystem, matching the dashboard's group-by-name
 * mode and the fragmentation report, so `React` and `react` are one package.
 *
 * ## Current and dropped, at package level
 *
 * An application *currently uses* a package when its latest build ships any version of it.
 * It *dropped* the package when an earlier build shipped it and the latest ships no version
 * at all. An upgrade from 1.0 to 1.1 is therefore neither - it is still current use, which
 * is what a reader asking "who ships log4j" means. (The per-application search counts the
 * 1.0 pair as historical; that is correct for a pair and wrong for a package.)
 *
 * ## Vulnerabilities
 *
 * A secondary column, counted over current builds only - a version an application dropped is
 * not exposure - and excluding accepted risks with the same predicate every other count uses.
 * Distinct advisories, not findings: a CVE affecting forty applications is one advisory, and
 * how many applications it reaches is its own column.
 */
export class PackageSearchService {
  constructor(private readonly deps: { db: Database }) {}

  async search(
    query: PackageSearchQuery,
    scopes: ReadScope[],
    vulnScanningEnabled: boolean,
  ): Promise<PackageSearchResult> {
    const conditions: SQL[] = [
      query.match === "exact"
        ? sql`lower(c.name) = lower(${query.name})`
        : sql`c.name ILIKE ${"%" + escapeLike(query.name) + "%"}`,
    ];
    if (query.version) conditions.push(sql`c.version = ${query.version}`);
    if (query.ecosystem) conditions.push(sql`c.ecosystem = ${query.ecosystem}`);

    const statusCondition = query.includeInactive ? sql`` : sql`AND a.status <> 'inactive'`;
    const scopeCondition =
      query.scope === "current"
        ? sql`WHERE pkg.current_apps > 0`
        : query.scope === "historical"
          ? sql`WHERE pkg.historical_apps > 0`
          : sql``;

    const rows = await this.deps.db.execute<Row<SearchRow>>(sql`
      WITH matched AS (
        SELECT c.id, c.name, c.version, c.ecosystem, c.kind, c.vuln_scanned_at
        FROM component c
        WHERE ${sql.join(conditions, sql` AND `)}
        ORDER BY lower(c.name) ASC, c.version ASC NULLS LAST
        LIMIT ${MATCH_CAP + 1}
      ),
      usage AS (
        SELECT DISTINCT ON (sc.component_id, sc.application_id)
               sc.component_id, sc.application_id, sc.scan_id AS last_seen_scan_id
        FROM scan_component sc
        WHERE sc.component_id IN (SELECT id FROM matched)
        ORDER BY sc.component_id, sc.application_id, sc.created_at DESC, sc.scan_id DESC
      ),
      pairs AS (
        SELECT a.environment_id, lower(m.name) AS name_key, m.ecosystem,
               m.id AS component_id, m.name, m.version, m.kind, m.vuln_scanned_at,
               a.id AS application_id,
               (u.last_seen_scan_id = a.latest_scan_id) AS in_latest
        FROM usage u
        JOIN matched m     ON m.id = u.component_id
        JOIN application a ON a.id = u.application_id
        WHERE ${applicationInAnyScope("a", scopes)} ${statusCondition}
      ),
      app_pkg AS (
        SELECT environment_id, name_key, ecosystem, application_id, bool_or(in_latest) AS current
        FROM pairs
        GROUP BY environment_id, name_key, ecosystem, application_id
      ),
      pkg AS (
        SELECT environment_id, name_key, ecosystem,
               count(*) FILTER (WHERE current)::int     AS current_apps,
               count(*) FILTER (WHERE NOT current)::int AS historical_apps
        FROM app_pkg
        GROUP BY environment_id, name_key, ecosystem
      ),
      pkg_versions AS (
        SELECT environment_id, name_key, ecosystem,
               min(name) AS name,
               -- os and runtime sort after library, so a package Syft classified as the
               -- distribution or an interpreter anywhere is labelled that way.
               max(kind) AS kind,
               count(DISTINCT coalesce(version, '')) FILTER (WHERE in_latest)::int AS versions_in_use,
               count(DISTINCT coalesce(version, ''))::int AS versions_ever,
               (array_agg(DISTINCT version ORDER BY version)
                  FILTER (WHERE in_latest AND version IS NOT NULL))[1:6] AS version_sample,
               count(DISTINCT coalesce(version, ''))
                 FILTER (WHERE in_latest AND vuln_scanned_at IS NULL)::int AS unassessed_versions,
               coalesce(bool_or(in_latest AND vuln_scanned_at IS NOT NULL), false) AS assessed
        FROM pairs
        GROUP BY environment_id, name_key, ecosystem
      ),
      ${vulnCte(vulnScanningEnabled)}
      SELECT
        pkg.environment_id, e.name AS environment_name,
        pv.name, pkg.ecosystem, pv.kind,
        pkg.current_apps, pkg.historical_apps,
        pv.versions_in_use, pv.versions_ever, pv.version_sample,
        pv.unassessed_versions, pv.assessed,
        coalesce(vu.advisories, 0)::int AS advisories,
        coalesce(vu.critical, 0)::int   AS critical,
        coalesce(vu.high, 0)::int       AS high,
        coalesce(vu.kev, 0)::int        AS kev,
        coalesce(vu.vulnerable_apps, 0)::int AS vulnerable_apps,
        count(*) OVER () AS total,
        (SELECT count(*) FROM matched) AS matched_components
      FROM pkg
      JOIN pkg_versions pv
        ON pv.environment_id = pkg.environment_id AND pv.name_key = pkg.name_key
       AND pv.ecosystem = pkg.ecosystem
      JOIN environment e ON e.id = pkg.environment_id
      LEFT JOIN vuln vu
        ON vu.environment_id = pkg.environment_id AND vu.name_key = pkg.name_key
       AND vu.ecosystem = pkg.ecosystem
      ${scopeCondition}
      ${packageOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const result = rowsOf(rows);
    const matched = result[0] ? Number(result[0].matched_components) : 0;
    return {
      ...paginate(result.map((r) => toPackageRow(r, vulnScanningEnabled)), totalFromRows(result), query),
      truncated: matched > MATCH_CAP,
      vulnScanningEnabled,
    };
  }

  /**
   * One package in one estate: its versions, and every application that uses or used it.
   *
   * Two queries rather than one: the usage rows and the findings rows have different grains,
   * and folding them together in SQL would multiply each usage row by its advisory count. The
   * assembly is a pure function below, which is where the counting rules are tested.
   */
  async detail(
    query: PackageDetailQuery,
    scope: ReadScope,
    vulnScanningEnabled: boolean,
  ): Promise<PackageDetail> {
    const statusCondition = query.includeInactive ? sql`` : sql`AND a.status <> 'inactive'`;
    const base = sql`
      matched AS (
        SELECT id, name, version, vuln_scanned_at
        FROM component
        WHERE lower(name) = lower(${query.name}) AND ecosystem = ${query.ecosystem}
      ),
      usage AS (
        SELECT DISTINCT ON (sc.component_id, sc.application_id)
               sc.component_id, sc.application_id,
               sc.scan_id AS last_seen_scan_id, sc.created_at AS last_seen_at
        FROM scan_component sc
        WHERE sc.component_id IN (SELECT id FROM matched)
        ORDER BY sc.component_id, sc.application_id, sc.created_at DESC, sc.scan_id DESC
      ),
      pairs AS (
        SELECT m.id AS component_id, m.name, m.version, (m.vuln_scanned_at IS NOT NULL) AS assessed,
               a.id AS application_id, a.name AS application_name, a.status AS application_status,
               (u.last_seen_scan_id = a.latest_scan_id) AS in_latest,
               u.last_seen_scan_id, u.last_seen_at, s.build_number
        FROM usage u
        JOIN matched m     ON m.id = u.component_id
        JOIN application a ON a.id = u.application_id
        JOIN scan s        ON s.id = u.last_seen_scan_id
        WHERE ${applicationInAnyScope("a", [scope])} ${statusCondition}
      )`;

    const pairRows = rowsOf(
      await this.deps.db.execute<Row<DetailPairRow>>(sql`WITH ${base} SELECT * FROM pairs`),
    );

    const findingRows = vulnScanningEnabled && pairRows.some((p) => p.in_latest)
      ? rowsOf(
          await this.deps.db.execute<Row<DetailFindingRow>>(sql`
            WITH ${base}
            SELECT p.application_id, p.version, v.id AS vulnerability_id, v.severity,
                   v.known_exploited
            FROM pairs p
            JOIN component c ON c.id = p.component_id
            JOIN application a ON a.id = p.application_id
            JOIN component_vulnerability cv ON cv.component_id = p.component_id
            JOIN vulnerability v ON v.id = cv.vulnerability_id
            WHERE p.in_latest AND ${NOT_SUPPRESSED}
          `),
        )
      : [];

    const name = pairRows[0]?.name ?? query.name;
    return {
      name,
      ecosystem: query.ecosystem,
      environmentId: scope.id,
      environmentName: scope.name,
      vulnScanningEnabled,
      ...assemblePackageDetail(
        pairRows.map((p) => ({
          componentId: String(p.component_id),
          version: p.version,
          assessed: p.assessed === true,
          applicationId: p.application_id,
          applicationName: p.application_name,
          applicationStatus: p.application_status,
          inLatest: p.in_latest === true,
          lastSeenScanId: p.last_seen_scan_id,
          lastSeenAt: toIso(p.last_seen_at) ?? "",
          lastSeenBuildNumber: p.build_number,
        })),
        findingRows.map((f) => ({
          applicationId: f.application_id,
          version: f.version,
          vulnerabilityId: f.vulnerability_id,
          severity: f.severity,
          knownExploited: f.known_exploited === true,
        })),
        vulnScanningEnabled,
      ),
    };
  }
}

/** The findings CTE, or an empty stand-in when scanning is off so the outer query is unchanged. */
function vulnCte(enabled: boolean): SQL {
  if (!enabled) {
    return sql`vuln AS (
      SELECT NULL::uuid AS environment_id, NULL::text AS name_key, NULL::text AS ecosystem,
             0 AS advisories, 0 AS critical, 0 AS high, 0 AS kev, 0 AS vulnerable_apps
      WHERE FALSE
    )`;
  }
  /*
    Joined back to component and application under the aliases NOT_SUPPRESSED expects, so the
    accepted-risk rule here is the one every other count applies, not a hand-written copy.
  */
  return sql`findings AS (
      SELECT p.environment_id, p.name_key, p.ecosystem, p.application_id,
             v.id AS vulnerability_id, v.severity, v.known_exploited
      FROM pairs p
      JOIN component c   ON c.id = p.component_id
      JOIN application a ON a.id = p.application_id
      JOIN component_vulnerability cv ON cv.component_id = p.component_id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
      WHERE p.in_latest AND ${NOT_SUPPRESSED}
    ),
    vuln AS (
      SELECT environment_id, name_key, ecosystem,
             count(DISTINCT vulnerability_id)::int AS advisories,
             count(DISTINCT vulnerability_id) FILTER (WHERE severity = 'critical')::int AS critical,
             count(DISTINCT vulnerability_id) FILTER (WHERE severity = 'high')::int AS high,
             count(DISTINCT vulnerability_id) FILTER (WHERE known_exploited)::int AS kev,
             count(DISTINCT application_id)::int AS vulnerable_apps
      FROM findings
      GROUP BY environment_id, name_key, ecosystem
    )`;
}

/**
 * `%` and `_` typed into the box are literal characters in a package name, not wildcards.
 * Without this, searching `my_pkg` also matched `myXpkg`.
 */
function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

/**
 * Sort clause. The tiebreaker is the grouping key itself - unique per row - so equal counts
 * cannot swap places across page boundaries.
 */
function packageOrderBy(sortBy: PackageSearchQuery["sortBy"], dir: PackageSearchQuery["sortDir"]): SQL {
  const d = direction(dir);
  const unique = sql`lower(pv.name), pkg.ecosystem, pkg.environment_id`;
  const byName = sql`lower(pv.name) ASC`;
  switch (sortBy) {
    case "name":
      return orderBy([sql`lower(pv.name) ${d}`], unique);
    case "ecosystem":
      return orderBy([sql`pkg.ecosystem ${d}`, byName], unique);
    case "environment":
      return orderBy([sql`lower(e.name) ${d}`, byName], unique);
    case "historicalApplications":
      return orderBy([sql`pkg.historical_apps ${d}`, byName], unique);
    case "versionsInUse":
      return orderBy([sql`pv.versions_in_use ${d}`, byName], unique);
    case "advisories":
      return orderBy([sql`coalesce(vu.advisories, 0) ${d}`, byName], unique);
    case "critical":
      return orderBy([sql`coalesce(vu.critical, 0) ${d}`, sql`coalesce(vu.high, 0) ${d}`, byName], unique);
    case "vulnerableApplications":
      return orderBy([sql`coalesce(vu.vulnerable_apps, 0) ${d}`, byName], unique);
    case "currentApplications":
    default:
      return orderBy([sql`pkg.current_apps ${d}`, sql`pkg.historical_apps ${d}`, byName], unique);
  }
}

function toPackageRow(r: SearchRow, vulnScanningEnabled: boolean): PackageSearchRow {
  return {
    environmentId: r.environment_id,
    environmentName: r.environment_name,
    name: r.name,
    ecosystem: r.ecosystem,
    kind: r.kind,
    currentApplications: Number(r.current_apps),
    historicalApplications: Number(r.historical_apps),
    versionsInUse: Number(r.versions_in_use),
    versionsEver: Number(r.versions_ever),
    versionSample: Array.isArray(r.version_sample)
      ? r.version_sample.filter((v): v is string => typeof v === "string")
      : [],
    vulnerabilities: vulnScanningEnabled
      ? {
          assessed: r.assessed === true,
          unassessedVersions: Number(r.unassessed_versions),
          advisories: Number(r.advisories),
          critical: Number(r.critical),
          high: Number(r.high),
          knownExploited: Number(r.kev),
          vulnerableApplications: Number(r.vulnerable_apps),
        }
      : null,
  };
}

// ---------------------------------------------------------------------------
// Detail assembly - pure, so the counting rules are testable without a database
// ---------------------------------------------------------------------------

export interface DetailPair {
  componentId: string;
  version: string | null;
  assessed: boolean;
  applicationId: string;
  applicationName: string;
  applicationStatus: PackageApplicationEntry["applicationStatus"];
  /** This component is in the application's latest build. */
  inLatest: boolean;
  lastSeenScanId: string;
  lastSeenAt: string;
  lastSeenBuildNumber: string | null;
}

export interface DetailFinding {
  applicationId: string;
  version: string | null;
  vulnerabilityId: string;
  severity: string;
  knownExploited: boolean;
}

const versionKey = (v: string | null) => v ?? "\u0000";

function countAdvisories(findings: DetailFinding[]): PackageAdvisoryCounts {
  const all = new Set<string>();
  const critical = new Set<string>();
  const high = new Set<string>();
  const kev = new Set<string>();
  for (const f of findings) {
    all.add(f.vulnerabilityId);
    if (f.severity === "critical") critical.add(f.vulnerabilityId);
    if (f.severity === "high") high.add(f.vulnerabilityId);
    if (f.knownExploited) kev.add(f.vulnerabilityId);
  }
  return { advisories: all.size, critical: critical.size, high: high.size, knownExploited: kev.size };
}

/** Newest version first, comparing digit runs numerically so 1.10 sorts above 1.9. */
export function compareVersionsDesc(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return b.localeCompare(a, undefined, { numeric: true, sensitivity: "base" });
}

/**
 * Folds usage and findings into the version table and the application table.
 *
 * Rules, each one a decision a reader would otherwise have to guess at:
 *  - An application is `current` when its latest build ships any version of the package; its
 *    versions are then every version in that build. Otherwise it dropped the package, and its
 *    versions are the ones in the last build that shipped it.
 *  - A version's `historicalApplications` are applications that shipped that version and no
 *    longer do - including ones that upgraded to another version. That is what "fully
 *    removed" means at version level, and why it differs from the package-level count.
 *  - Advisory counts are distinct advisories over current use only, and null rather than zero
 *    when nothing was matched yet or scanning is off.
 */
export function assemblePackageDetail(
  pairs: DetailPair[],
  findings: DetailFinding[],
  vulnScanningEnabled: boolean,
): { versions: PackageVersionEntry[]; applications: PackageApplicationEntry[] } {
  // --- applications -------------------------------------------------------
  const byApp = new Map<string, DetailPair[]>();
  for (const p of pairs) {
    const list = byApp.get(p.applicationId) ?? [];
    list.push(p);
    byApp.set(p.applicationId, list);
  }

  const findingsByApp = new Map<string, DetailFinding[]>();
  for (const f of findings) {
    const list = findingsByApp.get(f.applicationId) ?? [];
    list.push(f);
    findingsByApp.set(f.applicationId, list);
  }

  const applications: PackageApplicationEntry[] = [];
  for (const appPairs of byApp.values()) {
    const first = appPairs[0]!;
    const current = appPairs.filter((p) => p.inLatest);
    let shown: DetailPair[];
    if (current.length > 0) {
      shown = current;
    } else {
      // The last build that shipped it, and every version that build carried.
      const newest = appPairs.reduce((a, b) => (b.lastSeenAt > a.lastSeenAt ? b : a));
      shown = appPairs.filter((p) => p.lastSeenScanId === newest.lastSeenScanId);
    }
    const lead = shown[0]!;
    const assessed = current.some((p) => p.assessed);
    applications.push({
      applicationId: first.applicationId,
      applicationName: first.applicationName,
      applicationStatus: first.applicationStatus,
      usage: current.length > 0 ? "current" : "historical",
      versions: [...new Set(shown.map((p) => p.version))].sort(compareVersionsDesc),
      lastSeenScanId: lead.lastSeenScanId,
      lastSeenAt: lead.lastSeenAt,
      lastSeenBuildNumber: lead.lastSeenBuildNumber,
      vulnerabilities:
        vulnScanningEnabled && current.length > 0 && assessed
          ? countAdvisories(findingsByApp.get(first.applicationId) ?? [])
          : null,
    });
  }
  applications.sort((a, b) =>
    a.usage !== b.usage
      ? a.usage === "current" ? -1 : 1
      : a.applicationName.localeCompare(b.applicationName, undefined, { sensitivity: "base" }),
  );

  // --- versions -----------------------------------------------------------
  const byVersion = new Map<string, DetailPair[]>();
  for (const p of pairs) {
    const key = versionKey(p.version);
    const list = byVersion.get(key) ?? [];
    list.push(p);
    byVersion.set(key, list);
  }
  const findingsByVersion = new Map<string, DetailFinding[]>();
  for (const f of findings) {
    const key = versionKey(f.version);
    const list = findingsByVersion.get(key) ?? [];
    list.push(f);
    findingsByVersion.set(key, list);
  }

  const versions: PackageVersionEntry[] = [];
  for (const [key, versionPairs] of byVersion) {
    const currentApps = new Set(versionPairs.filter((p) => p.inLatest).map((p) => p.applicationId));
    const everApps = new Set(versionPairs.map((p) => p.applicationId));
    const assessed = versionPairs.some((p) => p.inLatest && p.assessed);
    versions.push({
      version: versionPairs[0]!.version,
      currentApplications: currentApps.size,
      historicalApplications: [...everApps].filter((id) => !currentApps.has(id)).length,
      assessed,
      vulnerabilities:
        vulnScanningEnabled && currentApps.size > 0 && assessed
          ? countAdvisories(findingsByVersion.get(key) ?? [])
          : null,
    });
  }
  versions.sort((a, b) => compareVersionsDesc(a.version, b.version));

  return { versions, applications };
}

interface SearchRow {
  environment_id: string;
  environment_name: string;
  name: string;
  ecosystem: string;
  kind: "library" | "os" | "runtime";
  current_apps: number | string;
  historical_apps: number | string;
  versions_in_use: number | string;
  versions_ever: number | string;
  version_sample: unknown;
  unassessed_versions: number | string;
  assessed: boolean;
  advisories: number | string;
  critical: number | string;
  high: number | string;
  kev: number | string;
  vulnerable_apps: number | string;
  total?: number | string;
  matched_components: number | string;
}

interface DetailPairRow {
  component_id: number | string;
  name: string;
  version: string | null;
  assessed: boolean;
  application_id: string;
  application_name: string;
  application_status: PackageApplicationEntry["applicationStatus"];
  in_latest: boolean;
  last_seen_scan_id: string;
  last_seen_at: Date | string;
  build_number: string | null;
}

interface DetailFindingRow {
  application_id: string;
  version: string | null;
  vulnerability_id: string;
  severity: string;
  known_exploited: boolean;
}
