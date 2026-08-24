import { sql, type SQL } from "drizzle-orm";
import type {
  ListMaliciousQuery,
  MaliciousAckSummary,
  MaliciousApplicationImpact,
  MaliciousFinding,
  MaliciousFindingDetail,
  MaliciousMatchMode,
  MaliciousStatus,
  MaliciousSummary,
  Paginated,
  SortDirection,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import { groupMemberPredicate } from "../vulnerabilities/scope.js";
import type { SettingsService } from "../settings/settings.service.js";
import type { MaliciousFeedService } from "./malicious-feed.service.js";
import type { MaliciousMatchService } from "./malicious-match.service.js";

/**
 * Reading malicious-package findings.
 *
 * ## Current and historical are both reported, always
 *
 * Every count here comes in a pair, and nothing in this file ever collapses them. A CVE in a
 * build you replaced last month is history; a malicious package in a build you replaced last
 * month is not, because its payload ran at install time on whatever machine built it. The
 * credentials that were readable there are still compromised whether or not the package is
 * still in the tree.
 *
 * So `currentApplications` is what can be removed today, and `affectedApplications` is the set
 * whose pipeline secrets need rotating. A finding with zero current and four historical
 * applications is not a clean result -- it is four pipelines nobody has cleaned up. Reporting
 * only the first number would let this platform tell somebody they were fine when they were
 * comprehensively not.
 *
 * ## The queries start from the findings table
 *
 * `component_malicious` is small -- a handful of rows on a healthy estate -- while
 * `scan_component` is the largest table in the database. Driving from the findings side and
 * joining outward through `scan_component_search_idx` keeps every query here proportional to
 * the number of findings rather than to the size of the estate.
 */

/** Live reports only. A withdrawal must stop producing findings the moment it lands. */
const LIVE_REPORT = sql`mp.withdrawn_at IS NULL`;

function findingOrderBy(sortBy: ListMaliciousQuery["sortBy"], dir: SortDirection): SQL {
  const d = direction(dir);
  switch (sortBy) {
    case "affectedApplications":
      return orderBy([sql`affected_applications ${d}`], sql`mp.id`);
    case "packageName":
      return orderBy([sql`lower(mp.package_name) ${d}`], sql`mp.id`);
    case "publishedAt":
      return orderBy([sql`mp.published_at ${d} NULLS LAST`], sql`mp.id`);
    case "firstShippedAt":
      return orderBy([sql`first_shipped_at ${d} NULLS LAST`], sql`mp.id`);
    case "currentApplications":
    default:
      // Ties break on total reach, so among the packages you no longer ship the widest
      // historical spread still floats to the top.
      return orderBy([sql`current_applications ${d}`, sql`affected_applications ${d}`], sql`mp.id`);
  }
}

export class MaliciousService {
  constructor(
    private readonly deps: {
      db: Database;
      settings: SettingsService;
      feed: MaliciousFeedService;
      match: MaliciousMatchService;
    },
  ) {}

  /** True when an administrator has switched detection on. */
  async isEnabled(): Promise<boolean> {
    return (await this.deps.settings.getMaliciousSettings()).enabled;
  }

  /**
   * Feature state, readable in every condition.
   *
   * Deliberately never refuses. The SPA has to tell "switched off" from "on but never
   * downloaded" from "on and broken", and each of those needs a different sentence on screen.
   */
  async status(): Promise<MaliciousStatus> {
    const settings = await this.deps.settings.getMaliciousSettings();
    const snapshot = await this.deps.feed.snapshot();

    return {
      enabled: settings.enabled,
      feedBuiltAt: snapshot.builtAt?.toISOString() ?? null,
      reportCount: snapshot.reportCount,
      intervalHours: settings.intervalHours,
      refreshing: this.deps.feed.isRefreshing,
      sweeping: this.deps.match.isRunning,
      // No snapshot means nothing to measure coverage against. Zeros here would say "nothing
      // matched yet", which is a claim about the estate rather than about the feed.
      coverage: snapshot.builtAt ? await this.deps.match.coverage(snapshot.builtAt) : null,
      lastUpdate: await this.deps.feed.lastAttempt(),
    };
  }

  /**
   * The estate headline, or null when there is nothing to say.
   *
   * Null rather than zeros whenever detection is off or no feed is installed. A zeroed block
   * renders as "no malicious packages", which is the single most dangerous thing this
   * platform could assert without having looked.
   */
  async summary(): Promise<MaliciousSummary | null> {
    const settings = await this.deps.settings.getMaliciousSettings();
    if (!settings.enabled) return null;

    const snapshot = await this.deps.feed.snapshot();
    if (!snapshot.builtAt) return null;

    const rows = await this.deps.db.execute<Row<Record<string, number>>>(sql`
      SELECT
        count(DISTINCT mp.id) FILTER (WHERE sc.scan_id = a.latest_scan_id)::int AS current_packages,
        count(DISTINCT a.id)  FILTER (WHERE sc.scan_id = a.latest_scan_id)::int AS current_applications,
        count(DISTINCT mp.id)::int AS ever_packages,
        count(DISTINCT a.id)::int  AS ever_applications,
        count(DISTINCT mp.id) FILTER (WHERE ack.id IS NOT NULL)::int AS acknowledged_packages
      FROM component_malicious cm
      JOIN malicious_package mp ON mp.id = cm.malicious_package_id AND ${LIVE_REPORT}
      JOIN scan_component sc ON sc.component_id = cm.component_id
      JOIN application a ON a.id = sc.application_id
      LEFT JOIN malicious_acknowledgement ack
        ON ack.malicious_package_id = mp.id
       AND (ack.application_id IS NULL OR ack.application_id = a.id)
    `);

    const row = rowsOf(rows)[0];
    const coverage = await this.deps.match.coverage(snapshot.builtAt);

    return {
      currentPackages: Number(row?.current_packages ?? 0),
      currentApplications: Number(row?.current_applications ?? 0),
      everPackages: Number(row?.ever_packages ?? 0),
      everApplications: Number(row?.ever_applications ?? 0),
      acknowledgedPackages: Number(row?.acknowledged_packages ?? 0),
      feedBuiltAt: snapshot.builtAt.toISOString(),
      matchedComponents: coverage.matched,
      pendingComponents: coverage.pending,
    };
  }

  async list(query: ListMaliciousQuery): Promise<Paginated<MaliciousFinding>> {
    const conditions: SQL[] = [LIVE_REPORT];

    if (query.search) {
      const like = `%${query.search.replace(/[%_\\]/g, (m) => `\\${m}`)}%`;
      conditions.push(sql`(mp.package_name ILIKE ${like} OR mp.id ILIKE ${like})`);
    }
    if (query.ecosystem) conditions.push(sql`mp.ecosystem = ${query.ecosystem}`);
    if (query.application) conditions.push(sql`a.id = ${query.application}::uuid`);
    if (query.group) conditions.push(groupMemberPredicate(query.group));

    const where = sql.join([sql`WHERE `, sql.join(conditions, sql` AND `)]);

    /*
     * Presence is applied AFTER aggregation, not as a row filter.
     *
     * Filtering the joined rows instead would silently corrupt the other column: asking for
     * "current" while counting `affected_applications` over only current rows makes the
     * historical figure equal the current one, and the page would then claim a package that
     * spread through eight applications only ever touched one.
     */
    const presence =
      query.presence === "current"
        ? sql`HAVING count(DISTINCT a.id) FILTER (WHERE sc.scan_id = a.latest_scan_id) > 0`
        : query.presence === "historical"
          ? sql`HAVING count(DISTINCT a.id) FILTER (WHERE sc.scan_id = a.latest_scan_id) = 0`
          : sql``;

    const unacknowledged = query.unacknowledged
      ? sql`AND NOT EXISTS (
            SELECT 1 FROM malicious_acknowledgement ack2
            WHERE ack2.malicious_package_id = mp.id
          )`
      : sql``;

    const rows = await this.deps.db.execute<Row<FindingRow>>(sql`
      SELECT
        mp.id, mp.ecosystem, mp.package_name, mp.summary, mp.match_mode,
        mp.aliases, mp.sources, mp.reference_url, mp.published_at,
        count(DISTINCT a.id) FILTER (WHERE sc.scan_id = a.latest_scan_id)::int AS current_applications,
        count(DISTINCT a.id)::int AS affected_applications,
        min(s.created_at) AS first_shipped_at,
        max(s.created_at) AS last_shipped_at,
        array_remove(array_agg(DISTINCT c.version), NULL) AS observed_versions,
        count(*) OVER () AS total
      FROM component_malicious cm
      JOIN malicious_package mp ON mp.id = cm.malicious_package_id
      JOIN component c ON c.id = cm.component_id
      JOIN scan_component sc ON sc.component_id = cm.component_id
      JOIN application a ON a.id = sc.application_id
      JOIN scan s ON s.id = sc.scan_id
      ${where} ${unacknowledged}
      GROUP BY mp.id
      ${presence}
      ${findingOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const items = rowsOf(rows);
    /*
     * `count(*) OVER ()` counts the GROUPED rows but is evaluated before HAVING trims them,
     * so a presence filter would leave the total describing a larger set than the page. Only
     * the unfiltered case can trust the window; the others count separately.
     */
    const total =
      query.presence === "all"
        ? totalFromRows(items)
        : await this.countFiltered(where, unacknowledged, presence);

    const acks = await this.acknowledgementsFor(items.map((r) => r.id));

    return paginate(
      items.map((row) => toFinding(row, acks.get(row.id) ?? null)),
      total,
      query,
    );
  }

  private async countFiltered(where: SQL, unacknowledged: SQL, presence: SQL): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ n: number }>>(sql`
      SELECT count(*)::int AS n FROM (
        SELECT mp.id
        FROM component_malicious cm
        JOIN malicious_package mp ON mp.id = cm.malicious_package_id
        JOIN scan_component sc ON sc.component_id = cm.component_id
        JOIN application a ON a.id = sc.application_id
        ${where} ${unacknowledged}
        GROUP BY mp.id
        ${presence}
      ) grouped
    `);
    return Number(rowsOf(rows)[0]?.n ?? 0);
  }

  /**
   * One report in full, with every application it ever reached.
   *
   * 404 rather than an empty detail when the report exists in the feed but matches nothing
   * here: the page is about a finding, and rendering a report nobody is affected by as though
   * it were one would be alarming for no reason.
   */
  async getById(id: string): Promise<MaliciousFindingDetail> {
    const rows = await this.deps.db.execute<Row<FindingRow & DetailRow>>(sql`
      SELECT
        mp.id, mp.ecosystem, mp.package_name, mp.summary, mp.details, mp.match_mode,
        mp.affected_versions, mp.aliases, mp.sources, mp.reference_url,
        mp.published_at, mp.modified_at, mp.withdrawn_at,
        count(DISTINCT a.id) FILTER (WHERE sc.scan_id = a.latest_scan_id)::int AS current_applications,
        count(DISTINCT a.id)::int AS affected_applications,
        min(s.created_at) AS first_shipped_at,
        max(s.created_at) AS last_shipped_at,
        array_remove(array_agg(DISTINCT c.version), NULL) AS observed_versions
      FROM component_malicious cm
      JOIN malicious_package mp ON mp.id = cm.malicious_package_id
      JOIN component c ON c.id = cm.component_id
      JOIN scan_component sc ON sc.component_id = cm.component_id
      JOIN application a ON a.id = sc.application_id
      JOIN scan s ON s.id = sc.scan_id
      WHERE mp.id = ${id}
      GROUP BY mp.id
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Malicious package finding");

    const acks = await this.acknowledgementsFor([id]);
    const all = await this.allAcknowledgements(id);

    return {
      ...toFinding(row, acks.get(id) ?? null),
      details: row.details,
      affectedVersions: row.affected_versions ?? [],
      modifiedAt: toIso(row.modified_at),
      withdrawnAt: toIso(row.withdrawn_at),
      impacts: await this.impacts(id),
      acknowledgements: all,
    };
  }

  /** Per-application detail: what was affected, when, and whether it is still shipping. */
  private async impacts(id: string): Promise<MaliciousApplicationImpact[]> {
    const rows = await this.deps.db.execute<Row<ImpactRow>>(sql`
      SELECT
        a.id AS application_id, a.name AS application_name, a.status AS application_status,
        bool_or(sc.scan_id = a.latest_scan_id) AS in_current_build,
        array_remove(array_agg(DISTINCT c.version), NULL) AS versions,
        count(DISTINCT sc.scan_id)::int AS builds,
        min(s.created_at) AS first_seen_at,
        max(s.created_at) AS last_seen_at,
        (array_agg(sc.scan_id ORDER BY s.created_at DESC))[1] AS last_scan_id
      FROM component_malicious cm
      JOIN component c ON c.id = cm.component_id
      JOIN scan_component sc ON sc.component_id = cm.component_id
      JOIN application a ON a.id = sc.application_id
      JOIN scan s ON s.id = sc.scan_id
      WHERE cm.malicious_package_id = ${id}
      GROUP BY a.id, a.name, a.status
      -- Still-shipping applications first; they are the ones with work to do today.
      ORDER BY bool_or(sc.scan_id = a.latest_scan_id) DESC, lower(a.name)
    `);

    const perApp = await this.acknowledgementsByApplication(id);

    return rowsOf(rows).map((row) => ({
      applicationId: row.application_id,
      applicationName: row.application_name,
      applicationStatus: row.application_status,
      inCurrentBuild: row.in_current_build === true,
      versions: row.versions ?? [],
      builds: Number(row.builds),
      firstSeenAt: toIso(row.first_seen_at)!,
      lastSeenAt: toIso(row.last_seen_at)!,
      lastScanId: row.last_scan_id,
      acknowledgement: perApp.get(row.application_id) ?? perApp.get(GLOBAL_ACK) ?? null,
    }));
  }

  /**
   * The single acknowledgement to show against each report in a list.
   *
   * An estate-wide acknowledgement wins over a per-application one, because in a list the row
   * describes the whole report rather than any one application.
   */
  private async acknowledgementsFor(ids: string[]): Promise<Map<string, MaliciousAckSummary>> {
    if (ids.length === 0) return new Map();
    const rows = await this.deps.db.execute<Row<AckRow>>(sql`
      SELECT DISTINCT ON (ack.malicious_package_id)
        ack.id, ack.malicious_package_id, ack.application_id, ack.state, ack.note,
        ack.acknowledged_by_email, ack.created_at, app.name AS application_name
      FROM malicious_acknowledgement ack
      LEFT JOIN application app ON app.id = ack.application_id
      WHERE ack.malicious_package_id = ANY(${sql.param(ids)}::text[])
      ORDER BY ack.malicious_package_id, (ack.application_id IS NULL) DESC, ack.created_at DESC
    `);
    return new Map(rowsOf(rows).map((row) => [row.malicious_package_id, toAck(row)]));
  }

  private async allAcknowledgements(id: string): Promise<MaliciousAckSummary[]> {
    const rows = await this.deps.db.execute<Row<AckRow>>(sql`
      SELECT ack.id, ack.malicious_package_id, ack.application_id, ack.state, ack.note,
             ack.acknowledged_by_email, ack.created_at, app.name AS application_name
      FROM malicious_acknowledgement ack
      LEFT JOIN application app ON app.id = ack.application_id
      WHERE ack.malicious_package_id = ${id}
      ORDER BY (ack.application_id IS NULL) DESC, lower(app.name) NULLS FIRST
    `);
    return rowsOf(rows).map(toAck);
  }

  private async acknowledgementsByApplication(id: string): Promise<Map<string, MaliciousAckSummary>> {
    const map = new Map<string, MaliciousAckSummary>();
    for (const ack of await this.allAcknowledgements(id)) {
      map.set(ack.applicationId ?? GLOBAL_ACK, ack);
    }
    return map;
  }
}

/** Sentinel key for the estate-wide acknowledgement, which has no application id. */
const GLOBAL_ACK = " global";

interface FindingRow {
  id: string;
  ecosystem: string;
  package_name: string;
  summary: string | null;
  match_mode: MaliciousMatchMode;
  aliases: string[] | null;
  sources: string[] | null;
  reference_url: string | null;
  published_at: Date | string | null;
  current_applications: number;
  affected_applications: number;
  first_shipped_at: Date | string | null;
  last_shipped_at: Date | string | null;
  observed_versions: string[] | null;
  total?: number | string;
}

interface DetailRow {
  details: string | null;
  affected_versions: string[] | null;
  modified_at: Date | string | null;
  withdrawn_at: Date | string | null;
}

interface ImpactRow {
  application_id: string;
  application_name: string;
  application_status: string;
  in_current_build: boolean;
  versions: string[] | null;
  builds: number;
  first_seen_at: Date | string;
  last_seen_at: Date | string;
  last_scan_id: string;
}

interface AckRow {
  id: string;
  malicious_package_id: string;
  application_id: string | null;
  application_name: string | null;
  state: string;
  note: string;
  acknowledged_by_email: string | null;
  created_at: Date | string;
}

function toAck(row: AckRow): MaliciousAckSummary {
  return {
    id: row.id,
    state: row.state as MaliciousAckSummary["state"],
    note: row.note,
    applicationId: row.application_id,
    applicationName: row.application_name,
    acknowledgedByEmail: row.acknowledged_by_email,
    createdAt: toIso(row.created_at)!,
  };
}

function toFinding(row: FindingRow, ack: MaliciousAckSummary | null): MaliciousFinding {
  return {
    id: row.id,
    ecosystem: row.ecosystem,
    packageName: row.package_name,
    summary: row.summary,
    matchMode: row.match_mode,
    observedVersions: (row.observed_versions ?? []).slice().sort(),
    aliases: row.aliases ?? [],
    sources: row.sources ?? [],
    referenceUrl: row.reference_url,
    publishedAt: toIso(row.published_at),
    currentApplications: Number(row.current_applications),
    affectedApplications: Number(row.affected_applications),
    firstShippedAt: toIso(row.first_shipped_at),
    lastShippedAt: toIso(row.last_shipped_at),
    acknowledgement: ack,
  };
}
