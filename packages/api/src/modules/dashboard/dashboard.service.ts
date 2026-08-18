import { sql } from "drizzle-orm";
import { EXPANDABLE_LIST_CAP } from "@sbom/shared";
import type {
  DashboardStats,
  EcosystemBreakdownEntry,
  PlatformBreakdown,
  TopComponentEntry,
  TopComponentsQuery,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import type { SettingsService } from "../settings/settings.service.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";

/**
 * Estate-wide aggregates for the landing page.
 *
 * Every figure is computed live. At ~1000 applications these run in
 * milliseconds off indexes that already exist for the list and search paths,
 * and a materialised view would introduce the one failure mode a dependency
 * inventory cannot afford: numbers that look authoritative and are quietly
 * hours out of date.
 *
 * "Current use" throughout means `scan_component` rows belonging to some
 * application's `latest_scan_id`. That join is the whole trick — it turns
 * "what is deployed right now" into an equality on an indexed column instead of
 * a correlated max() over the scan history.
 */
export class DashboardService {
  constructor(
    private readonly deps: { db: Database; config: Config; settings: SettingsService },
  ) {}

  async stats(): Promise<DashboardStats> {
    const { db, settings } = this.deps;
    // One definition of "stale", shared with the applications list and the analytics
    // report. Resolved once here so every aggregate in this query agrees.
    const staleInterval = await settings.staleInterval();
    const { staleThresholdDays } = await settings.getPlatformSettings();

    // One round trip. These are independent aggregates over three tables, and
    // issuing them separately would cost three pool checkouts to build a single
    // screen.
    const rows = await db.execute<Row<StatsRow>>(sql`
      SELECT
        (SELECT count(*) FROM application)::int AS app_total,
        (SELECT count(*) FROM application WHERE status = 'active')::int AS app_active,
        (SELECT count(*) FROM application WHERE status = 'inactive')::int AS app_inactive,
        (SELECT count(*) FROM application WHERE status = 'pending_confirmation')::int AS app_pending,
        (SELECT count(*) FROM application
          WHERE status = 'active'
            AND last_scan_at IS NOT NULL
            AND last_scan_at < now() - ${staleInterval})::int AS app_stale,
        (SELECT count(*) FROM application WHERE latest_scan_id IS NULL)::int AS app_never_scanned,
        (SELECT count(*) FROM scan)::int AS scan_total,
        (SELECT count(*) FROM scan WHERE created_at > now() - interval '24 hours')::int AS scan_24h,
        (SELECT count(*) FROM scan WHERE created_at > now() - interval '7 days')::int AS scan_7d,
        (SELECT max(created_at) FROM scan) AS scan_latest_at,
        (SELECT count(*) FROM component)::int AS component_total,
        (SELECT count(DISTINCT sc.component_id)
           FROM scan_component sc
           JOIN application a ON a.latest_scan_id = sc.scan_id)::int AS component_current
    `);

    const r = rowsOf(rows)[0];
    if (!r) throw new Error("dashboard stats query returned no row");

    return {
      applications: {
        total: Number(r.app_total),
        active: Number(r.app_active),
        inactive: Number(r.app_inactive),
        pendingConfirmation: Number(r.app_pending),
        stale: Number(r.app_stale),
        neverScanned: Number(r.app_never_scanned),
      },
      scans: {
        total: Number(r.scan_total),
        last24h: Number(r.scan_24h),
        last7d: Number(r.scan_7d),
        latestAt: toIso(r.scan_latest_at),
      },
      components: {
        distinct: Number(r.component_total),
        inCurrentUse: Number(r.component_current),
      },
      staleThresholdDays,
    };
  }

  /**
   * How many applications currently run each OS and each runtime.
   *
   * Also the source for the applications list's platform filter dropdowns, so
   * the options offered are exactly the values that exist — a filter that lists
   * `wolfi` when nothing runs it is noise, and one that omits it when something
   * does is a dead end.
   *
   * Both halves count DISTINCT applications, not scans. An application appears
   * once per OS and once per runtime it currently ships, which means the runtime
   * numbers legitimately sum to more than the application total for an image
   * carrying both Node and Python.
   */
  async platforms(): Promise<PlatformBreakdown> {
    const { db } = this.deps;

    const osRows = await db.execute<Row<OsRow>>(sql`
      SELECT s.os_name AS name, s.os_version AS version, count(*)::int AS applications,
             -- Same FROM and WHERE as the count, so the list cannot contradict it. One row
             -- per application here (the join is on latest_scan_id), which is why the count
             -- can be count(*) and the names still need no DISTINCT beyond the aggregate's.
             (array_agg(DISTINCT a.name ORDER BY a.name))[1:${sql.raw(String(EXPANDABLE_LIST_CAP))}] AS application_list
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      WHERE a.status <> 'inactive'
      GROUP BY s.os_name, s.os_version
      ORDER BY applications DESC, s.os_name ASC NULLS LAST, s.os_version ASC NULLS LAST
    `);

    /**
     * `jsonb_array_elements` unnests the runtimes array so each entry becomes a
     * row to group by. The LEFT JOIN LATERAL rather than a plain one matters:
     * an inner join would silently drop applications whose runtimes column is
     * NULL or empty, and those are precisely the ones the `unknown` count below
     * needs to see.
     */
    const runtimeRows = await db.execute<Row<RuntimeRow>>(sql`
      SELECT
        r.value ->> 'name'    AS name,
        r.value ->> 'version' AS version,
        count(DISTINCT a.id)::int AS applications,
        (array_agg(DISTINCT a.name ORDER BY a.name))[1:${sql.raw(String(EXPANDABLE_LIST_CAP))}] AS application_list
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.runtimes, '[]'::jsonb)) AS r(value)
      WHERE a.status <> 'inactive'
      GROUP BY r.value ->> 'name', r.value ->> 'version'
      ORDER BY applications DESC, name ASC, version ASC NULLS LAST
    `);

    const unknownRows = await db.execute<Row<{ count: number | string }>>(sql`
      SELECT count(*)::int AS count
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      WHERE a.status <> 'inactive'
        AND s.os_name IS NULL
        AND COALESCE(jsonb_array_length(s.runtimes), 0) = 0
    `);

    return {
      operatingSystems: rowsOf(osRows)
        // A row with no OS is reported through `unknown` instead, so it does not
        // appear as a nameless bar in the breakdown.
        .filter((r) => r.name !== null)
        .map((r) => ({
          name: r.name,
          version: r.version,
          applications: Number(r.applications),
          applicationList: r.application_list ?? [],
        })),
      // A runtime entry with no name cannot happen — the parser only stores
      // named ones — but jsonb carries no guarantee, so it is filtered rather
      // than asserted.
      runtimes: rowsOf(runtimeRows).flatMap((r) =>
        typeof r.name === "string" && r.name !== ""
          ? [
              {
                name: r.name,
                version: r.version,
                applications: Number(r.applications),
                applicationList: r.application_list ?? [],
              },
            ]
          : [],
      ),
      unknown: Number(rowsOf(unknownRows)[0]?.count ?? 0),
    };
  }

  /** Ecosystem mix across every application's current state. */
  async ecosystems(): Promise<EcosystemBreakdownEntry[]> {
    const rows = await this.deps.db.execute<Row<EcosystemRow>>(sql`
      SELECT
        c.ecosystem,
        count(DISTINCT c.id)::int AS components,
        (array_agg(DISTINCT a.name ORDER BY a.name))[1:${sql.raw(String(EXPANDABLE_LIST_CAP))}] AS application_list,
        count(DISTINCT sc.application_id)::int AS applications
      FROM scan_component sc
      JOIN application a ON a.latest_scan_id = sc.scan_id
      -- Libraries only, matching the top-components list. The OS and runtimes
      -- would otherwise appear here as a phantom "generic" / "unknown"
      -- ecosystem that corresponds to no package manager anyone uses.
      JOIN component c ON c.id = sc.component_id AND c.kind = 'library'
      GROUP BY c.ecosystem
      ORDER BY components DESC, c.ecosystem ASC
    `);

    return rowsOf(rows).map((r) => ({
      ecosystem: r.ecosystem,
      components: Number(r.components),
      applications: Number(r.applications),
      applicationList: r.application_list ?? [],
    }));
  }

  /**
   * Packages present in the most applications right now.
   *
   * The blast-radius list: when a package turns out to be a problem, this is
   * the number that decides whether it is one team's afternoon or an
   * organisation-wide exercise. Inactive applications are excluded — counting
   * decommissioned services would inflate exactly the figure being used to
   * judge urgency.
   */
  async topComponents(query: TopComponentsQuery): Promise<TopComponentEntry[]> {
    const rows = query.groupByName
      ? await this.deps.db.execute<Row<TopRow>>(sql`
          SELECT
            min(c.id)::bigint AS id,
            min(c.name) AS name,
            NULL::text AS version,
            c.ecosystem,
            count(DISTINCT sc.application_id)::int AS applications,
            (array_agg(DISTINCT a.name ORDER BY a.name))[1:${sql.raw(String(EXPANDABLE_LIST_CAP))}] AS application_list
          FROM scan_component sc
          JOIN application a ON a.latest_scan_id = sc.scan_id AND a.status <> 'inactive'
          -- Libraries only. The base OS and the language runtime are in the
          -- inventory and are shown as the platform, but ranking "alpine"
          -- alongside "log4j-core" would make this list useless for the
          -- blast-radius judgement it exists to support.
          JOIN component c ON c.id = sc.component_id AND c.kind = 'library'
          GROUP BY lower(c.name), c.ecosystem
          ORDER BY applications DESC, lower(min(c.name)) ASC
          LIMIT ${query.limit}
        `)
      : await this.deps.db.execute<Row<TopRow>>(sql`
          SELECT
            c.id, c.name, c.version, c.ecosystem,
            count(DISTINCT sc.application_id)::int AS applications,
            (array_agg(DISTINCT a.name ORDER BY a.name))[1:${sql.raw(String(EXPANDABLE_LIST_CAP))}] AS application_list
          FROM scan_component sc
          JOIN application a ON a.latest_scan_id = sc.scan_id AND a.status <> 'inactive'
          -- Libraries only. The base OS and the language runtime are in the
          -- inventory and are shown as the platform, but ranking "alpine"
          -- alongside "log4j-core" would make this list useless for the
          -- blast-radius judgement it exists to support.
          JOIN component c ON c.id = sc.component_id AND c.kind = 'library'
          GROUP BY c.id, c.name, c.version, c.ecosystem
          ORDER BY applications DESC, lower(c.name) ASC
          LIMIT ${query.limit}
        `);

    return rowsOf(rows).map((r) => ({
      componentId: String(r.id),
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
      applications: Number(r.applications),
      applicationList: r.application_list ?? [],
    }));
  }
}

interface StatsRow {
  app_total: number | string;
  app_active: number | string;
  app_inactive: number | string;
  app_pending: number | string;
  app_stale: number | string;
  app_never_scanned: number | string;
  scan_total: number | string;
  scan_24h: number | string;
  scan_7d: number | string;
  scan_latest_at: Date | string | null;
  component_total: number | string;
  component_current: number | string;
}

interface EcosystemRow {
  ecosystem: string;
  components: number | string;
  applications: number | string;
  application_list: string[] | null;
}

interface OsRow {
  name: string | null;
  version: string | null;
  applications: number | string;
  application_list: string[] | null;
}

interface RuntimeRow {
  name: string | null;
  version: string | null;
  applications: number | string;
  application_list: string[] | null;
}

interface TopRow {
  id: number | string;
  name: string;
  version: string | null;
  ecosystem: string;
  applications: number | string;
  application_list: string[] | null;
}
