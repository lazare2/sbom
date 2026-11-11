import { sql, type SQL } from "drizzle-orm";
import {
  EXPANDABLE_LIST_CAP,
  teamFilterLabel,
  type EcosystemBreakdownEntry,
  type FragmentationEntry,
  type InventoryOsEntry,
  type InventoryPackageEntry,
  type InventoryReport,
  type InventoryRuntimeEntry,
  type TopProjectEntry,
  type TeamFilter,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { ReadScope } from "../environments/environment.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import { APP_DEPENDENCY_PREDICATE, NOT_SUPPRESSED } from "../vulnerabilities/scope.js";
import { toScanPlatform, type PlatformRow } from "../ingestion/platform-row.js";
import { filteredApplications } from "./team-filter.js";

const CAP = sql.raw(String(EXPANDABLE_LIST_CAP));

/** The OS ecosystems a base image is made of; see VulnReportService for why this list is narrow. */
const OS_ECOSYSTEMS = ["deb", "rpm", "apk"] as const;

/**
 * What the reader's estate is made of: which packages, distributions and runtimes are in use,
 * and what is known against them.
 *
 * Every figure describes current builds of active and unconfirmed applications the reader may
 * see, optionally narrowed to squads, tribes or groups. Inactive applications are excluded
 * everywhere: a decommissioned service inflating a usage count is worse than omitting it.
 *
 * The package tables count application dependencies only. Base-image packages - the
 * distribution's own deb/rpm/apk packages, the OS marker and the runtimes - are reported through
 * the distribution table instead, because ranked together they take every row: a container
 * image carries a hundred times more of them than it carries dependencies.
 */
export class InventoryService {
  constructor(
    private readonly deps: {
      db: Database;
      settings: SettingsService;
      /** @see VulnReportService - ecosystems the active vulnerability database cannot see. */
      uncoveredEcosystems: () => Promise<string[]>;
    },
  ) {}

  async report(args: { scope: ReadScope; filter: TeamFilter; limit: number }): Promise<InventoryReport> {
    const { scope, filter, limit } = args;
    const vulnEnabled = await this.deps.settings.vulnScanningEnabled();
    const apps = filteredApplications(scope, filter);

    /*
      Whether base-image figures can be believed. With only a database that holds no data for
      any OS ecosystem, every distribution would read as clean because nobody asked - so the
      distribution table carries no vulnerability figures at all rather than zeros.
    */
    const uncovered = new Set(vulnEnabled ? await this.deps.uncoveredEcosystems() : []);
    const osAssessable = vulnEnabled && OS_ECOSYSTEMS.some((eco) => !uncovered.has(eco));

    const [totals, mostUsed, mostVulnerable, operatingSystems, runtimes, ecosystems, fragmentation, largestApplications] =
      await Promise.all([
        this.totals(apps),
        this.packages(apps, limit, "usage", vulnEnabled),
        vulnEnabled ? this.packages(apps, limit, "vulnerability", true) : Promise.resolve([]),
        this.operatingSystems(apps, osAssessable),
        this.runtimes(apps),
        this.ecosystems(apps),
        this.fragmentation(apps, limit),
        this.largestApplications(apps, limit),
      ]);

    return {
      generatedAt: new Date().toISOString(),
      environmentId: scope.id,
      environmentName: scope.name,
      filter,
      filterLabel: teamFilterLabel(filter),
      vulnScanningEnabled: vulnEnabled,
      totals,
      mostUsedPackages: mostUsed,
      // Only packages that actually carry something: a "most vulnerable" row with nothing
      // against it would rank clean packages by name and read as a finding.
      mostVulnerablePackages: mostVulnerable.filter((p) => (p.vulnerabilities?.advisories ?? 0) > 0),
      operatingSystems,
      runtimes,
      ecosystems,
      fragmentation,
      largestApplications,
    };
  }

  private async totals(apps: SQL): Promise<InventoryReport["totals"]> {
    const rows = await this.deps.db.execute<Row<Record<string, number | string>>>(sql`
      WITH current_apps AS (
        SELECT a.id, a.latest_scan_id FROM application a
        WHERE a.status <> 'inactive' AND a.latest_scan_id IS NOT NULL AND ${apps}
      )
      SELECT
        (SELECT count(*) FROM current_apps)::int AS applications,
        (SELECT count(*) FROM (
           SELECT DISTINCT lower(c.name), c.ecosystem
           FROM current_apps ca
           JOIN scan_component sc ON sc.scan_id = ca.latest_scan_id
           JOIN component c ON c.id = sc.component_id
           WHERE ${APP_DEPENDENCY_PREDICATE}
         ) p)::int AS packages,
        (SELECT count(DISTINCT (s.os_name, s.os_version)) FROM current_apps ca
           JOIN scan s ON s.id = ca.latest_scan_id WHERE s.os_name IS NOT NULL)::int AS operating_systems,
        (SELECT count(DISTINCT (r.value ->> 'name', r.value ->> 'version')) FROM current_apps ca
           JOIN scan s ON s.id = ca.latest_scan_id
           CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.runtimes, '[]'::jsonb)) AS r(value))::int AS runtimes,
        (SELECT count(*) FROM current_apps ca JOIN scan s ON s.id = ca.latest_scan_id
           WHERE s.os_name IS NULL AND COALESCE(jsonb_array_length(s.runtimes), 0) = 0)::int AS unknown_platform
    `);
    const r = rowsOf(rows)[0] ?? {};
    return {
      applications: Number(r.applications ?? 0),
      packages: Number(r.packages ?? 0),
      operatingSystems: Number(r.operating_systems ?? 0),
      runtimes: Number(r.runtimes ?? 0),
      unknownPlatform: Number(r.unknown_platform ?? 0),
    };
  }

  /**
   * Application dependencies in current builds, ranked by reach or by what is known against them.
   *
   * One package is a name within an ecosystem, matching package search and the fragmentation
   * table. Advisory counts are distinct advisories across the versions in use, accepted risks
   * excluded through the shared predicate.
   */
  private async packages(
    apps: SQL,
    limit: number,
    rankBy: "usage" | "vulnerability",
    vulnEnabled: boolean,
  ): Promise<InventoryPackageEntry[]> {
    const order =
      rankBy === "usage"
        ? sql`p.applications DESC, coalesce(va.critical, 0) DESC, lower(p.name) ASC, p.ecosystem ASC`
        : sql`coalesce(va.critical, 0) DESC, coalesce(va.high, 0) DESC, coalesce(va.vulnerable_apps, 0) DESC,
              coalesce(va.advisories, 0) DESC, lower(p.name) ASC, p.ecosystem ASC`;

    const findings = vulnEnabled
      ? sql`findings AS (
          SELECT cur.name_key, cur.ecosystem, cur.application_id, v.id AS vulnerability_id,
                 v.severity, v.known_exploited, cv.fix_state
          FROM cur
          JOIN component c   ON c.id = cur.component_id
          JOIN application a ON a.id = cur.application_id
          JOIN component_vulnerability cv ON cv.component_id = cur.component_id
          JOIN vulnerability v ON v.id = cv.vulnerability_id
          WHERE ${NOT_SUPPRESSED}
        ),
        vuln AS (
          SELECT name_key, ecosystem,
                 count(DISTINCT vulnerability_id)::int AS advisories,
                 count(DISTINCT vulnerability_id) FILTER (WHERE severity = 'critical')::int AS critical,
                 count(DISTINCT vulnerability_id) FILTER (WHERE severity = 'high')::int AS high,
                 count(DISTINCT vulnerability_id) FILTER (WHERE known_exploited)::int AS kev,
                 count(DISTINCT vulnerability_id) FILTER (WHERE fix_state = 'fixed')::int AS fixable,
                 count(DISTINCT application_id)::int AS vulnerable_apps
          FROM findings
          GROUP BY name_key, ecosystem
        )`
      : sql`vuln AS (
          SELECT NULL::text AS name_key, NULL::text AS ecosystem, 0 AS advisories, 0 AS critical,
                 0 AS high, 0 AS kev, 0 AS fixable, 0 AS vulnerable_apps
          WHERE FALSE
        )`;

    const rows = await this.deps.db.execute<Row<PackageRow>>(sql`
      WITH cur AS (
        SELECT sc.application_id, a.name AS application_name, c.id AS component_id,
               lower(c.name) AS name_key, c.name, c.version, c.ecosystem, c.vuln_scanned_at
        FROM application a
        JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
        JOIN component c ON c.id = sc.component_id
        WHERE a.status <> 'inactive' AND ${apps} AND ${APP_DEPENDENCY_PREDICATE}
      ),
      p AS (
        SELECT name_key, ecosystem, min(name) AS name,
               count(DISTINCT application_id)::int AS applications,
               (array_agg(DISTINCT application_name ORDER BY application_name))[1:${CAP}] AS application_list,
               count(DISTINCT coalesce(version, ''))::int AS versions,
               (array_agg(DISTINCT version ORDER BY version) FILTER (WHERE version IS NOT NULL))[1:6] AS version_sample,
               coalesce(bool_or(vuln_scanned_at IS NOT NULL), false) AS assessed
        FROM cur
        GROUP BY name_key, ecosystem
      ),
      ${findings}
      SELECT p.*, va.advisories, va.critical, va.high, va.kev, va.fixable, va.vulnerable_apps
      FROM p
      LEFT JOIN vuln va ON va.name_key = p.name_key AND va.ecosystem = p.ecosystem
      ORDER BY ${order}
      LIMIT ${limit}
    `);

    return rowsOf(rows).map((r) => ({
      name: r.name,
      ecosystem: r.ecosystem,
      applications: Number(r.applications),
      applicationList: r.application_list ?? [],
      versions: Number(r.versions),
      versionSample: (r.version_sample ?? []).filter((v): v is string => typeof v === "string"),
      vulnerabilities: vulnEnabled
        ? {
            assessed: r.assessed === true,
            advisories: Number(r.advisories ?? 0),
            critical: Number(r.critical ?? 0),
            high: Number(r.high ?? 0),
            knownExploited: Number(r.kev ?? 0),
            fixable: Number(r.fixable ?? 0),
            vulnerableApplications: Number(r.vulnerable_apps ?? 0),
          }
        : null,
    }));
  }

  /**
   * Distributions by how many applications run them, with their base-image findings.
   *
   * Findings come from each application's per-build summary for its current build: the same
   * figures every other page shows, so a distribution's total is the sum of what its
   * applications' own pages say. An application whose build has not been matched yet has no
   * summary and is left out of the averages rather than counted as clean.
   */
  private async operatingSystems(apps: SQL, assessable: boolean): Promise<InventoryOsEntry[]> {
    const rows = await this.deps.db.execute<Row<OsRow>>(sql`
      SELECT s.os_name AS name, s.os_version AS version, min(s.os_pretty) AS pretty,
             count(*)::int AS applications,
             (array_agg(a.name ORDER BY a.name))[1:${CAP}] AS application_list,
             count(vs.scan_id)::int AS assessed,
             coalesce(sum(vs.os_findings), 0)::int AS findings,
             coalesce(sum(vs.os_critical), 0)::int AS critical,
             coalesce(sum(vs.os_high), 0)::int AS high,
             coalesce(sum(vs.os_fixable), 0)::int AS fixable,
             coalesce(sum(vs.os_known_exploited), 0)::int AS kev
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      LEFT JOIN scan_vuln_summary vs ON vs.scan_id = s.id
      WHERE a.status <> 'inactive' AND ${apps} AND s.os_name IS NOT NULL
      GROUP BY s.os_name, s.os_version
      ORDER BY applications DESC, s.os_name ASC, s.os_version ASC NULLS LAST
    `);

    return rowsOf(rows).map((r) => {
      const assessed = Number(r.assessed);
      const avg = (total: number) => (assessed === 0 ? null : Math.round((total / assessed) * 10) / 10);
      const findings = Number(r.findings);
      const critical = Number(r.critical);
      const high = Number(r.high);
      return {
        name: r.name,
        version: r.version,
        pretty: r.pretty,
        applications: Number(r.applications),
        applicationList: r.application_list ?? [],
        vulnerabilities: assessable
          ? {
              assessedApplications: assessed,
              findings,
              critical,
              high,
              fixable: Number(r.fixable),
              knownExploited: Number(r.kev),
              averageFindings: avg(findings),
              averageCritical: avg(critical),
              averageHigh: avg(high),
            }
          : null,
      };
    });
  }

  private async runtimes(apps: SQL): Promise<InventoryRuntimeEntry[]> {
    const rows = await this.deps.db.execute<Row<RuntimeRow>>(sql`
      SELECT r.value ->> 'name' AS name, r.value ->> 'version' AS version,
             count(DISTINCT a.id)::int AS applications,
             (array_agg(DISTINCT a.name ORDER BY a.name))[1:${CAP}] AS application_list
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.runtimes, '[]'::jsonb)) AS r(value)
      WHERE a.status <> 'inactive' AND ${apps}
      GROUP BY r.value ->> 'name', r.value ->> 'version'
      ORDER BY applications DESC, name ASC, version ASC NULLS LAST
    `);
    return rowsOf(rows).flatMap((r) =>
      typeof r.name === "string" && r.name !== ""
        ? [{ name: r.name, version: r.version, applications: Number(r.applications), applicationList: r.application_list ?? [] }]
        : [],
    );
  }

  /** Distinct application dependencies per package manager; base-image packages are the distribution table. */
  private async ecosystems(apps: SQL): Promise<EcosystemBreakdownEntry[]> {
    const rows = await this.deps.db.execute<Row<EcosystemRow>>(sql`
      SELECT c.ecosystem,
             count(DISTINCT c.id)::int AS components,
             count(DISTINCT a.id)::int AS applications,
             (array_agg(DISTINCT a.name ORDER BY a.name))[1:${CAP}] AS application_list
      FROM application a
      JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
      JOIN component c ON c.id = sc.component_id
      WHERE a.status <> 'inactive' AND ${apps} AND ${APP_DEPENDENCY_PREDICATE}
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
   * Applications carrying the most packages in their current build. Moved here from Analytics.
   * Reads scan.component_count, the figure recorded at ingest, so it matches the scan pages.
   */
  private async largestApplications(apps: SQL, limit: number): Promise<TopProjectEntry[]> {
    const rows = await this.deps.db.execute<
      Row<PlatformRow & { id: string; name: string; packages: number | string; scan_at: Date | string | null }>
    >(sql`
      SELECT a.id, a.name, s.component_count::int AS packages, s.created_at AS scan_at,
             s.os_name, s.os_version, s.os_pretty, s.runtimes
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      WHERE a.status <> 'inactive' AND ${apps}
      ORDER BY s.component_count DESC, a.name ASC
      LIMIT ${limit}
    `);
    return rowsOf(rows).map((r) => ({
      applicationId: r.id,
      name: r.name,
      packages: Number(r.packages),
      scanAt: toIso(r.scan_at),
      platform: toScanPlatform(r).summary,
    }));
  }

  /**
   * Application dependencies run in more than one version at once, grouped by lower(name)
   * within an ecosystem. Moved here from Analytics.
   */
  private async fragmentation(apps: SQL, limit: number): Promise<FragmentationEntry[]> {
    const rows = await this.deps.db.execute<Row<FragmentationRow>>(sql`
      WITH current_components AS (
        SELECT DISTINCT sc.component_id, sc.application_id
        FROM application a
        JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
        WHERE a.status <> 'inactive' AND ${apps}
      )
      SELECT min(c.name) AS name, c.ecosystem,
             count(DISTINCT c.version)::int AS versions,
             count(DISTINCT cc.application_id)::int AS applications,
             (array_agg(DISTINCT c.version ORDER BY c.version) FILTER (WHERE c.version IS NOT NULL))[1:6] AS examples
      FROM current_components cc
      JOIN component c ON c.id = cc.component_id
      -- Application dependencies only. Distribution packages vary with every base image, so
      -- counted here they would fill the table with libc6 and busybox - base-image churn the
      -- distribution table already reports, crowding out the upgrades a team can choose to do.
      WHERE ${APP_DEPENDENCY_PREDICATE}
      GROUP BY lower(c.name), c.ecosystem
      HAVING count(DISTINCT c.version) > 1
      ORDER BY versions DESC, applications DESC, lower(min(c.name)) ASC
      LIMIT ${limit}
    `);
    return rowsOf(rows).map((r) => ({
      name: r.name,
      ecosystem: r.ecosystem,
      versions: Number(r.versions),
      applications: Number(r.applications),
      examples: Array.isArray(r.examples) ? r.examples.filter((v): v is string => typeof v === "string") : [],
    }));
  }
}

interface PackageRow {
  name: string;
  ecosystem: string;
  applications: number | string;
  application_list: string[] | null;
  versions: number | string;
  version_sample: Array<string | null> | null;
  assessed: boolean;
  advisories: number | string | null;
  critical: number | string | null;
  high: number | string | null;
  kev: number | string | null;
  fixable: number | string | null;
  vulnerable_apps: number | string | null;
}

interface OsRow {
  name: string;
  version: string | null;
  pretty: string | null;
  applications: number | string;
  application_list: string[] | null;
  assessed: number | string;
  findings: number | string;
  critical: number | string;
  high: number | string;
  fixable: number | string;
  kev: number | string;
}

interface RuntimeRow {
  name: string | null;
  version: string | null;
  applications: number | string;
  application_list: string[] | null;
}

interface EcosystemRow {
  ecosystem: string;
  components: number | string;
  applications: number | string;
  application_list: string[] | null;
}

interface FragmentationRow {
  name: string;
  ecosystem: string;
  versions: number | string;
  applications: number | string;
  examples: unknown;
}
