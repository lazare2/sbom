import { sql } from "drizzle-orm";
import type {
  ActivityBucket,
  AnalyticsReport,
  CoverageReport,
  EstateTotals,
  FragmentationEntry,
  NewPackageEntry,
  ReportMeta,
  TopProjectEntry,
  VelocitySummary,
  VulnerabilityReport,
  VulnFilterState,
} from "@sbom/shared";
import { INERT_VULN_FILTER } from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { DashboardService } from "../dashboard/dashboard.service.js";
import { toScanPlatform, type PlatformRow } from "../ingestion/platform-row.js";
import type { SettingsService } from "../settings/settings.service.js";
import { groupMemberPredicate } from "../vulnerabilities/scope.js";
import type { VulnReportService } from "../vulnerabilities/vuln-report.service.js";

/**
 * Estate analytics: the sections shared by the `/analytics` page and the PDF
 * report.
 *
 * Most sections are counts and set comparisons over SBOM contents the platform
 * received, and rank nothing by risk — topProjects measures size and fragmentation
 * measures version spread, and both say so where a reader might assume otherwise.
 *
 * The vulnerability sections are the exception: they report what Grype found when
 * matching those contents against its database. They are omitted entirely (null, not
 * zero) when an administrator has not enabled scanning.
 *
 * Scope conventions, applied uniformly so sections can be read against each
 * other:
 *   - "current" means rows belonging to some application's `latest_scan_id`.
 *   - Inactive applications are excluded everywhere. A decommissioned service
 *     inflating a count is worse than omitting it, because the count is being
 *     used to judge how much work something is.
 *   - Package figures count `kind = 'library'` only, matching the dashboard. The
 *     base OS and the runtime are reported as the platform instead.
 */
export class AnalyticsService {
  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      dashboard: DashboardService;
      settings: SettingsService;
      vulnReport: VulnReportService;
    },
  ) {}

  /**
   * Assemble the whole report.
   *
   * One entry point, so the PDF and the web page are two renderings of one
   * payload. If they each assembled their own, the first divergence would be a
   * printed number nobody can reproduce on screen.
   *
   * The sections are independent queries issued concurrently: they touch three
   * different tables and serialising them would make the report's latency the sum
   * of its parts for no benefit. The one shared input is `periodStart`, computed
   * once here so every section reports the same window even if the request
   * straddles midnight.
   */
  async report(args: {
    periodDays: number;
    generatedBy: string | null;
    limit?: number;
    /**
     * Narrows the vulnerability sections only. Severity has no meaning for churn,
     * coverage or platform mix, so the inventory sections describe the whole estate under
     * every filter — and the page states that rather than leaving it to be inferred.
     */
    vulnFilter?: VulnFilterState;
  }): Promise<AnalyticsReport> {
    const limit = args.limit ?? 10;
    const vulnFilter = args.vulnFilter ?? INERT_VULN_FILTER;
    /*
      The group is the one part of the filter that reaches the inventory sections.

      Severity and scope describe findings, which is why they narrow only the vulnerability
      half — the note on `vulnFilter` above says so. A group describes *applications*, and
      every section here is an aggregate over applications, so leaving churn, coverage and
      the platform mix estate-wide while the vulnerability cards showed one product would
      put two different populations on one page under one heading.
    */
    const groupId = vulnFilter.group;
    const generatedAt = new Date();
    const periodStart = new Date(generatedAt.getTime() - args.periodDays * 86_400_000);

    const [
      totals,
      coverage,
      topPackages,
      topProjects,
      fragmentation,
      newPackages,
      velocity,
      activity,
      ecosystems,
      platforms,
    ] = await Promise.all([
      this.totals(periodStart, groupId),
      this.coverage(limit, groupId),
      this.deps.dashboard.topComponents({ limit, groupByName: false, groupId }),
      this.topProjects(limit, groupId),
      this.fragmentation(limit, groupId),
      this.newPackages(periodStart, limit, groupId),
      this.velocity(periodStart, groupId),
      this.activity(periodStart, args.periodDays, groupId),
      this.deps.dashboard.ecosystems(groupId),
      this.deps.dashboard.platforms(groupId),
    ]);

    /*
     * Vulnerability sections, or null when scanning is disabled.
     *
     * Issued after the concurrent block rather than inside it because it is
     * conditional: when the feature is off there is nothing to query, and adding a
     * settings read plus five aggregates to every report for a deployment that does not
     * use the feature would be pure cost.
     */
    const vulnerabilities = (await this.deps.settings.vulnScanningEnabled())
      ? await this.vulnerabilities(vulnFilter, limit)
      : null;

    const meta: ReportMeta = {
      generatedAt: generatedAt.toISOString(),
      generatedBy: args.generatedBy,
      periodDays: args.periodDays,
      periodStart: periodStart.toISOString(),
      staleThresholdDays: (await this.deps.settings.getPlatformSettings()).staleThresholdDays,
    };

    return {
      meta,
      totals,
      coverage,
      topPackages,
      topProjects,
      fragmentation,
      newPackages,
      velocity,
      activity,
      ecosystems,
      platforms,
      vulnerabilities,
    };
  }

  /**
   * The vulnerability sections of the report.
   *
   * Delegated rather than assembled here: they count what Grype matched, not what the
   * SBOMs contain, and they are the only part of this report a filter can narrow. The
   * queries live beside the app/base-image split they depend on.
   */
  async vulnerabilities(filter: VulnFilterState, limit: number): Promise<VulnerabilityReport> {
    return this.deps.vulnReport.report(filter, limit);
  }


  /** Whole-estate counters. Deliberately identical to the dashboard's, plus the window. */
  async totals(periodStart: Date, groupId: string | null = null): Promise<EstateTotals> {
    const inGroup = groupMemberPredicate(groupId);
    const rows = await this.deps.db.execute<Row<TotalsRow>>(sql`
      SELECT
        (SELECT count(*) FROM application a WHERE ${inGroup})::int AS app_total,
        (SELECT count(*) FROM application a WHERE status = 'active' AND ${inGroup})::int AS app_active,
        (SELECT count(*) FROM application a WHERE status = 'inactive' AND ${inGroup})::int AS app_inactive,
        (SELECT count(*) FROM application a WHERE status = 'pending_confirmation' AND ${inGroup})::int AS app_pending,
        (SELECT count(*) FROM scan s JOIN application a ON a.id = s.application_id
          WHERE ${inGroup})::int AS scan_total,
        (SELECT count(*) FROM scan s JOIN application a ON a.id = s.application_id
          WHERE s.created_at >= ${periodStart} AND ${inGroup})::int AS scan_period,
        (SELECT max(s.created_at) FROM scan s JOIN application a ON a.id = s.application_id
          WHERE ${inGroup}) AS scan_latest_at,
        /*
          Distinct packages anywhere in the group's history, not estate-wide. The component
          table is a global dedup table with no application of its own, so it has to be
          reached through the scans that reference it -- counting it directly would report
          the whole estate's package total under a group's heading.
        */
        (SELECT count(DISTINCT sc.component_id)
           FROM scan_component sc
           JOIN application a ON a.id = sc.application_id
          WHERE ${inGroup})::int AS component_total,
        (SELECT count(DISTINCT sc.component_id)
           FROM scan_component sc
           JOIN application a ON a.latest_scan_id = sc.scan_id
          WHERE ${inGroup})::int AS component_current
    `);

    const r = rowsOf(rows)[0];
    if (!r) throw new Error("analytics totals query returned no row");

    return {
      applications: Number(r.app_total),
      activeApplications: Number(r.app_active),
      inactiveApplications: Number(r.app_inactive),
      pendingApplications: Number(r.app_pending),
      scans: Number(r.scan_total),
      scansInPeriod: Number(r.scan_period),
      distinctPackages: Number(r.component_total),
      packagesInUse: Number(r.component_current),
      latestScanAt: toIso(r.scan_latest_at),
    };
  }

  /**
   * What share of the estate the inventory can see, and which applications it
   * cannot.
   *
   * `covered` is deliberately not `eligible - stale`: an application can be
   * active with no scan at all, which belongs in neither bucket, and computing
   * one from the other would quietly absorb those into "covered".
   */
  async coverage(limit: number, groupId: string | null = null): Promise<CoverageReport> {
    const inGroup = groupMemberPredicate(groupId);
    const { db, config } = this.deps;
    const staleInterval = await this.deps.settings.staleInterval();

    const summaryRows = await db.execute<Row<CoverageSummaryRow>>(sql`
      SELECT
        (SELECT count(*) FROM application a WHERE status = 'active' AND ${inGroup})::int AS eligible,
        (SELECT count(*) FROM application a
          WHERE status = 'active' AND ${inGroup}
            AND last_scan_at IS NOT NULL
            AND last_scan_at >= now() - ${staleInterval})::int AS covered,
        (SELECT count(*) FROM application
          WHERE status = 'active'
            AND last_scan_at IS NOT NULL
            AND last_scan_at < now() - ${staleInterval})::int AS stale,
        (SELECT count(*) FROM application WHERE latest_scan_id IS NULL)::int AS never_scanned,
        (SELECT count(*) FROM application WHERE status = 'pending_confirmation')::int AS pending
    `);

    /**
     * `NULLS FIRST` is the whole point of the ordering: an application that has
     * never reported is the worst case in this list, not a row with a missing
     * value to be sorted to the bottom and overlooked.
     */
    const offenderRows = await db.execute<Row<OffenderRow>>(sql`
      SELECT
        a.id,
        a.name,
        a.last_scan_at,
        CASE
          WHEN a.last_scan_at IS NULL THEN NULL
          ELSE floor(extract(epoch FROM (now() - a.last_scan_at)) / 86400)::int
        END AS days_since_scan
      FROM application a
      WHERE a.status = 'active' AND ${inGroup}
        AND (a.last_scan_at IS NULL OR a.last_scan_at < now() - ${staleInterval})
      ORDER BY a.last_scan_at ASC NULLS FIRST, a.name ASC
      LIMIT ${limit}
    `);

    const s = rowsOf(summaryRows)[0];
    if (!s) throw new Error("analytics coverage query returned no row");

    const eligible = Number(s.eligible);
    const covered = Number(s.covered);

    return {
      eligible,
      covered,
      // Reported as 0 rather than 100 for an empty estate: "100% covered" with
      // nothing registered is the most misleading number this report could print.
      coveragePct: eligible === 0 ? 0 : Math.round((covered / eligible) * 100),
      stale: Number(s.stale),
      neverScanned: Number(s.never_scanned),
      pendingConfirmation: Number(s.pending),
      worstOffenders: rowsOf(offenderRows).map((r) => ({
        applicationId: r.id,
        name: r.name,
        lastScanAt: toIso(r.last_scan_at),
        daysSinceScan: r.days_since_scan === null ? null : Number(r.days_since_scan),
      })),
    };
  }

  /**
   * Applications carrying the most packages in their current build.
   *
   * Reads `scan.component_count`, the figure recorded at ingest, rather than
   * counting `scan_component` rows: it is the same number the scan detail page
   * and the recent-scans list already show, and a report that disagrees with the
   * screen about an application's package count is a bug report waiting to happen.
   */
  async topProjects(limit: number, groupId: string | null = null): Promise<TopProjectEntry[]> {
    const inGroup = groupMemberPredicate(groupId);
    const rows = await this.deps.db.execute<Row<TopProjectRow>>(sql`
      SELECT
        a.id,
        a.name,
        s.component_count::int AS packages,
        s.created_at AS scan_at,
        s.os_name, s.os_version, s.os_pretty, s.runtimes
      FROM application a
      JOIN scan s ON s.id = a.latest_scan_id
      WHERE a.status <> 'inactive' AND ${inGroup}
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
   * Packages the estate currently runs more than one version of.
   *
   * Grouped by `lower(name)` within an ecosystem, matching the dashboard's
   * group-by-name mode, so `React` and `react` are one package rather than two
   * single-version rows that never surface here.
   */
  async fragmentation(limit: number, groupId: string | null = null): Promise<FragmentationEntry[]> {
    const inGroup = groupMemberPredicate(groupId);
    const rows = await this.deps.db.execute<Row<FragmentationRow>>(sql`
      WITH current_components AS (
        SELECT DISTINCT sc.component_id, sc.application_id
        FROM scan_component sc
        JOIN application a ON a.latest_scan_id = sc.scan_id AND a.status <> 'inactive'
        WHERE ${inGroup}
      )
      SELECT
        min(c.name) AS name,
        c.ecosystem,
        count(DISTINCT c.version)::int AS versions,
        count(DISTINCT cc.application_id)::int AS applications,
        /*
         * A sample of the versions, so the row names the actual spread without a
         * drill-down. Sorted as text, which is not semver order — these are
         * illustrative, and the count above is the figure that ranks the row.
         */
        (array_agg(DISTINCT c.version ORDER BY c.version) FILTER (WHERE c.version IS NOT NULL))[1:6]
          AS examples
      FROM current_components cc
      JOIN component c ON c.id = cc.component_id AND c.kind = 'library'
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

  /**
   * Packages whose first appearance anywhere in the estate falls inside the
   * window.
   *
   * First-seen comes from `min(scan_component.created_at)`, which is copied from
   * the scan's own timestamp, not from `component.created_at`. That distinction
   * matters: `component.created_at` is when the row was inserted, so a re-seeded
   * or backfilled database would report every package in the estate as brand new.
   *
   * The most expensive query in the report. The `current_components` CTE bounds
   * the aggregate to packages that are actually still deployed, which is what
   * keeps it from being a full aggregate over the largest table in the schema.
   */
  async newPackages(
    periodStart: Date,
    limit: number,
    groupId: string | null = null,
  ): Promise<NewPackageEntry[]> {
    const inGroup = groupMemberPredicate(groupId);
    // The self-join below compares against a second application row, so it needs its own
    // predicate bound to that alias rather than a reused one silently pointing at `a`.
    const inGroup2 = groupMemberPredicate(groupId, "a2");
    const rows = await this.deps.db.execute<Row<NewPackageRow>>(sql`
      WITH current_components AS (
        SELECT DISTINCT sc.component_id
        FROM scan_component sc
        JOIN application a ON a.latest_scan_id = sc.scan_id AND a.status <> 'inactive'
        WHERE ${inGroup}
      ),
      first_seen AS (
        SELECT sc.component_id, min(sc.created_at) AS first_seen_at
        FROM scan_component sc
        JOIN current_components cc ON cc.component_id = sc.component_id
        GROUP BY sc.component_id
      )
      SELECT
        c.id, c.name, c.version, c.ecosystem,
        fs.first_seen_at,
        (SELECT count(DISTINCT sc2.application_id)::int
           FROM scan_component sc2
           JOIN application a2 ON a2.latest_scan_id = sc2.scan_id AND a2.status <> 'inactive'
             AND ${inGroup2}
          WHERE sc2.component_id = c.id) AS applications
      FROM first_seen fs
      JOIN component c ON c.id = fs.component_id AND c.kind = 'library'
      WHERE fs.first_seen_at >= ${periodStart}
      ORDER BY fs.first_seen_at DESC, lower(c.name) ASC
      LIMIT ${limit}
    `);

    return rowsOf(rows).map((r) => ({
      componentId: String(r.id),
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
      // Non-null by the WHERE clause; the `?? ""` only satisfies the type.
      firstSeenAt: toIso(r.first_seen_at) ?? "",
      applications: Number(r.applications),
    }));
  }

  /**
   * Dependency churn across the estate over the window.
   *
   * Each application's current build is compared against its last build from
   * *before* the window. Two decisions shape what the numbers mean:
   *
   *  1. Comparison is by package name within an ecosystem, not by exact version.
   *     A patch bump is therefore one upgrade, not one addition plus one removal.
   *     Counting identities would make a routine dependency-update round read as
   *     thousands of packages added and thousands removed, which is true but
   *     tells nobody anything.
   *
   *  2. Applications with no build before the window are excluded and counted
   *     separately. Their entire package list would otherwise land in `added`,
   *     and one newly onboarded service would dominate the estate's churn.
   */
  async velocity(periodStart: Date, groupId: string | null = null): Promise<VelocitySummary> {
    const inGroup = groupMemberPredicate(groupId);
    const rows = await this.deps.db.execute<Row<VelocityRow>>(sql`
      WITH baseline AS (
        -- Each application's last build strictly before the window.
        SELECT DISTINCT ON (application_id) application_id, id AS scan_id
        FROM scan
        WHERE created_at < ${periodStart}
        ORDER BY application_id, created_at DESC
      ),
      current_builds AS (
        SELECT a.id AS application_id, a.latest_scan_id AS scan_id
        FROM application a
        WHERE a.status <> 'inactive' AND ${inGroup} AND a.latest_scan_id IS NOT NULL
      ),
      /*
       * Applications with a build on both sides. The scan_id inequality drops
       * the ones whose newest build predates the window: for those the baseline is
       * the current build, so the honest answer is no change, and joining them to
       * themselves would be wasted work.
       */
      pairs AS (
        SELECT c.application_id, b.scan_id AS from_scan, c.scan_id AS to_scan
        FROM current_builds c
        JOIN baseline b ON b.application_id = c.application_id
        WHERE b.scan_id <> c.scan_id
      ),
      pkgs_before AS (
        SELECT p.application_id, lower(cm.name) AS name_key, cm.ecosystem,
               array_agg(DISTINCT coalesce(cm.version, '')) AS versions
        FROM pairs p
        JOIN scan_component sc ON sc.scan_id = p.from_scan
        JOIN component cm ON cm.id = sc.component_id AND cm.kind = 'library'
        GROUP BY p.application_id, lower(cm.name), cm.ecosystem
      ),
      pkgs_after AS (
        SELECT p.application_id, lower(cm.name) AS name_key, cm.ecosystem,
               array_agg(DISTINCT coalesce(cm.version, '')) AS versions
        FROM pairs p
        JOIN scan_component sc ON sc.scan_id = p.to_scan
        JOIN component cm ON cm.id = sc.component_id AND cm.kind = 'library'
        GROUP BY p.application_id, lower(cm.name), cm.ecosystem
      ),
      churn AS (
        SELECT
          count(*) FILTER (WHERE b.name_key IS NULL)::int AS added,
          count(*) FILTER (WHERE n.name_key IS NULL)::int AS removed,
          -- array_agg with DISTINCT sorts its input, so two identical version
          -- sets always compare equal regardless of row order.
          count(*) FILTER (
            WHERE b.name_key IS NOT NULL AND n.name_key IS NOT NULL AND b.versions <> n.versions
          )::int AS upgraded
        FROM pkgs_before b
        FULL OUTER JOIN pkgs_after n USING (application_id, name_key, ecosystem)
      )
      SELECT
        (SELECT count(*) FROM scan WHERE created_at >= ${periodStart})::int AS scans,
        (SELECT count(DISTINCT application_id) FROM scan
          WHERE created_at >= ${periodStart})::int AS apps_scanned,
        (SELECT count(*) FROM pairs)::int AS apps_compared,
        (SELECT count(*) FROM current_builds c
          WHERE NOT EXISTS (
            SELECT 1 FROM baseline b WHERE b.application_id = c.application_id
          ))::int AS apps_without_baseline,
        /*
         * The third bucket: newest build predates the window, so the baseline is
         * the current build and nothing changed. Counted here rather than derived
         * downstream so all three come from one population — subtracting the
         * other two from an application total computed with a different status
         * filter gives a plausible-looking wrong answer.
         */
        (SELECT count(*) FROM current_builds c
          JOIN baseline b ON b.application_id = c.application_id
          WHERE b.scan_id = c.scan_id)::int AS apps_unchanged,
        churn.added, churn.removed, churn.upgraded
      FROM churn
    `);

    const r = rowsOf(rows)[0];
    if (!r) throw new Error("analytics velocity query returned no row");

    return {
      scans: Number(r.scans),
      applicationsScanned: Number(r.apps_scanned),
      applicationsCompared: Number(r.apps_compared),
      applicationsWithoutBaseline: Number(r.apps_without_baseline),
      applicationsUnchanged: Number(r.apps_unchanged),
      packagesAdded: Number(r.added),
      packagesRemoved: Number(r.removed),
      packagesUpgraded: Number(r.upgraded),
    };
  }

  /**
   * Scan activity over the window, bucketed by day or week.
   *
   * `generate_series` supplies the buckets and the scans are LEFT JOINed onto
   * them, so quiet periods appear as zero rather than as absent points. A trend
   * line that silently omits the weeks nothing happened draws a flat estate as a
   * busy one.
   */
  async activity(
    periodStart: Date,
    periodDays: number,
    groupId: string | null = null,
  ): Promise<ActivityBucket[]> {
    const inGroup = groupMemberPredicate(groupId);
    // Daily for windows a reader can still take in as bars, weekly beyond that.
    // Interpolated into the SQL rather than bound, because `date_trunc` and
    // `generate_series` need literals — hence the fixed strings, not the input.
    const unit = periodDays <= 45 ? "day" : "week";
    const step = sql.raw(`interval '1 ${unit}'`);
    const truncUnit = sql.raw(`'${unit}'`);

    const rows = await this.deps.db.execute<Row<ActivityRow>>(sql`
      WITH buckets AS (
        SELECT generate_series(
          date_trunc(${truncUnit}, ${periodStart}::timestamptz),
          date_trunc(${truncUnit}, now()),
          ${step}
        ) AS bucket_start
      )
      SELECT
        b.bucket_start,
        count(s.id)::int AS scans,
        count(DISTINCT s.application_id)::int AS applications
      FROM buckets b
      LEFT JOIN scan s
        /*
         * The lower bound is clamped to the window start, not just to the
         * bucket's own start. date_trunc rounds the first bucket back to
         * midnight (or to Monday), which reaches behind the window and would
         * pull in scans that no other section counts — so the bars would sum to
         * more than the reported scans-in-window, and anyone adding them up
         * would find a discrepancy. The first bar is therefore a partial
         * day or week, which is what it honestly is.
         */
        ON s.created_at >= greatest(b.bucket_start, ${periodStart})
       AND s.created_at < b.bucket_start + ${step}
       /*
         In the join condition, not a WHERE. A WHERE would filter out the rows the LEFT JOIN
         produced for empty buckets, turning a week with no scans into a missing bar rather
         than a zero one -- and the chart would silently change shape rather than show a gap.
       */
       AND EXISTS (
         SELECT 1 FROM application a
         WHERE a.id = s.application_id AND ${inGroup}
       )
      GROUP BY b.bucket_start
      ORDER BY b.bucket_start ASC
    `);

    return rowsOf(rows).map((r) => ({
      bucketStart: toIso(r.bucket_start) ?? "",
      scans: Number(r.scans),
      applications: Number(r.applications),
    }));
  }
}

interface TotalsRow {
  app_total: number | string;
  app_active: number | string;
  app_inactive: number | string;
  app_pending: number | string;
  scan_total: number | string;
  scan_period: number | string;
  scan_latest_at: Date | string | null;
  component_total: number | string;
  component_current: number | string;
}

interface CoverageSummaryRow {
  eligible: number | string;
  covered: number | string;
  stale: number | string;
  never_scanned: number | string;
  pending: number | string;
}

interface OffenderRow {
  id: string;
  name: string;
  last_scan_at: Date | string | null;
  days_since_scan: number | string | null;
}

interface TopProjectRow extends PlatformRow {
  id: string;
  name: string;
  packages: number | string;
  scan_at: Date | string | null;
}

interface FragmentationRow {
  name: string;
  ecosystem: string;
  versions: number | string;
  applications: number | string;
  examples: unknown;
}

interface NewPackageRow {
  id: number | string;
  name: string;
  version: string | null;
  ecosystem: string;
  first_seen_at: Date | string | null;
  applications: number | string;
}

interface VelocityRow {
  scans: number | string;
  apps_scanned: number | string;
  apps_compared: number | string;
  apps_without_baseline: number | string;
  apps_unchanged: number | string;
  added: number | string;
  removed: number | string;
  upgraded: number | string;
}

interface ActivityRow {
  bucket_start: Date | string | null;
  scans: number | string;
  applications: number | string;
}
