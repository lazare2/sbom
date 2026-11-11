import { sql } from "drizzle-orm";
import {
  EMPTY_TEAM_FILTER,
  teamFilterLabel,
  type ActivityBucket,
  type AnalyticsReport,
  type CoverageReport,
  type EstateTotals,
  type NewPackageEntry,
  type TeamFilter,
  type VelocitySummary,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import type { ReadScope } from "../environments/environment.service.js";
import { filteredApplications } from "../inventory/team-filter.js";
import type { ProgressService } from "./progress.service.js";

/**
 * Estate analytics: progress over a window, for the `/analytics` page, the PDF and the monthly
 * report - one payload, three renderings, so a printed figure is always one the screen shows.
 *
 * The questions are about movement: which projects are fixing more than they introduce, how
 * often each one builds, which need attention and why, what each build did to the findings of
 * the build before it, and which packages to upgrade first. What the estate is made of is the
 * Inventory page.
 *
 * Scope conventions, applied uniformly so sections can be read against each other:
 *   - Everything describes applications the reader can see in one estate, optionally
 *     narrowed to squads, tribes or groups. The narrowing applies to every section.
 *   - "current" means rows belonging to some application's `latest_scan_id`.
 *   - Inactive applications are excluded everywhere. A decommissioned service inflating a
 *     count is worse than omitting it, because the count is being used to judge how much work
 *     something is.
 *   - Findings are judged by today's vulnerability database and exclude accepted risks.
 */
export class AnalyticsService {
  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      settings: SettingsService;
      progress: ProgressService;
    },
  ) {}

  /**
   * Assemble the whole report.
   *
   * The one shared input is `periodStart`, computed once here so every section reports the
   * same window even if the request straddles midnight.
   */
  async report(args: {
    periodDays: number;
    generatedBy: string | null;
    limit?: number;
    filter?: TeamFilter;
    /** Every section below describes one estate. There is no all-environments report. */
    scope: ReadScope;
    /** Injected so the scheduled report and the tests decide what "now" is. */
    now?: Date;
  }): Promise<AnalyticsReport> {
    const limit = args.limit ?? 10;
    const filter = args.filter ?? EMPTY_TEAM_FILTER;
    const generatedAt = args.now ?? new Date();
    const periodStart = new Date(generatedAt.getTime() - args.periodDays * 86_400_000);
    const [vulnEnabled, attentionSettings, platform] = await Promise.all([
      this.deps.settings.vulnScanningEnabled(),
      this.deps.settings.getAttentionSettings(),
      this.deps.settings.getPlatformSettings(),
    ]);

    const [totals, coverage, newPackages, velocity, activity, sections] = await Promise.all([
      this.totals(periodStart, args.scope, filter),
      this.coverage(limit, args.scope, filter),
      this.newPackages(periodStart, limit, args.scope, filter),
      this.velocity(periodStart, args.scope, filter),
      this.activity(periodStart, args.periodDays, args.scope, filter),
      this.deps.progress.sections({
        scope: args.scope,
        filter,
        periodStart,
        now: generatedAt,
        settings: attentionSettings,
        vulnEnabled,
      }),
    ]);

    return {
      meta: {
        generatedAt: generatedAt.toISOString(),
        generatedBy: args.generatedBy,
        periodDays: args.periodDays,
        periodStart: periodStart.toISOString(),
        staleThresholdDays: platform.staleThresholdDays,
        environmentName: args.scope.name,
        filter,
        filterLabel: teamFilterLabel(filter),
        vulnScanningEnabled: vulnEnabled,
        attentionSettings,
      },
      totals,
      coverage,
      ...sections,
      newPackages,
      velocity,
      activity,
    };
  }

  /** Whole-estate counters. Deliberately identical to the dashboard's, plus the window. */
  async totals(
    periodStart: Date,
    scope: ReadScope,
    filter: TeamFilter = EMPTY_TEAM_FILTER,
  ): Promise<EstateTotals> {
    const inGroup = filteredApplications(scope, filter);
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
  async coverage(
    limit: number,
    scope: ReadScope,
    filter: TeamFilter = EMPTY_TEAM_FILTER,
  ): Promise<CoverageReport> {
    const inGroup = filteredApplications(scope, filter);
    const { db, config } = this.deps;
    const staleInterval = await this.deps.settings.staleInterval();

    const summaryRows = await db.execute<Row<CoverageSummaryRow>>(sql`
      SELECT
        (SELECT count(*) FROM application a WHERE status = 'active' AND ${inGroup})::int AS eligible,
        (SELECT count(*) FROM application a
          WHERE status = 'active' AND ${inGroup}
            AND last_scan_at IS NOT NULL
            AND last_scan_at >= now() - ${staleInterval})::int AS covered,
        /*
          Every line carries the same scope predicate. These three once read the bare table,
          which counted stale, unscanned and pending applications in every estate -- including
          ones the reader was never granted -- beside an eligible figure that did not.
        */
        (SELECT count(*) FROM application a
          WHERE status = 'active' AND ${inGroup}
            AND last_scan_at IS NOT NULL
            AND last_scan_at < now() - ${staleInterval})::int AS stale,
        (SELECT count(*) FROM application a
          WHERE latest_scan_id IS NULL AND ${inGroup})::int AS never_scanned,
        (SELECT count(*) FROM application a
          WHERE status = 'pending_confirmation' AND ${inGroup})::int AS pending
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
    scope: ReadScope,
    filter: TeamFilter = EMPTY_TEAM_FILTER,
  ): Promise<NewPackageEntry[]> {
    const inGroup = filteredApplications(scope, filter);
    // The self-join below compares against a second application row, so it needs its own
    // predicate bound to that alias rather than a reused one silently pointing at `a`.
    const inGroup2 = filteredApplications(scope, filter, "a2");
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
  async velocity(
    periodStart: Date,
    scope: ReadScope,
    filter: TeamFilter = EMPTY_TEAM_FILTER,
  ): Promise<VelocitySummary> {
    const inGroup = filteredApplications(scope, filter);
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
        -- Scoped like every other line: a bare scan count reported the whole deployment.
        (SELECT count(*) FROM scan s JOIN application a ON a.id = s.application_id
          WHERE s.created_at >= ${periodStart} AND ${inGroup})::int AS scans,
        (SELECT count(DISTINCT s.application_id) FROM scan s JOIN application a ON a.id = s.application_id
          WHERE s.created_at >= ${periodStart} AND ${inGroup})::int AS apps_scanned,
        (SELECT count(*) FROM pairs)::int AS apps_compared,
        (SELECT count(*) FROM current_builds c
          WHERE NOT EXISTS (
            SELECT 1 FROM baseline b WHERE b.application_id = c.application_id
          ))::int AS apps_without_baseline,
        /*
         * The third bucket: newest build predates the window, so the baseline is
         * the current build and nothing changed. Counted here rather than derived
         * downstream so all three come from one population - subtracting the
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
    scope: ReadScope,
    filter: TeamFilter = EMPTY_TEAM_FILTER,
  ): Promise<ActivityBucket[]> {
    const inGroup = filteredApplications(scope, filter);
    // Daily for windows a reader can still take in as bars, weekly beyond that.
    // Interpolated into the SQL rather than bound, because `date_trunc` and
    // `generate_series` need literals - hence the fixed strings, not the input.
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
         * pull in scans that no other section counts - so the bars would sum to
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
