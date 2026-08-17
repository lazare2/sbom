import { sql } from "drizzle-orm";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import type { ParsedFinding, ScannablePackage, VulnerabilityScanner } from "../../services/scanner/index.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { Logger } from "../ingestion/ingestion.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import { SCOPE_GROUP_EXPR } from "./scope.js";

/**
 * The match sweep: brings every package up to date against the installed database.
 *
 * There is no job queue. The work list is derived from two columns on `component`:
 *
 *   vuln_scanned_at IS NULL            -- never matched
 *   OR vuln_db_built_at IS NULL        -- matched before provenance was recorded
 *   OR vuln_db_built_at < <db build>   -- matched against an older database
 *
 * That single predicate covers every case that needs work — a newly ingested package,
 * the first time scanning is enabled, a freshly published database, and a sweep that
 * was killed halfway — and it is why a restart needs no recovery logic: there was
 * never a queue to lose, only a fact to recompute.
 *
 * It is also why "when the database updates, every package gets rescanned" costs
 * nothing to implement. Installing a new database moves the build timestamp, which
 * makes every previously-scanned component match the predicate again. Nothing has to
 * enumerate or enqueue anything.
 */

/** Bind-parameter ceiling is 65535; these keep the widest insert comfortably under it. */
const VULN_UPSERT_CHUNK = 500;
const FINDING_UPSERT_CHUNK = 1000;

export interface SweepProgress {
  batches: number;
  componentsScanned: number;
  findingsStored: number;
  /** Non-zero means grype attributed findings to ids we never submitted — see the parser. */
  unmapped: number;
}

export interface SweepOutcome extends SweepProgress {
  status: "completed" | "disabled" | "unavailable" | "no-database" | "already-running" | "failed";
  message: string;
  /** Components still awaiting a match when the sweep stopped. */
  remaining: number;
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export class SweepService {
  /**
   * In-process guard.
   *
   * Prevents the scheduler, an ingest trigger and an admin action overlapping inside
   * one process, which is the realistic collision. Across replicas a duplicate sweep
   * is possible and harmless: every write below is an idempotent upsert keyed on
   * (component, advisory), so two workers matching the same package produce the same
   * rows rather than double-counting anything. Guarding that case with a distributed
   * lock would add a failure mode to protect against wasted CPU.
   */
  private running = false;
  private lastFinishedAt: Date | null = null;

  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      scanner: VulnerabilityScanner;
      settings: SettingsService;
      logger: Logger;
    },
  ) {}

  get isRunning(): boolean {
    return this.running;
  }

  get finishedAt(): Date | null {
    return this.lastFinishedAt;
  }

  /**
   * Brings the component set up to date, in batches, until nothing is pending.
   *
   * `maxBatches` bounds one invocation so an ingest-triggered sweep of a huge new
   * application cannot run for an unbounded time — the scheduler picks up whatever is
   * left. Returning a status rather than throwing is deliberate: every caller is a
   * background trigger that must not fail because scanning happens to be off.
   */
  async sweep(options: { maxBatches?: number; reason: string } = { reason: "manual" }): Promise<SweepOutcome> {
    const empty: SweepProgress = { batches: 0, componentsScanned: 0, findingsStored: 0, unmapped: 0 };

    if (this.running) {
      return { ...empty, status: "already-running", message: "A sweep is already running.", remaining: 0 };
    }

    if (!(await this.deps.settings.vulnScanningEnabled())) {
      return {
        ...empty,
        status: "disabled",
        message: "Vulnerability scanning is disabled.",
        remaining: 0,
      };
    }

    const availability = await this.deps.scanner.availability();
    if (!availability.available) {
      return {
        ...empty,
        status: "unavailable",
        message: "The grype binary is not available.",
        remaining: await this.pendingCount(null),
      };
    }

    const dbStatus = await this.deps.scanner.dbStatus();
    if (!dbStatus.present || dbStatus.builtAt === null) {
      return {
        ...empty,
        status: "no-database",
        message:
          "No vulnerability database is installed. Update it from the admin panel, or import an archive.",
        remaining: await this.pendingCount(null),
      };
    }

    this.running = true;
    const watermark = dbStatus.builtAt;
    const progress: SweepProgress = { ...empty };
    const maxBatches = options.maxBatches ?? Number.POSITIVE_INFINITY;

    try {
      while (progress.batches < maxBatches) {
        const packages = await this.claimBatch(watermark, this.deps.config.GRYPE_BATCH_SIZE);
        if (packages.length === 0) break;

        const result = await this.deps.scanner.match(packages);
        progress.batches++;
        progress.unmapped += result.unmappedFindings;

        if (result.unmappedFindings > 0) {
          // Loud, because this is the failure that would quietly understate every
          // count on every dashboard.
          this.deps.logger.warn(
            { unmapped: result.unmappedFindings, batch: packages.length },
            "grype reported findings for ids that were not submitted",
          );
        }

        await this.storeFindings(result.findings);
        await this.markScanned(
          result.submittedComponentIds,
          result.dbBuiltAt ?? watermark,
        );

        progress.componentsScanned += packages.length;
        progress.findingsStored += result.findings.length;
      }

      // Snapshots are recomputed once at the end rather than per batch: a scan's
      // counts are only meaningful when all of its components have been matched, and
      // recomputing per batch would publish partial figures that briefly look like a
      // drop in exposure.
      await this.refreshScanSummaries(watermark, availability.version);

      const remaining = await this.pendingCount(watermark);
      this.lastFinishedAt = new Date();

      this.deps.logger.info(
        { ...progress, remaining, reason: options.reason, dbBuiltAt: watermark.toISOString() },
        "vulnerability sweep finished",
      );

      return {
        ...progress,
        status: "completed",
        message:
          remaining === 0
            ? `Matched ${progress.componentsScanned} packages against the database.`
            : `Matched ${progress.componentsScanned} packages; ${remaining} still pending.`,
        remaining,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.deps.logger.warn({ err, ...progress, reason: options.reason }, "vulnerability sweep failed");
      return {
        ...progress,
        status: "failed",
        message,
        remaining: await this.pendingCount(watermark).catch(() => 0),
      };
    } finally {
      this.running = false;
    }
  }

  // -------------------------------------------------------------------------
  // Work claiming
  // -------------------------------------------------------------------------

  /**
   * The pending predicate, in one place.
   *
   * Shared by the claim query and the pending count so the number an administrator
   * sees is the same set the sweep will actually process — two hand-written variants
   * of this expression would eventually disagree.
   */
  private pendingPredicate(watermark: Date | null) {
    if (watermark === null) {
      return sql`(c.vuln_scanned_at IS NULL OR c.vuln_db_built_at IS NULL)`;
    }
    return sql`(
      c.vuln_scanned_at IS NULL
      OR c.vuln_db_built_at IS NULL
      OR c.vuln_db_built_at < ${watermark.toISOString()}::timestamptz
    )`;
  }

  private async pendingCount(watermark: Date | null): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ pending: number | string }>>(sql`
      SELECT count(*)::int AS pending FROM component c WHERE ${this.pendingPredicate(watermark)}
    `);
    return Number(rowsOf(rows)[0]?.pending ?? 0);
  }

  /**
   * Takes the next batch of components needing a match.
   *
   * `FOR UPDATE SKIP LOCKED` so concurrent workers partition the set rather than
   * fighting over the same rows. Ordered by id for a stable, resumable walk.
   *
   * Only `kind`-agnostic: OS and runtime packages are matched too. They are reported
   * separately from application dependencies everywhere, but they are genuinely
   * vulnerable and excluding them from matching would make the base-image figure
   * impossible to produce at all.
   */
  private async claimBatch(watermark: Date, limit: number): Promise<ScannablePackage[]> {
    const rows = await this.deps.db.execute<
      Row<{
        id: number | string;
        name: string;
        version: string | null;
        purl: string | null;
        ecosystem: string;
      }>
    >(sql`
      SELECT c.id, c.name, c.version, c.purl, c.ecosystem
      FROM component c
      WHERE ${this.pendingPredicate(watermark)}
      ORDER BY c.id
      LIMIT ${limit}
      FOR UPDATE SKIP LOCKED
    `);

    return rowsOf(rows).map((row) => ({
      componentId: Number(row.id),
      name: row.name,
      version: row.version,
      purl: row.purl,
      ecosystem: row.ecosystem,
    }));
  }

  // -------------------------------------------------------------------------
  // Storing results
  // -------------------------------------------------------------------------

  /**
   * Upserts advisories and the pairings that reference them.
   *
   * Advisory rows are written first because `component_vulnerability` has a foreign
   * key to them. Both writes are upserts keyed on natural identity, which is what
   * makes the whole sweep safely repeatable — re-running it against the same database
   * produces no change rather than duplicate findings.
   */
  private async storeFindings(findings: readonly ParsedFinding[]): Promise<void> {
    if (findings.length === 0) return;

    /*
     * One advisory can affect many packages in a batch, so the same id arrives
     * repeatedly. Collapsing first keeps the upsert proportional to distinct
     * advisories rather than to findings — a batch of 5,000 packages routinely
     * carries thousands of findings across a few hundred advisories.
     */
    const advisories = new Map<string, ParsedFinding>();
    for (const finding of findings) {
      const existing = advisories.get(finding.vulnerabilityId);
      // Keep whichever copy knows the most: alias and score coverage can differ
      // between two matches of the same advisory.
      if (!existing || finding.aliases.length > existing.aliases.length) {
        advisories.set(finding.vulnerabilityId, finding);
      }
    }

    for (const batch of chunk([...advisories.values()], VULN_UPSERT_CHUNK)) {
      const values = batch.map(
        (f) => sql`(
          ${f.vulnerabilityId},
          ${f.severity},
          ${f.cvssBaseScore},
          ${f.cvssVector},
          ${f.epssScore},
          ${f.epssPercentile},
          ${f.knownExploited},
          ${f.description},
          ${f.dataSource},
          ${f.namespace},
          ${sql.param(f.aliases)}::text[],
          ${sql.param(f.urls)}::text[]
        )`,
      );

      await this.deps.db.execute(sql`
        INSERT INTO vulnerability (
          id, severity, cvss_base_score, cvss_vector, epss_score, epss_percentile,
          known_exploited, description, data_source, namespace, aliases, urls
        )
        VALUES ${sql.join(values, sql`, `)}
        ON CONFLICT (id) DO UPDATE SET
          severity = EXCLUDED.severity,
          cvss_base_score = EXCLUDED.cvss_base_score,
          cvss_vector = EXCLUDED.cvss_vector,
          epss_score = EXCLUDED.epss_score,
          epss_percentile = EXCLUDED.epss_percentile,
          known_exploited = EXCLUDED.known_exploited,
          description = EXCLUDED.description,
          data_source = EXCLUDED.data_source,
          namespace = EXCLUDED.namespace,
          /*
           * Union rather than replace: different matches of the same advisory can each
           * know a different subset of its CVE ids, and dropping the ones this match did
           * not mention would break CVE search intermittently.
           *
           * COALESCE is load-bearing. array_agg over an empty set returns NULL, not an
           * empty array, so an advisory with no aliases at all violated the NOT NULL
           * constraint. That is not a rare case: OS advisories are reported with the CVE
           * as the primary id and therefore carry no aliases, so this broke every
           * estate containing deb, rpm or apk packages — which is nearly all of them.
           */
          aliases = COALESCE((
            SELECT array_agg(DISTINCT a ORDER BY a)
            FROM unnest(vulnerability.aliases || EXCLUDED.aliases) AS a
          ), '{}'::text[]),
          urls = COALESCE((
            SELECT array_agg(DISTINCT u ORDER BY u)
            FROM unnest(vulnerability.urls || EXCLUDED.urls) AS u
          ), '{}'::text[]),
          updated_at = now()
      `);
    }

    for (const batch of chunk(findings, FINDING_UPSERT_CHUNK)) {
      const values = batch.map(
        (f) => sql`(
          ${f.componentId},
          ${f.vulnerabilityId},
          ${f.fixState},
          ${sql.param(f.fixVersions)}::text[],
          ${f.matchType}
        )`,
      );

      await this.deps.db.execute(sql`
        INSERT INTO component_vulnerability (
          component_id, vulnerability_id, fix_state, fix_versions, match_type
        )
        VALUES ${sql.join(values, sql`, `)}
        ON CONFLICT (component_id, vulnerability_id) DO UPDATE SET
          fix_state = EXCLUDED.fix_state,
          fix_versions = EXCLUDED.fix_versions,
          match_type = EXCLUDED.match_type,
          last_confirmed_at = now()
      `);
    }
  }

  /**
   * Marks a batch matched, and clears findings that the current database no longer
   * reports.
   *
   * The delete is what keeps the data honest in both directions. Advisories get
   * withdrawn, and matching logic gets corrected between grype releases; without this,
   * a finding retracted upstream would persist forever and no amount of upgrading
   * would clear it from the dashboards. Scoped to the components just processed and to
   * pairings not confirmed by this pass.
   */
  private async markScanned(componentIds: readonly number[], dbBuiltAt: Date): Promise<void> {
    if (componentIds.length === 0) return;
    const ids = sql`${sql.param(componentIds)}::bigint[]`;
    const stamp = dbBuiltAt.toISOString();

    await this.deps.db.execute(sql`
      DELETE FROM component_vulnerability cv
      WHERE cv.component_id = ANY(${ids})
        AND cv.last_confirmed_at < ${stamp}::timestamptz - interval '1 second'
        AND cv.last_confirmed_at < now() - interval '1 second'
    `);

    await this.deps.db.execute(sql`
      UPDATE component
      SET vuln_scanned_at = now(), vuln_db_built_at = ${stamp}::timestamptz
      WHERE id = ANY(${ids})
    `);
  }

  // -------------------------------------------------------------------------
  // Per-scan snapshots
  // -------------------------------------------------------------------------

  /**
   * Recomputes the per-scan severity snapshot for every scan whose components are now
   * fully matched.
   *
   * Two jobs, as documented on `scan_vuln_summary`: it is the exposure trend, and it
   * is the pre-aggregation that makes "Top 10 vulnerable applications" read one row
   * per application instead of joining millions of `scan_component` rows.
   *
   * Suppressed findings are excluded here rather than at read time, so every ranking,
   * dashboard tile and report figure derives from one consistent definition of what
   * counts. A suppression added later is picked up by the next sweep.
   */
  private async refreshScanSummaries(watermark: Date, grypeVersion: string | null): Promise<void> {
    const stamp = watermark.toISOString();

    await this.deps.db.execute(sql`
      WITH
      -- Scans whose every component has been matched against this database build.
      -- A partially matched scan is skipped rather than summarised, because half a
      -- scan's findings reads as a real improvement in exposure.
      ready AS (
        SELECT s.id AS scan_id, s.application_id
        FROM scan s
        WHERE NOT EXISTS (
          SELECT 1
          FROM scan_component sc
          JOIN component c ON c.id = sc.component_id
          WHERE sc.scan_id = s.id
            AND (
              c.vuln_scanned_at IS NULL
              OR c.vuln_db_built_at IS NULL
              OR c.vuln_db_built_at < ${stamp}::timestamptz
            )
        )
      ),
      -- Findings per ready scan, with the app/base-image split and suppressions
      -- removed. The app/base-image side comes from scope.ts, which keys on ecosystem
      -- rather than kind: individual deb and apk packages are stored as libraries, so
      -- splitting on kind would file the entire base image as application dependencies.
      findings AS (
        SELECT
          r.scan_id,
          r.application_id,
          ${SCOPE_GROUP_EXPR} AS scope_group,
          c.id AS component_id,
          v.id AS vulnerability_id,
          v.severity,
          v.known_exploited,
          cv.fix_state
        FROM ready r
        JOIN scan_component sc ON sc.scan_id = r.scan_id
        JOIN component c ON c.id = sc.component_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability v ON v.id = cv.vulnerability_id
        WHERE NOT EXISTS (
          SELECT 1 FROM vulnerability_suppression sup
          WHERE sup.vulnerability_id = v.id
            AND (sup.expires_at IS NULL OR sup.expires_at > now())
            AND (sup.component_id IS NULL OR sup.component_id = c.id)
            AND (sup.application_id IS NULL OR sup.application_id = r.application_id)
        )
      ),
      agg AS (
        SELECT
          r.scan_id,
          r.application_id,
          count(*) FILTER (WHERE f.scope_group = 'app')::int AS app_findings,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.severity = 'critical')::int AS app_critical,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.severity = 'high')::int AS app_high,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.severity = 'medium')::int AS app_medium,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.severity = 'low')::int AS app_low,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.severity = 'negligible')::int AS app_negligible,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.severity = 'unknown')::int AS app_unknown,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.fix_state = 'fixed')::int AS app_fixable,
          count(*) FILTER (WHERE f.scope_group = 'app' AND f.known_exploited)::int AS app_kev,
          count(DISTINCT f.component_id) FILTER (WHERE f.scope_group = 'app')::int AS app_packages,
          count(*) FILTER (WHERE f.scope_group = 'os')::int AS os_findings,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.severity = 'critical')::int AS os_critical,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.severity = 'high')::int AS os_high,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.severity = 'medium')::int AS os_medium,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.severity = 'low')::int AS os_low,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.severity = 'negligible')::int AS os_negligible,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.severity = 'unknown')::int AS os_unknown,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.fix_state = 'fixed')::int AS os_fixable,
          count(*) FILTER (WHERE f.scope_group = 'os' AND f.known_exploited)::int AS os_kev,
          count(DISTINCT f.component_id) FILTER (WHERE f.scope_group = 'os')::int AS os_packages
        FROM ready r
        LEFT JOIN findings f ON f.scan_id = r.scan_id
        GROUP BY r.scan_id, r.application_id
      )
      INSERT INTO scan_vuln_summary (
        scan_id, application_id, computed_at, db_built_at, grype_version,
        app_findings, app_critical, app_high, app_fixable, app_known_exploited, app_affected_packages,
        os_findings, os_critical, os_high, os_affected_packages, os_fixable, os_known_exploited, counts
      )
      SELECT
        agg.scan_id, agg.application_id, now(), ${stamp}::timestamptz, ${grypeVersion},
        agg.app_findings, agg.app_critical, agg.app_high, agg.app_fixable, agg.app_kev, agg.app_packages,
        agg.os_findings, agg.os_critical, agg.os_high, agg.os_packages, agg.os_fixable, agg.os_kev,
        jsonb_build_object(
          'app', jsonb_build_object(
            'critical', agg.app_critical, 'high', agg.app_high, 'medium', agg.app_medium,
            'low', agg.app_low, 'negligible', agg.app_negligible, 'unknown', agg.app_unknown
          ),
          'os', jsonb_build_object(
            'critical', agg.os_critical, 'high', agg.os_high, 'medium', agg.os_medium,
            'low', agg.os_low, 'negligible', agg.os_negligible, 'unknown', agg.os_unknown
          )
        )
      FROM agg
      ON CONFLICT (scan_id) DO UPDATE SET
        computed_at = EXCLUDED.computed_at,
        db_built_at = EXCLUDED.db_built_at,
        grype_version = EXCLUDED.grype_version,
        app_findings = EXCLUDED.app_findings,
        app_critical = EXCLUDED.app_critical,
        app_high = EXCLUDED.app_high,
        app_fixable = EXCLUDED.app_fixable,
        app_known_exploited = EXCLUDED.app_known_exploited,
        app_affected_packages = EXCLUDED.app_affected_packages,
        os_findings = EXCLUDED.os_findings,
        os_critical = EXCLUDED.os_critical,
        os_high = EXCLUDED.os_high,
        os_affected_packages = EXCLUDED.os_affected_packages,
        os_fixable = EXCLUDED.os_fixable,
        os_known_exploited = EXCLUDED.os_known_exploited,
        counts = EXCLUDED.counts
    `);

    // Only now is a scan genuinely "scanned": its components are matched and its
    // snapshot is published. Setting this earlier would let the UI claim a build had
    // been assessed while its figures were still being computed.
    await this.deps.db.execute(sql`
      UPDATE scan s
      SET vuln_status = 'scanned'
      WHERE s.vuln_status <> 'scanned'
        AND EXISTS (SELECT 1 FROM scan_vuln_summary vs WHERE vs.scan_id = s.id)
    `);
  }

  /**
   * Recomputes snapshots after a suppression changes.
   *
   * Suppressions are applied when snapshots are built, so adding or removing one has
   * to rebuild them or the dashboards would keep reporting a risk that has just been
   * accepted. Cheap: no matching is involved, only the aggregate.
   */
  async refreshAfterSuppressionChange(): Promise<void> {
    const dbStatus = await this.deps.scanner.dbStatus().catch(() => null);
    if (!dbStatus?.builtAt) return;
    const availability = await this.deps.scanner.availability().catch(() => null);
    await this.refreshScanSummaries(dbStatus.builtAt, availability?.version ?? null);
  }
}
