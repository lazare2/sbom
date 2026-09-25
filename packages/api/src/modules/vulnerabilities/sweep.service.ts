import { sql } from "drizzle-orm";
import type { VulnProvider } from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import type {
  ParsedFinding,
  ScannablePackage,
  ScannerAvailability,
  VulnerabilityScanner,
} from "../../services/scanner/index.js";
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

/**
 * Collapses findings onto the pairing upsert's conflict target.
 *
 * `INSERT ... ON CONFLICT (component_id, vulnerability_id)` is rejected outright by
 * Postgres when a single statement proposes that pair twice -- SQLSTATE 21000, "ON
 * CONFLICT DO UPDATE command cannot affect row a second time". It fails the whole
 * statement, so one duplicated pair costs the entire batch and with it the sweep.
 *
 * Grype never produced one: it reports a package/vulnerability match once. Xray reports per
 * *issue*, and one CVE is routinely carried by several issue records naming the same
 * component, so `toFindings` emits that pair more than once for an ordinary response. Every
 * sweep under Xray therefore aborted in `storeFindings`, leaving no component stamped and
 * the previous provider's findings standing -- which reads as "switching provider did
 * nothing" rather than as a failure, and is why this went unnoticed for a full day.
 *
 * Collapsed here rather than in the Xray mapper because the constraint being respected
 * belongs to this statement, and any provider is free to report a pair twice.
 */
/**
 * Why the sweep cannot run, phrased for the provider that is actually configured.
 *
 * The message an administrator reads is the whole diagnosis -- the sweep declines quietly
 * and this is the only account of it. Reporting a missing grype binary under Xray points
 * the reader at the filesystem when the real failure is an unreachable server.
 *
 * `attempts` is where every provider's availability check records why it failed, so the
 * specific reason travels with the summary instead of living only in a log line.
 */
export function unavailableMessage(provider: VulnProvider, availability: ScannerAvailability): string {
  const detail = availability.attempts[0]?.reason ?? null;
  const summary =
    provider === "xray"
      ? `JFrog Xray at ${availability.path ?? "the configured URL"} could not be reached.`
      : "The grype binary is not available.";
  return detail ? `${summary} ${detail}` : summary;
}

export function collapsePairings(findings: readonly ParsedFinding[]): ParsedFinding[] {
  const byPair = new Map<string, ParsedFinding>();
  for (const finding of findings) {
    // A null byte cannot occur in either half, so no two distinct pairs can collide on
    // the joined key -- which a plain separator like ":" would allow.
    const key = `${finding.componentId}\u0000${finding.vulnerabilityId}`;
    const existing = byPair.get(key);
    if (!existing || namesABetterFix(finding, existing)) byPair.set(key, finding);
  }
  return [...byPair.values()];
}

/**
 * Whether `next` should displace `current` as the surviving copy of a pair.
 *
 * "Fixed in 2.15.0" is the actionable half of a finding, and two records of the same pair
 * can disagree about it: Xray states fixed versions per issue, and one issue may name them
 * where another does not. Keeping the copy that knows about a fix means which duplicate
 * happened to arrive last never silently removes the upgrade an administrator would act on.
 */
function namesABetterFix(next: ParsedFinding, current: ParsedFinding): boolean {
  if (next.fixVersions.length !== current.fixVersions.length) {
    return next.fixVersions.length > current.fixVersions.length;
  }
  return current.fixState === "unknown" && next.fixState !== "unknown";
}

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
      /**
       * Whether a database replacement is in flight.
       *
       * The mirror of VulnDbService's `scanBusy`: that stops an update starting while a
       * sweep holds the database open, this stops a sweep starting while the file is
       * being swapped. Both directions are needed — without this one the collision just
       * moves to the other ordering.
       */
      dbReplacing: () => boolean;
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

    /*
      Reuses the `already-running` status rather than adding a case every consumer would
      have to learn: to every caller this is the same situation — come back later, nothing
      is wrong. The message carries the distinction for anyone reading it.

      Deliberately after the re-entrancy check and before the enabled check, so the
      cheapest guards stay first and no work is done on behalf of a sweep that will not
      run.
    */
    if (this.deps.dbReplacing()) {
      return {
        ...empty,
        status: "already-running",
        message: "The vulnerability database is being replaced. The sweep will run once it is installed.",
        remaining: 0,
      };
    }

    if (!(await this.deps.settings.vulnScanningEnabled())) {
      return {
        ...empty,
        status: "disabled",
        message: "Vulnerability scanning is disabled.",
        remaining: 0,
      };
    }

    /*
      Resolved once and passed down rather than read again per query. Every statement in one
      run has to agree about which database is the authority: a provider changed mid-sweep
      would claim components under one name and stamp them under another, leaving rows that
      look assessed and belong to nobody.

      After the guards above, not before, so a tick that declines for any of those reasons
      costs no settings read at all.
    */
    const provider = await this.deps.settings.vulnProvider();

    const availability = await this.deps.scanner.availability();
    if (!availability.available) {
      /*
        Named rather than assumed. Under Xray there is no binary at all, and reporting a
        missing grype binary points the reader at the filesystem when the actual failure is
        an unreachable server -- a wrong turn that cost a real diagnosis a day.

        `attempts` is where every provider's availability check records why it failed, so the
        specific reason travels with the message instead of being logged somewhere else.
      */
      return {
        ...empty,
        status: "unavailable",
        message: unavailableMessage(provider, availability),
        remaining: await this.pendingCount(null, provider),
      };
    }

    /*
      The data set being matched against, asked of the scanner rather than read off a local
      database file. Grype answers with its database build timestamp; Xray answers with the
      assessment epoch it keeps on this side, because it publishes no build date of its own.

      Null means the scanner cannot say, and the sweep refuses rather than guessing --
      findings recorded against an unknown data set can never be invalidated later.
    */
    const dbStatus = await this.deps.scanner.dbStatus();
    const watermark = await this.deps.scanner.watermark();
    if (!dbStatus.present || watermark === null) {
      return {
        ...empty,
        status: "no-database",
        message: dbStatus.error
          ? `The vulnerability database is not usable: ${dbStatus.error}`
          : "No vulnerability database is installed. Update it from the admin panel, or import an archive.",
        remaining: await this.pendingCount(null, provider),
      };
    }

    this.running = true;
    const progress: SweepProgress = { ...empty };
    const maxBatches = options.maxBatches ?? Number.POSITIVE_INFINITY;

    try {
      while (progress.batches < maxBatches) {
        const packages = await this.claimBatch(watermark, provider, this.deps.config.GRYPE_BATCH_SIZE);
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
          provider,
        );

        progress.componentsScanned += packages.length;
        progress.findingsStored += result.findings.length;
      }

      // Snapshots are recomputed once at the end rather than per batch: a scan's
      // counts are only meaningful when all of its components have been matched, and
      // recomputing per batch would publish partial figures that briefly look like a
      // drop in exposure.
      await this.refreshScanSummaries(watermark, availability.version);

      const remaining = await this.pendingCount(watermark, provider);
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
        remaining: await this.pendingCount(watermark, provider).catch(() => 0),
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
  /**
   * What still needs assessing, as an expression rather than a queue.
   *
   * Three terms, and the third is what makes changing the vulnerability database safe:
   *
   *   never assessed            a new package, or the first sweep after enabling scanning
   *   assessed by someone else  the active provider changed, so the finding was produced
   *                             by a database that is no longer the authority here
   *   assessed against older    a newer Grype build, or a new Xray assessment epoch
   *
   * The provider term means switching between Grype and Xray re-queues the estate on its
   * own -- nothing to migrate, nothing to wipe, and switching back undoes it. The
   * alternative was blending two databases that identify the same advisory differently.
   */
  private pendingPredicate(watermark: Date | null, provider: VulnProvider) {
    const wrongProvider = sql`c.vuln_provider IS DISTINCT FROM ${provider}`;

    if (watermark === null) {
      return sql`(c.vuln_scanned_at IS NULL OR c.vuln_db_built_at IS NULL OR ${wrongProvider})`;
    }
    return sql`(
      c.vuln_scanned_at IS NULL
      OR c.vuln_db_built_at IS NULL
      OR ${wrongProvider}
      OR c.vuln_db_built_at < ${watermark.toISOString()}::timestamptz
    )`;
  }

  private async pendingCount(watermark: Date | null, provider: VulnProvider): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ pending: number | string }>>(sql`
      SELECT count(*)::int AS pending FROM component c WHERE ${this.pendingPredicate(watermark, provider)}
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
  private async claimBatch(
    watermark: Date,
    provider: VulnProvider,
    limit: number,
  ): Promise<ScannablePackage[]> {
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
      WHERE ${this.pendingPredicate(watermark, provider)}
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

    for (const batch of chunk(collapsePairings(findings), FINDING_UPSERT_CHUNK)) {
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
  private async markScanned(
    componentIds: readonly number[],
    dbBuiltAt: Date,
    provider: VulnProvider,
  ): Promise<void> {
    if (componentIds.length === 0) return;
    const ids = sql`${sql.param(componentIds)}::bigint[]`;
    const stamp = dbBuiltAt.toISOString();

    await this.deps.db.execute(sql`
      DELETE FROM component_vulnerability cv
      WHERE cv.component_id = ANY(${ids})
        AND cv.last_confirmed_at < ${stamp}::timestamptz - interval '1 second'
        AND cv.last_confirmed_at < now() - interval '1 second'
    `);

    /*
      The provider is stamped in the same statement as the watermark, so a component can
      never be recorded as assessed without recording what assessed it. Two statements would
      leave a window where a crash produces rows that look current and belong to nobody.
    */
    await this.deps.db.execute(sql`
      UPDATE component
      SET vuln_scanned_at = now(),
          vuln_db_built_at = ${stamp}::timestamptz,
          vuln_provider = ${provider}
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
