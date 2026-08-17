import { sql } from "drizzle-orm";
import type {
  VulnDbUpdateAttempt,
  VulnDbUpdateOutcome,
  VulnDbUpdateTrigger,
  VulnScanStatus,
} from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { vulnDbUpdate } from "../../db/schema.js";
import type { VulnerabilityScanner } from "../../services/scanner/index.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { Actor } from "../admin/audit.service.js";
import type { SettingsService } from "../settings/settings.service.js";

/**
 * Owns the vulnerability database: its state, its updates, and the record of every
 * attempt to change it.
 *
 * The governing rule for this whole class is that **nothing here may break anything
 * else**. A missing binary, an unreachable listing URL, a corrupt archive and an
 * expired database are all states to report, never exceptions to propagate. Ingest
 * still returns 201, search still works, and the dashboards still render — the only
 * thing affected by a failure here is vulnerability data itself.
 */

/**
 * How long an unfinished attempt is treated as still running.
 *
 * Also the crash-recovery window: a process killed mid-download leaves a row with no
 * `finished_at`, and without a cutoff that row would block updates forever. An hour
 * comfortably exceeds a 141 MB download on a slow link while still self-healing
 * within one scheduled interval.
 */
const IN_PROGRESS_CUTOFF = sql`interval '1 hour'`;

interface UpdateRow {
  id: string;
  started_at: Date | string;
  finished_at: Date | string | null;
  trigger: VulnDbUpdateTrigger;
  outcome: VulnDbUpdateOutcome | null;
  message: string | null;
  db_built_before: Date | string | null;
  db_built_after: Date | string | null;
  schema_version: string | null;
  source_url: string | null;
  actor_email: string | null;
}

function toAttempt(row: UpdateRow): VulnDbUpdateAttempt {
  return {
    id: row.id,
    startedAt: toIso(row.started_at)!,
    finishedAt: toIso(row.finished_at),
    trigger: row.trigger,
    outcome: row.outcome,
    message: row.message,
    dbBuiltBefore: toIso(row.db_built_before),
    dbBuiltAfter: toIso(row.db_built_after),
    schemaVersion: row.schema_version,
    sourceUrl: row.source_url,
    actorEmail: row.actor_email,
  };
}

export interface UpdateAttemptResult {
  outcome: VulnDbUpdateOutcome | "busy";
  message: string;
  attempt: VulnDbUpdateAttempt | null;
  /** True when a database was actually installed, so the caller knows to re-sweep. */
  databaseChanged: boolean;
}

export class VulnDbService {
  /**
   * True while grype is replacing the database on disk.
   *
   * Read by the sweep, which must not start a match run into a database that is about
   * to be deleted from under it. The `claim` row below already prevents two concurrent
   * updates; this is the other half of the exclusion, against scans.
   */
  private replacing = false;

  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      scanner: VulnerabilityScanner;
      settings: SettingsService;
      /**
       * Whether a scan is currently holding the database open.
       *
       * Installing a database means deleting the old file, and on Windows a file with an
       * open handle cannot be unlinked — grype's purge fails with "being used by another
       * process", and it fails *after* removing import.json, which leaves a database
       * that is present but unreadable. That is worse than not updating at all: a
       * previously working installation becomes invalid because an update was attempted
       * at an unlucky moment.
       *
       * POSIX unlink-while-open would let this succeed, so the Linux container never
       * showed it — but even there a sweep would go on matching against a file being
       * swapped underneath it and attribute the results to the wrong database build.
       * Worth excluding on every platform, not just the one that reports it.
       */
      scanBusy: () => boolean;
    },
  ) {}

  /** @see replacing */
  get replacingDatabase(): boolean {
    return this.replacing;
  }

  /**
   * Refuses a replacement while a scan holds the database open.
   *
   * Reported as `busy` and deliberately not written to the history table: nothing was
   * attempted, so recording a failure would put a red row in the admin panel for a
   * transient collision that resolves itself. Scheduled updates retry on the next tick.
   */
  private scanBusyResult(action: string): UpdateAttemptResult | null {
    if (!this.deps.scanBusy()) return null;
    return {
      outcome: "busy",
      message:
        `A vulnerability sweep is in progress, so the database cannot be ${action} yet. ` +
        "It holds the database open; retry once the sweep finishes.",
      attempt: null,
      databaseChanged: false,
    };
  }

  // -------------------------------------------------------------------------
  // Status
  // -------------------------------------------------------------------------

  /**
   * The complete picture for the admin panel.
   *
   * Assembled from four independent sources — the settings row, the binary, the
   * database on disk, and the update history — and reported separately rather than
   * reduced to a single "healthy" flag, because an administrator needs to know
   * *which* of them to fix.
   */
  async status(): Promise<VulnScanStatus> {
    const [settings, availability, dbStatus] = await Promise.all([
      this.deps.settings.getVulnSettings(),
      this.deps.scanner.availability(),
      this.deps.scanner.dbStatus(),
    ]);

    const [last, lastSuccessful, inProgress, coverage, listingUrl] = await Promise.all([
      this.lastAttempt(false),
      this.lastAttempt(true),
      this.isUpdateInProgress(),
      this.coverage(dbStatus.builtAt),
      this.deps.scanner
        .listingUrl()
        // Falls back to the configured base if the binary cannot be asked for its
        // schema. Showing the wrong-but-close URL beats showing none.
        .catch(() => this.listingUrlFallback()),
    ]);

    const ageHours =
      dbStatus.builtAt === null
        ? null
        : Math.max(0, (Date.now() - dbStatus.builtAt.getTime()) / (60 * 60 * 1000));

    /*
     * The next check is derived from the last attempt rather than tracked, so it
     * cannot drift from reality after a restart. Null when scanning is off, because
     * the scheduler genuinely is not running — showing a future time for something
     * that will not happen would be a lie.
     */
    let nextCheckAt: string | null = null;
    if (settings.enabled) {
      const base = last ? new Date(last.startedAt).getTime() : Date.now();
      nextCheckAt = new Date(base + settings.intervalHours * 60 * 60 * 1000).toISOString();
    }

    return {
      enabled: settings.enabled,
      scanner: {
        available: availability.available,
        version: availability.version,
        path: availability.path,
        resolvedBy: availability.resolvedBy,
        attempts: availability.attempts,
      },
      database: {
        present: dbStatus.present,
        builtAt: dbStatus.builtAt?.toISOString() ?? null,
        schemaVersion: dbStatus.schemaVersion,
        valid: dbStatus.valid,
        error: dbStatus.error,
        ageHours: ageHours === null ? null : Math.round(ageHours * 10) / 10,
        path: dbStatus.path,
      },
      updates: {
        intervalHours: settings.intervalHours,
        listingUrl,
        nextCheckAt,
        last,
        lastSuccessful,
        inProgress,
      },
      coverage,
    };
  }

  /**
   * Fallback listing URL for display when the binary cannot be asked for its schema.
   *
   * The scanner derives the real URL from the binary's supported schema; this is only
   * used when there is no binary to ask, where showing the configured base is more
   * useful than showing nothing.
   */
  private listingUrlFallback(): string {
    return `${this.deps.config.GRYPE_DB_UPDATE_URL.replace(/\/+$/, "")}/v6/latest.json`;
  }

  /**
   * Sweep progress against the installed database build.
   *
   * `pending` is derived from the same predicate the sweep claims on, so the number an
   * administrator sees is exactly the work that remains rather than a separately
   * maintained counter that could disagree with it.
   */
  private async coverage(dbBuiltAt: Date | null): Promise<VulnScanStatus["coverage"]> {
    const watermark = dbBuiltAt ? sql`${dbBuiltAt.toISOString()}::timestamptz` : sql`NULL::timestamptz`;

    const rows = await this.deps.db.execute<Row<{ scanned: number | string; pending: number | string }>>(sql`
      SELECT
        count(*) FILTER (
          WHERE c.vuln_scanned_at IS NOT NULL
            AND (${watermark} IS NULL OR c.vuln_db_built_at >= ${watermark})
        )::int AS scanned,
        count(*) FILTER (
          WHERE c.vuln_scanned_at IS NULL
             OR c.vuln_db_built_at IS NULL
             OR (${watermark} IS NOT NULL AND c.vuln_db_built_at < ${watermark})
        )::int AS pending
      FROM component c
    `);

    const row = rowsOf(rows)[0];
    return {
      scanned: Number(row?.scanned ?? 0),
      pending: Number(row?.pending ?? 0),
      // Filled in by the worker, which owns the in-process sweep state.
      sweeping: false,
      lastSweepFinishedAt: null,
    };
  }

  async lastAttempt(successfulOnly: boolean): Promise<VulnDbUpdateAttempt | null> {
    const condition = successfulOnly
      ? sql`AND u.outcome IN ('updated', 'imported')`
      : sql``;
    const rows = await this.deps.db.execute<Row<UpdateRow>>(sql`
      SELECT u.id, u.started_at, u.finished_at, u.trigger, u.outcome, u.message,
             u.db_built_before, u.db_built_after, u.schema_version, u.source_url, u.actor_email
      FROM vuln_db_update u
      WHERE u.finished_at IS NOT NULL ${condition}
      ORDER BY u.started_at DESC
      LIMIT 1
    `);
    const row = rowsOf(rows)[0];
    return row ? toAttempt(row) : null;
  }

  async history(limit: number): Promise<VulnDbUpdateAttempt[]> {
    const rows = await this.deps.db.execute<Row<UpdateRow>>(sql`
      SELECT u.id, u.started_at, u.finished_at, u.trigger, u.outcome, u.message,
             u.db_built_before, u.db_built_after, u.schema_version, u.source_url, u.actor_email
      FROM vuln_db_update u
      ORDER BY u.started_at DESC
      LIMIT ${limit}
    `);
    return rowsOf(rows).map(toAttempt);
  }

  /**
   * Closes out update attempts left unfinished by a crash or restart.
   *
   * Called once at boot. An attempt with no `finished_at` holds the claim that stops
   * another update starting, so a process killed mid-download — which `tsx watch` does on
   * every edit, and a container restart does in production — would otherwise block the
   * Update button for the full hour of the in-progress cutoff. That is a genuinely
   * confusing state: the panel says an update is running when nothing is.
   *
   * Safe with several replicas even though it is unconditional. If a peer really is still
   * downloading, its own `finish()` writes the true outcome to the same row afterwards, so
   * the worst case is an "interrupted" row that corrects itself rather than a lost update.
   */
  async reconcileInterruptedUpdates(): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      UPDATE vuln_db_update
      SET finished_at = now(),
          outcome = 'failed',
          message = COALESCE(message, 'Interrupted — the service restarted while this update was running.')
      WHERE finished_at IS NULL
      RETURNING id
    `);
    return rowsOf(rows).length;
  }

  async isUpdateInProgress(): Promise<boolean> {
    const rows = await this.deps.db.execute<Row<{ live: number | string }>>(sql`
      SELECT count(*)::int AS live FROM vuln_db_update
      WHERE finished_at IS NULL AND started_at > now() - ${IN_PROGRESS_CUTOFF}
    `);
    return Number(rowsOf(rows)[0]?.live ?? 0) > 0;
  }

  // -------------------------------------------------------------------------
  // Updating
  // -------------------------------------------------------------------------

  /**
   * Claims the right to run an update.
   *
   * A conditional insert rather than a lock: the `WHERE NOT EXISTS` and the insert are
   * one statement, so two replicas racing cannot both win, and the claim is visible in
   * the history table as an in-flight attempt rather than living in a lock nobody can
   * inspect. Returns null when another attempt is already running.
   *
   * This is the one place in the feature that genuinely needs mutual exclusion: the
   * download is 141 MB, and two of them at once would waste bandwidth and race to
   * write the same database directory.
   */
  private async claim(
    trigger: VulnDbUpdateTrigger,
    actor: Actor | null,
  ): Promise<string | null> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      INSERT INTO vuln_db_update (trigger, actor_user_id, actor_email)
      SELECT ${trigger},
             ${actor?.id ?? null}::uuid,
             ${actor?.email ?? null}::text
      WHERE NOT EXISTS (
        SELECT 1 FROM vuln_db_update
        WHERE finished_at IS NULL AND started_at > now() - ${IN_PROGRESS_CUTOFF}
      )
      RETURNING id
    `);
    return rowsOf(rows)[0]?.id ?? null;
  }

  private async finish(
    id: string,
    result: {
      outcome: VulnDbUpdateOutcome;
      message: string;
      builtBefore: Date | null;
      builtAfter: Date | null;
      schemaVersion: string | null;
      sourceUrl: string | null;
    },
  ): Promise<VulnDbUpdateAttempt | null> {
    const rows = await this.deps.db.execute<Row<UpdateRow>>(sql`
      UPDATE vuln_db_update
      SET finished_at = now(),
          outcome = ${result.outcome},
          message = ${result.message},
          db_built_before = ${result.builtBefore?.toISOString() ?? null}::timestamptz,
          db_built_after = ${result.builtAfter?.toISOString() ?? null}::timestamptz,
          schema_version = ${result.schemaVersion},
          source_url = ${result.sourceUrl}
      WHERE id = ${id}::uuid
      RETURNING id, started_at, finished_at, trigger, outcome, message,
                db_built_before, db_built_after, schema_version, source_url, actor_email
    `);
    const row = rowsOf(rows)[0];
    return row ? toAttempt(row) : null;
  }

  /**
   * Runs a database update.
   *
   * Order of checks is chosen so the message an administrator sees names the actual
   * problem: no binary is reported as no binary, and no route to the listing is
   * reported with the exact URL rather than as a generic download failure.
   */
  async update(trigger: VulnDbUpdateTrigger, actor: Actor | null): Promise<UpdateAttemptResult> {
    const availability = await this.deps.scanner.availability();
    if (!availability.available) {
      return {
        outcome: "failed",
        message:
          "The grype binary is not available, so the vulnerability database cannot be updated. " +
          "See the scanner status for where it was looked for.",
        attempt: null,
        databaseChanged: false,
      };
    }

    const busy = this.scanBusyResult("updated");
    if (busy) return busy;

    const id = await this.claim(trigger, actor);
    if (id === null) {
      return {
        outcome: "busy",
        message: "A database update is already running.",
        attempt: null,
        databaseChanged: false,
      };
    }

    this.replacing = true;
    try {
      const result = await this.deps.scanner.updateDb();
      const attempt = await this.finish(id, result);
      return {
        outcome: result.outcome,
        message: result.message,
        attempt,
        databaseChanged: result.outcome === "updated",
      };
    } catch (err) {
      // Should be unreachable: the scanner resolves rather than throws for
      // operational failures. Recorded anyway, because leaving the claim unfinished
      // would block updates for an hour.
      const message = err instanceof Error ? err.message : String(err);
      const attempt = await this.finish(id, {
        outcome: "failed",
        message: message.slice(0, 2000),
        builtBefore: null,
        builtAfter: null,
        schemaVersion: null,
        sourceUrl: null,
      });
      return { outcome: "failed", message, attempt, databaseChanged: false };
    } finally {
      this.replacing = false;
    }
  }

  /** Installs a database from an uploaded archive. The air-gapped path. */
  async importArchive(archivePath: string, actor: Actor | null): Promise<UpdateAttemptResult> {
    const availability = await this.deps.scanner.availability();
    if (!availability.available) {
      return {
        outcome: "failed",
        message: "The grype binary is not available, so a database cannot be imported.",
        attempt: null,
        databaseChanged: false,
      };
    }

    const busy = this.scanBusyResult("imported");
    if (busy) return busy;

    const id = await this.claim("import", actor);
    if (id === null) {
      return {
        outcome: "busy",
        message: "A database update is already running.",
        attempt: null,
        databaseChanged: false,
      };
    }

    this.replacing = true;
    try {
      const result = await this.deps.scanner.importDb(archivePath);
      const attempt = await this.finish(id, result);
      return {
        outcome: result.outcome,
        message: result.message,
        attempt,
        databaseChanged: result.outcome === "imported",
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const attempt = await this.finish(id, {
        outcome: "failed",
        message: message.slice(0, 2000),
        builtBefore: null,
        builtAfter: null,
        schemaVersion: null,
        sourceUrl: archivePath,
      });
      return { outcome: "failed", message, attempt, databaseChanged: false };
    } finally {
      this.replacing = false;
    }
  }
}
