import type { Logger } from "../ingestion/ingestion.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import type { SweepService } from "./sweep.service.js";
import type { VulnDbService } from "./vuln-db.service.js";

/**
 * Background driver for vulnerability scanning.
 *
 * Owns three triggers, all of which converge on the same two operations — update the
 * database if it is due, then bring the component set up to date:
 *
 *   - the schedule (default every 3 hours, admin-editable)
 *   - an ingest, so a newly received SBOM's packages are matched within seconds
 *   - enabling the feature, which is the moment a fresh install first needs a database
 *
 * Every path is fire-and-forget and swallows its own failures. Nothing here may
 * surface as an error anywhere else in the platform: an unreachable listing URL, a
 * missing binary or a failed sweep must leave ingestion, search, the dashboards and
 * the analytics report working exactly as they do with the feature switched off.
 */

/**
 * How often the worker wakes to ask whether anything is due.
 *
 * A heartbeat rather than an interval timer set to the configured period, because the
 * period is admin-editable at runtime: changing it from 3 hours to 30 minutes takes
 * effect on the next heartbeat instead of requiring the timer to be torn down and
 * rebuilt, and a restart cannot lose or double-fire a scheduled check.
 */
const HEARTBEAT_MS = 60_000;

/**
 * Delay before the first heartbeat after boot.
 *
 * Long enough to stay out of the way of startup — migrations, seeding, the first
 * requests — and short enough that a container which was off for a week notices
 * promptly rather than waiting a full interval.
 */
const STARTUP_DELAY_MS = 60_000;

export class VulnWorker {
  private timer: NodeJS.Timeout | null = null;
  private ticking = false;
  /** Logged once per transition so a permanently offline server does not fill the log. */
  private lastUnavailableReason: string | null = null;

  constructor(
    private readonly deps: {
      settings: SettingsService;
      vulnDb: VulnDbService;
      sweep: SweepService;
      logger: Logger;
    },
  ) {}

  /** Begins the heartbeat. Safe to call once; a second call is ignored. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick("scheduled"), HEARTBEAT_MS);
    // Never keeps the process alive: a pending heartbeat must not delay shutdown.
    this.timer.unref();

    const initial = setTimeout(() => void this.tick("startup"), STARTUP_DELAY_MS);
    initial.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  get sweeping(): boolean {
    return this.deps.sweep.isRunning;
  }

  get lastSweepFinishedAt(): Date | null {
    return this.deps.sweep.finishedAt;
  }

  /**
   * One heartbeat.
   *
   * Re-entrancy guarded rather than queued: if a previous tick is still updating a
   * database or sweeping 50,000 components, the right behaviour is to skip this beat,
   * not to stack up work behind it.
   */
  private async tick(reason: "scheduled" | "startup"): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    try {
      if (!(await this.deps.settings.vulnScanningEnabled())) return;
      await this.maybeUpdateDatabase(reason);
      await this.runSweep(reason);
    } catch (err) {
      this.deps.logger.warn({ err, reason }, "vulnerability worker tick failed");
    } finally {
      this.ticking = false;
    }
  }

  /**
   * Updates the database when the configured interval has elapsed, or when none is
   * installed at all.
   *
   * The "no database installed" case bypasses the schedule on purpose: a fresh install
   * that has just had scanning enabled should not sit idle for three hours before
   * fetching the thing it needs to do any work.
   */
  private async maybeUpdateDatabase(reason: "scheduled" | "startup" | "enable"): Promise<boolean> {
    const settings = await this.deps.settings.getVulnSettings();
    const status = await this.deps.vulnDb.status();

    if (!status.scanner.available) {
      this.noteUnavailable(
        "grype binary not available",
        "vulnerability scanning is enabled but the grype binary was not found",
      );
      return false;
    }

    const due =
      !status.database.present ||
      status.updates.last === null ||
      Date.now() - new Date(status.updates.last.startedAt).getTime() >=
        settings.intervalHours * 60 * 60 * 1000;

    if (!due) return false;

    const trigger = reason === "enable" ? "enable" : reason === "startup" ? "startup" : "scheduled";
    const result = await this.deps.vulnDb.update(trigger, null);

    if (result.outcome === "unreachable") {
      /*
       * Expected on an air-gapped deployment, and deliberately not an error. The
       * message — which names the exact URL — is recorded in the update history and
       * shown in the admin panel, which is where an administrator can act on it. A log
       * line every interval, forever, would be noise.
       */
      this.noteUnavailable(result.message, result.message);
      return false;
    }

    this.lastUnavailableReason = null;
    if (result.outcome === "updated") {
      this.deps.logger.info(
        { outcome: result.outcome, builtAfter: result.attempt?.dbBuiltAfter },
        "vulnerability database updated; every package will be rematched",
      );
      return true;
    }
    return false;
  }

  /** Logs a persistent problem only when the reason changes. */
  private noteUnavailable(key: string, message: string): void {
    if (this.lastUnavailableReason === key) return;
    this.lastUnavailableReason = key;
    this.deps.logger.warn({ reason: message }, "vulnerability scanning cannot run");
  }

  private async runSweep(reason: string): Promise<void> {
    const outcome = await this.deps.sweep.sweep({ reason });
    if (outcome.status === "failed") {
      this.deps.logger.warn({ reason, message: outcome.message }, "vulnerability sweep reported a failure");
    }
  }

  // -------------------------------------------------------------------------
  // External triggers
  // -------------------------------------------------------------------------

  /**
   * Called after an SBOM is ingested.
   *
   * Fire-and-forget by design: the ingest endpoint has already returned 201, and the
   * whole point of the asynchronous decision is that a pipeline never waits on Grype.
   * Usually only the packages new to the platform need matching, so this is normally a
   * few seconds of work rather than a full sweep.
   *
   * `maxBatches` bounds it so one unusually large first-ever application cannot occupy
   * the worker indefinitely — the heartbeat picks up whatever is left.
   */
  requestSweepAfterIngest(): void {
    void (async () => {
      try {
        if (!(await this.deps.settings.vulnScanningEnabled())) return;
        await this.deps.sweep.sweep({ reason: "ingest", maxBatches: 20 });
      } catch (err) {
        this.deps.logger.warn({ err }, "post-ingest vulnerability sweep failed");
      }
    })();
  }

  /**
   * Called when an administrator switches scanning on.
   *
   * Fetches a database if none is installed, then matches everything already in the
   * estate. Without the backfill, enabling the feature would appear to do nothing —
   * the packages are all already ingested, so there would be no new SBOM to trigger a
   * match — and the reasonable conclusion would be that it is broken.
   *
   * Runs detached so the settings request returns immediately; progress is visible
   * through the coverage figures in the admin panel.
   */
  requestBackfillAfterEnable(): void {
    void (async () => {
      try {
        if (!(await this.deps.settings.vulnScanningEnabled())) return;
        await this.maybeUpdateDatabase("enable");
        await this.runSweep("enable");
      } catch (err) {
        this.deps.logger.warn({ err }, "vulnerability backfill after enabling failed");
      }
    })();
  }

  /**
   * Called after a database is installed by hand from the admin panel.
   *
   * A new database makes every previously matched component pending again, by virtue of
   * the build timestamp having moved — so this is a plain sweep, with nothing to
   * enqueue or invalidate.
   */
  requestSweepAfterDbChange(): void {
    void (async () => {
      try {
        if (!(await this.deps.settings.vulnScanningEnabled())) return;
        await this.runSweep("database-changed");
      } catch (err) {
        this.deps.logger.warn({ err }, "vulnerability sweep after a database change failed");
      }
    })();
  }

  /** Called after a suppression is added or removed, to rebuild the affected counts. */
  requestSummaryRefresh(): void {
    void (async () => {
      try {
        if (!(await this.deps.settings.vulnScanningEnabled())) return;
        await this.deps.sweep.refreshAfterSuppressionChange();
      } catch (err) {
        this.deps.logger.warn({ err }, "recomputing vulnerability summaries failed");
      }
    })();
  }
}
