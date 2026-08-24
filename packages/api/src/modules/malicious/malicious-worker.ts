import type { Logger } from "../ingestion/ingestion.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import type { MaliciousAlertService } from "./malicious-alert.service.js";
import type { MaliciousFeedService } from "./malicious-feed.service.js";
import type { MaliciousMatchService } from "./malicious-match.service.js";

/**
 * Background driver for malicious-package detection.
 *
 * Four triggers, all converging on the same sequence -- refresh the feed if it is due, match
 * anything unmatched, then mail whatever is new:
 *
 *   - the schedule (every 6 hours by default, admin-editable)
 *   - an ingest, so a newly uploaded SBOM is checked within seconds rather than at the next
 *     scheduled pass. This matters more here than it does for vulnerabilities: a malicious
 *     release is often pulled from its registry within a day, and a build that installed one
 *     an hour ago is exactly the case worth catching immediately
 *   - enabling the feature, which is when a fresh install first needs a feed
 *   - an administrator pressing the button
 *
 * Every path is fire-and-forget and swallows its own failures, for the reason the vulnerability
 * worker does: nothing about this feature may surface as an error anywhere else. An unreachable
 * feed, a relay that is down or a failed sweep must leave ingestion, search and every dashboard
 * working exactly as they do with detection switched off.
 */

/**
 * How often the worker asks whether anything is due.
 *
 * A heartbeat rather than a timer set to the configured interval, so changing that interval
 * takes effect on the next beat instead of requiring the timer to be rebuilt -- and so a
 * restart can neither lose nor double-fire a scheduled refresh.
 */
const HEARTBEAT_MS = 60_000;

/** Long enough to stay clear of migrations and the first requests after boot. */
const STARTUP_DELAY_MS = 45_000;

/**
 * Quiet period after an ingest before sweeping.
 *
 * A pipeline pushing thirty images in a burst should produce one sweep, not thirty. The timer
 * restarts on each request, so the sweep runs once the burst has actually stopped.
 */
const INGEST_DEBOUNCE_MS = 10_000;

export class MaliciousWorker {
  private timer: NodeJS.Timeout | null = null;
  private ingestTimer: NodeJS.Timeout | null = null;
  private ticking = false;
  /** Set when something asked for a refresh out of band. Consumed by the next tick. */
  private forcedRefresh: "enable" | "manual" | null = null;
  private sweepRequested = false;

  constructor(
    private readonly deps: {
      settings: SettingsService;
      feed: MaliciousFeedService;
      match: MaliciousMatchService;
      alerts: MaliciousAlertService;
      logger: Logger;
    },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), HEARTBEAT_MS);
    // Never keeps the process alive: a pending heartbeat must not delay shutdown.
    this.timer.unref?.();
    setTimeout(() => void this.tick(), STARTUP_DELAY_MS).unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    if (this.ingestTimer) clearTimeout(this.ingestTimer);
    this.timer = null;
    this.ingestTimer = null;
  }

  /** Called after an SBOM lands. Debounced, so a burst of builds produces one sweep. */
  requestSweepAfterIngest(): void {
    if (this.ingestTimer) clearTimeout(this.ingestTimer);
    this.ingestTimer = setTimeout(() => {
      this.sweepRequested = true;
      void this.tick();
    }, INGEST_DEBOUNCE_MS);
    this.ingestTimer.unref?.();
  }

  /** Refresh the feed on the next tick, whether or not the interval has elapsed. */
  requestRefresh(reason: "enable" | "manual"): void {
    this.forcedRefresh = reason;
    void this.tick();
  }

  requestSweep(): void {
    this.sweepRequested = true;
    void this.tick();
  }

  private async tick(): Promise<void> {
    // Re-entrancy guard rather than a lock: ticks are cheap and a skipped one is picked up by
    // the next heartbeat a minute later.
    if (this.ticking) return;
    this.ticking = true;

    try {
      const settings = await this.deps.settings.getMaliciousSettings();
      if (!settings.enabled) {
        // Requests made while the feature was off are dropped rather than queued, so
        // switching it on does not replay a backlog of stale triggers.
        this.forcedRefresh = null;
        this.sweepRequested = false;
        return;
      }

      const forced = this.forcedRefresh;
      this.forcedRefresh = null;

      if (forced !== null || (await this.deps.feed.isDue())) {
        const result = await this.deps.feed.update(forced === "enable" ? "enable" : "scheduled", null);
        if (result.outcome === "unreachable" || result.outcome === "failed") {
          // Logged, never thrown. An air-gapped install lives here permanently and the admin
          // page explains it from the attempt history.
          this.deps.logger.warn(
            { outcome: result.outcome, message: result.message },
            "malicious feed refresh did not complete",
          );
        }
      }

      const snapshot = await this.deps.feed.snapshot();
      if (!snapshot.builtAt) return;

      const wantSweep = this.sweepRequested;
      this.sweepRequested = false;

      const coverage = await this.deps.match.coverage(snapshot.builtAt);
      if (wantSweep || coverage.pending > 0) {
        const swept = await this.deps.match.sweep(snapshot.builtAt);
        if (swept.matchesAdded > 0 || swept.matchesRemoved > 0) {
          this.deps.logger.info(swept, "malicious package sweep completed");
        }
      }

      // Always attempted, even when this tick swept nothing: a previous send may have failed
      // against a relay that is now back, and those findings are still unannounced.
      await this.deps.alerts.dispatch();
    } catch (err) {
      this.deps.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "malicious detection tick failed",
      );
    } finally {
      this.ticking = false;
    }
  }
}
