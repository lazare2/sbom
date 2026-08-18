import type { FastifyBaseLogger } from "fastify";
import type { SettingsService } from "../settings/settings.service.js";
import { monthlyReportDue, previousMonthPeriod } from "./period.js";
import type { ReportService } from "./report.service.js";

/**
 * Sends the monthly report on the first working day of each month.
 *
 * A heartbeat that asks "is it due" rather than a timer armed for the next occurrence. The
 * send hour and timezone are admin-editable, so an armed timer would have to be torn down and
 * rebuilt on every settings change, and a restart would either lose the pending fire or add a
 * second one. Asking a cheap question every few minutes has neither problem.
 *
 * Nothing here may throw into the rest of the platform. A relay that is down, a report that
 * fails to render, a settings row someone edited by hand: all of them must leave ingestion,
 * search and the dashboards working exactly as they do with this feature switched off.
 *
 * Correctness against restarts does not live in this file. It lives in the unique index on
 * `(kind, period_start)` and in the conditional claim on `sent_at`, both of which are in the
 * database — because a process that is restarting is precisely the process that cannot be
 * trusted to remember what it already did.
 */

/**
 * How often to ask whether the report is due.
 *
 * Five minutes. The window being watched for is an hour wide in practice, so this is far
 * more often than it needs to be; the cost is one cached settings read, and the benefit is
 * that a container started at 09:03 on the first working day still sends that morning.
 */
const HEARTBEAT_MS = 5 * 60_000;

/** Long enough to stay clear of migrations and the first requests after boot. */
const STARTUP_DELAY_MS = 90_000;

export class ReportScheduler {
  private timer: NodeJS.Timeout | null = null;
  private ticking = false;

  constructor(
    private readonly deps: {
      settings: SettingsService;
      reports: ReportService;
      logger: FastifyBaseLogger;
    },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), HEARTBEAT_MS);
    // Never keeps the process alive: a pending heartbeat must not delay shutdown.
    this.timer.unref();

    const initial = setTimeout(() => void this.tick(), STARTUP_DELAY_MS);
    initial.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * One heartbeat.
   *
   * Re-entrancy guarded rather than queued. Generating a report walks the whole estate and
   * renders a PDF; if the previous tick is still doing that, the right response is to skip
   * this beat rather than to start a second one behind it.
   */
  async tick(now: Date = new Date()): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    try {
      await this.run(now);
    } catch (err) {
      this.deps.logger.warn({ err }, "monthly report scheduler tick failed");
    } finally {
      this.ticking = false;
    }
  }

  private async run(now: Date): Promise<void> {
    const { settings, reports, logger } = this.deps;
    const config = await settings.getReportSettings();

    if (!config.enabled) return;
    if (!monthlyReportDue(now, config.timeZone, config.sendHour)) return;

    /*
      Generation is idempotent by the unique index: the second call in a month returns the
      existing run rather than creating one. That is what lets this be attempted on every
      heartbeat for the rest of the month without special-casing "have I already run".
    */
    const period = previousMonthPeriod(now, config.timeZone);
    const result = await reports.generate({ kind: "monthly", now, timeZone: config.timeZone });

    if (!result.alreadyExisted) {
      logger.info({ period: period.label, reportId: result.run.id }, "monthly report generated");
    }

    // Already delivered, so there is nothing left to do this month. Checked after generation
    // rather than before, because a report that was generated but never sent -- the relay was
    // down on the day -- should still be sent when the relay comes back.
    if (result.run.sentAt) return;

    if (!(await settings.reportDeliveryConfigured())) {
      // Logged once per heartbeat would be noise for the rest of the month; logged at debug
      // because an administrator who has not finished configuring delivery has not made a
      // mistake, and the admin page already says so plainly.
      logger.debug(
        { reportId: result.run.id },
        "monthly report generated but delivery is not configured",
      );
      return;
    }

    const delivery = await reports.deliver(result.run.id);
    if (delivery.error) {
      // Recorded on the row by `deliver`, so the admin page can show why and the next
      // heartbeat will try again.
      logger.warn({ reportId: result.run.id, err: delivery.error }, "monthly report not sent");
    }
  }
}
