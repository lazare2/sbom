import { sql } from "drizzle-orm";
import type { FastifyBaseLogger } from "fastify";
import {
  REPORT_DEFAULT_TIMEZONE,
  type ReportDelta,
  type ReportDetail,
  type ReportKind,
  type ReportRunSummary,
  type ReportSnapshot,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { BlobStore } from "../../services/blob-store/index.js";
import { ConflictError, isPgError, NotFoundError, PG_UNIQUE_VIOLATION } from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import { computeDelta } from "./delta.js";
import { Mailer, renderTemplate } from "./mailer.js";
import { renderMonthlyReportPdf } from "./monthly-pdf.js";
import { buildMonthlyView } from "./monthly-view.js";
import { currentMonthPeriod, previousMonthPeriod, type ReportPeriod } from "./period.js";
import type { SnapshotService } from "./snapshot.service.js";

/**
 * Generating, storing and reading back the management report.
 *
 * Two rules shape everything here.
 *
 * The first is that a report is a *record*, not a view. Once written, its snapshot is the
 * only surviving evidence of what was true that month: the applications may since have been
 * deleted, and re-running the query today would answer with today's vulnerability database.
 * So generation writes, and nothing rewrites.
 *
 * The second is that only the monthly series may move the baseline. The button generates a
 * preview against the last monthly report, which is what makes it safe to press: a curious
 * click mid-month cannot shorten next month's reporting period to a fortnight while still
 * labelling it a month.
 */

export interface GenerateOptions {
  kind: ReportKind;
  /** Injected so the scheduler and the tests can both decide what "now" means. */
  now?: Date;
  timeZone?: string;
  actor?: { id: string; email: string } | undefined;
}

/** A report plus the snapshots the renderer needs. Neither snapshot crosses the wire. */
export interface LoadedReport extends ReportDetail {
  snapshot: ReportSnapshot;
  /** The snapshot this was compared against, so the renderer can show per-application
   * movement. Absent for the first report in the series. */
  baselineSnapshot?: ReportSnapshot | undefined;
}

export interface GenerateResult extends LoadedReport {
  /** True when an identical monthly run already existed and this returned it untouched. */
  alreadyExisted: boolean;
}

interface RunRow {
  id: string;
  kind: string;
  period_start: Date | string;
  period_end: Date | string;
  period_label: string;
  time_zone: string;
  generated_at: Date | string;
  generated_by_email: string | null;
  baseline_run_id: string | null;
  vuln_db_built_at: Date | string | null;
  pdf_blob_key: string | null;
  sent_at: Date | string | null;
  recipients: unknown;
  delivery_error: string | null;
}

type StoredRun = RunRow & { snapshot: ReportSnapshot };

function iso(value: Date | string | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}

export class ReportService {
  constructor(
    private readonly deps: {
      db: Database;
      blobStore: BlobStore;
      snapshots: SnapshotService;
      settings: SettingsService;
      mailer: Mailer;
      logger: FastifyBaseLogger;
    },
  ) {}

  /**
   * Captures the estate now and files it as a report.
   *
   * The snapshot is always of *now*, never of the period's end, and the distinction is
   * deliberate. The platform stores current builds rather than a build history per day, so
   * there is no way to reconstruct what the estate looked like at midnight on the 31st.
   * Pretending otherwise would produce a precise-looking number that nothing supports. What
   * the report can say honestly is "here is the estate on the day this was produced, and
   * here is how it differs from the day the last one was produced", which is the question
   * actually being asked.
   */
  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const { snapshots } = this.deps;
    const now = options.now ?? new Date();
    const timeZone = options.timeZone ?? REPORT_DEFAULT_TIMEZONE;

    const period: ReportPeriod =
      options.kind === "monthly"
        ? previousMonthPeriod(now, timeZone)
        : // An ad-hoc run covers the month in progress and is labelled as such, rather than
          // borrowing the monthly label and reading as a duplicate of the scheduled report.
          currentMonthPeriod(now, timeZone);

    const snapshot = await snapshots.capture();

    // Both baselines are monthly whatever kind is being generated: an ad-hoc preview answers
    // "what has changed since the last report management received".
    const [baseline, previous] = await this.recentMonthlyRuns();

    const delta = baseline ? computeDelta(baseline.snapshot, snapshot, previous?.snapshot) : null;

    const inserted = await this.insertRun({
      kind: options.kind,
      period,
      timeZone,
      snapshot,
      baselineRunId: baseline?.id ?? null,
      actor: options.actor,
    });

    if (!inserted) {
      /*
        The monthly unique index rejected it, so this month's report already exists. It is
        returned rather than raised as an error: the caller is a scheduler retrying after a
        restart, and the correct outcome of "generate this month's report" when it is
        already generated is the existing report.
      */
      const existing = await this.findMonthly(period.start);
      if (!existing) throw new ConflictError("This month's report is already being generated");
      return { ...(await this.detailOf(existing)), alreadyExisted: true };
    }

    return {
      run: this.summaryOf(inserted, snapshot),
      delta,
      snapshot,
      baselineSnapshot: baseline?.snapshot,
      alreadyExisted: false,
    };
  }

  /** History, newest first. Snapshots are excluded: they are large and the list shows totals. */
  async list(limit = 50): Promise<ReportRunSummary[]> {
    const rows = await this.deps.db.execute<
      Row<RunRow & { totals: ReportSnapshot["totals"] | null }>
    >(sql`
      SELECT r.id, r.kind, r.period_start, r.period_end, r.generated_at, r.generated_by_email,
             r.baseline_run_id, r.vuln_db_built_at, r.pdf_blob_key, r.sent_at, r.recipients,
             r.delivery_error,
             -- Totals only. A snapshot runs to hundreds of kilobytes, and a history page
             -- that loaded fifty of them would transfer tens of megabytes to draw a table.
             r.period_label, r.time_zone,
             r.snapshot -> 'totals' AS totals
      FROM report_run r
      ORDER BY r.generated_at DESC
      LIMIT ${limit}
    `);

    return rowsOf(rows).map((row) =>
      this.summaryOf(row, { totals: row.totals ?? undefined } as ReportSnapshot),
    );
  }

  /** One report in full, with its delta recomputed from the two stored snapshots. */
  async get(id: string): Promise<LoadedReport> {
    const run = await this.findById(id);
    if (!run) throw new NotFoundError("Report");
    return this.detailOf(run);
  }

  /**
   * The report as a PDF, rendered once and stored.
   *
   * Rendered from the stored snapshot rather than from a fresh query, so the file downloaded
   * a year from now is the file that was emailed. Cached in the blob store because the
   * emailed attachment and the downloaded copy must be the same bytes: re-rendering per
   * request would produce documents that differ in their creation timestamp, which is
   * exactly the kind of discrepancy that costs an afternoon when someone compares two copies.
   */
  async pdf(id: string): Promise<{ buffer: Buffer; filename: string; run: ReportRunSummary }> {
    const loaded = await this.get(id);
    const filename = `sbom-monthly-report-${loaded.run.periodLabel}.pdf`;

    if (loaded.run.hasPdf) {
      const key = (await this.findById(id))?.pdf_blob_key;
      if (key) {
        try {
          return { buffer: await this.deps.blobStore.get(key), filename, run: loaded.run };
        } catch {
          // The row says it was stored and the store disagrees. Re-render rather than fail:
          // the snapshot is the authority, and the blob is only a cache of it.
        }
      }
    }

    const view = buildMonthlyView({
      run: loaded.run,
      snapshot: loaded.snapshot,
      delta: loaded.delta,
      baseline: loaded.baselineSnapshot,
    });
    const buffer = await renderMonthlyReportPdf(view);

    const key = `report/${loaded.run.periodLabel}/${loaded.run.id}.pdf`;
    await this.deps.blobStore.put(key, buffer);
    await this.attachPdf(loaded.run.id, key);

    return { buffer, filename, run: { ...loaded.run, hasPdf: true } };
  }

  /**
   * Records where a run's rendered PDF was stored.
   *
   * Separate from generation on purpose: the snapshot is the part that cannot be recreated,
   * so it must be committed before anything as failure-prone as rendering and mailing is
   * attempted. A run whose PDF failed still holds its evidence and can be re-rendered.
   */
  async attachPdf(id: string, blobKey: string): Promise<void> {
    await this.deps.db.execute(sql`
      UPDATE report_run SET pdf_blob_key = ${blobKey} WHERE id = ${id}::uuid
    `);
  }

  /**
   * The delta is recomputed on read rather than stored alongside the run.
   *
   * Storing it would freeze the attribution logic at the version that generated it, so a
   * later correction to how a cause is decided would leave older reports asserting the old,
   * wrong thing forever. The snapshots are the evidence; the delta is an opinion about them,
   * and opinions should stay recomputable.
   */
  private async detailOf(run: StoredRun): Promise<LoadedReport> {
    const snapshot = run.snapshot;
    let delta: ReportDelta | null = null;
    let baselineSnapshot: ReportSnapshot | undefined;

    if (run.baseline_run_id) {
      const baseline = await this.findById(run.baseline_run_id);
      if (baseline) {
        baselineSnapshot = baseline.snapshot;
        const previous = baseline.baseline_run_id
          ? await this.findById(baseline.baseline_run_id)
          : null;
        delta = computeDelta(baseline.snapshot, snapshot, previous?.snapshot);
      }
    }

    return { run: this.summaryOf(run, snapshot), delta, snapshot, baselineSnapshot };
  }

  private summaryOf(row: RunRow, snapshot: ReportSnapshot): ReportRunSummary {
    const totals = snapshot?.totals;
    return {
      id: row.id,
      kind: row.kind === "monthly" ? "monthly" : "adhoc",
      periodStart: iso(row.period_start)!,
      periodEnd: iso(row.period_end)!,
      periodLabel: row.period_label,
      timeZone: row.time_zone,
      generatedAt: iso(row.generated_at)!,
      generatedBy: row.generated_by_email,
      vulnDbBuiltAt: iso(row.vuln_db_built_at),
      baselineRunId: row.baseline_run_id,
      hasPdf: row.pdf_blob_key !== null,
      sentAt: iso(row.sent_at),
      recipients: Array.isArray(row.recipients) ? (row.recipients as string[]) : null,
      deliveryError: row.delivery_error,
      totals: {
        applications: totals?.applications ?? 0,
        components: totals?.components ?? 0,
        findings: totals?.findings ?? 0,
      },
    };
  }

  /** The two most recent monthly runs: the baseline, and the one before it for regressions. */
  private async recentMonthlyRuns(): Promise<Array<StoredRun | undefined>> {
    const rows = await this.deps.db.execute<Row<StoredRun>>(sql`
      SELECT * FROM report_run
      WHERE kind = 'monthly'
      ORDER BY period_start DESC
      LIMIT 2
    `);
    const list = rowsOf(rows);
    return [list[0], list[1]];
  }

  private async findById(id: string): Promise<StoredRun | null> {
    const rows = await this.deps.db.execute<Row<StoredRun>>(sql`
      SELECT * FROM report_run WHERE id = ${id}::uuid
    `);
    return rowsOf(rows)[0] ?? null;
  }

  private async findMonthly(periodStart: Date): Promise<StoredRun | null> {
    const rows = await this.deps.db.execute<Row<StoredRun>>(sql`
      SELECT * FROM report_run
      WHERE kind = 'monthly' AND period_start = ${periodStart.toISOString()}::timestamptz
    `);
    return rowsOf(rows)[0] ?? null;
  }

  /**
   * Mails a report to the configured recipients.
   *
   * Claimed before it is sent, with a conditional update that only succeeds while `sent_at`
   * is null. That ordering is what makes a second attempt a no-op: two schedulers racing, or
   * one restarting mid-month, cannot both win the claim. If the send then fails the claim is
   * released and the error recorded, so the next attempt retries rather than giving up.
   *
   * The remaining window is a crash between claiming and the relay accepting, which leaves a
   * report marked sent that was not. That is deliberately preferred to the alternative: a
   * duplicate monthly report to management is a visible embarrassment, while a missing one is
   * visible too, and can be resent from the history page.
   */
  async deliver(id: string): Promise<{ sent: boolean; recipients: string[]; error?: string }> {
    const { db, settings, mailer, logger } = this.deps;
    const config = await settings.getReportSettings();

    if (config.recipients.length === 0 || !config.smtpHost || !config.smtpFrom) {
      throw new ConflictError(
        "Report delivery is not configured. Set a mail server, a sender address and at least one recipient first.",
      );
    }

    const claimed = await db.execute<Row<{ id: string }>>(sql`
      UPDATE report_run SET sent_at = now()
      WHERE id = ${id}::uuid AND sent_at IS NULL
      RETURNING id
    `);
    if (rowsOf(claimed).length === 0) {
      // Already sent, by an earlier attempt or another process. Reporting this as a success
      // is what makes the scheduler safe to run more than once.
      const existing = await this.findById(id);
      if (!existing) throw new NotFoundError("Report");
      return { sent: false, recipients: (existing.recipients as string[] | null) ?? [] };
    }

    try {
      const { buffer, filename, run } = await this.pdf(id);
      const loaded = await this.get(id);
      const view = buildMonthlyView({
        run,
        snapshot: loaded.snapshot,
        delta: loaded.delta,
        baseline: loaded.baselineSnapshot,
      });

      const values = placeholdersFor(view);
      const result = await mailer.send(config, {
        to: config.recipients,
        subject: renderTemplate(config.subjectTemplate, values),
        text: renderTemplate(config.bodyTemplate, values),
        attachments: [{ filename, content: buffer, contentType: "application/pdf" }],
      });

      await db.execute(sql`
        UPDATE report_run
        SET recipients = ${JSON.stringify(result.accepted)}::jsonb, delivery_error = NULL
        WHERE id = ${id}::uuid
      `);

      logger.info({ reportId: id, recipients: result.accepted.length }, "monthly report sent");
      return { sent: true, recipients: result.accepted };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Claim released, so the next attempt retries rather than seeing a report that claims
      // to have been sent.
      await db.execute(sql`
        UPDATE report_run SET sent_at = NULL, delivery_error = ${message}
        WHERE id = ${id}::uuid
      `);
      logger.error({ reportId: id, err }, "monthly report delivery failed");
      return { sent: false, recipients: [], error: message };
    }
  }

  /**
   * Inserts the run, returning null when the monthly guard rejected it.
   *
   * The guard is the unique index rather than a preceding SELECT. A scheduler that checks
   * and then inserts has a window between the two, and a container restart is precisely when
   * that window gets hit, which is the duplicate send this was built to prevent.
   */
  private async insertRun(input: {
    kind: ReportKind;
    period: ReportPeriod;
    timeZone: string;
    snapshot: ReportSnapshot;
    baselineRunId: string | null;
    actor: { id: string; email: string } | undefined;
  }): Promise<StoredRun | null> {
    try {
      const rows = await this.deps.db.execute<Row<StoredRun>>(sql`
        INSERT INTO report_run (
          kind, period_start, period_end, period_label, time_zone,
          generated_by_user_id, generated_by_email,
          baseline_run_id, vuln_db_built_at, detail_level, snapshot
        ) VALUES (
          ${input.kind},
          ${input.period.start.toISOString()}::timestamptz,
          ${input.period.end.toISOString()}::timestamptz,
          ${input.period.label},
          ${input.timeZone},
          ${input.actor?.id ?? null}::uuid,
          ${input.actor?.email ?? null},
          ${input.baselineRunId}::uuid,
          ${input.snapshot.vulnDbBuiltAt}::timestamptz,
          'full',
          ${JSON.stringify(input.snapshot)}::jsonb
        )
        RETURNING *
      `);
      return rowsOf(rows)[0] ?? null;
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) return null;
      throw err;
    }
  }
}

/**
 * The values an administrator's template may refer to.
 *
 * Strings rather than numbers, because they go straight into text and a locale-formatted
 * "1,234" is what a reader expects. Every placeholder documented in the shared schema has an
 * entry here; one without would render as itself, which is the intended behaviour for a typo
 * but would be a defect for a documented name.
 */
function placeholdersFor(view: ReturnType<typeof buildMonthlyView>): Record<string, string> {
  const number = (value: number): string => value.toLocaleString("en-US");
  const severity = (name: string): number =>
    view.severityMovement.find((row) => row.severity === name)?.now ?? 0;

  return {
    period: view.run.periodLabel,
    applications: number(view.headline.applications),
    findings: number(view.headline.totalFindings),
    resolved: number(view.headline.resolved),
    introduced: number(view.headline.introduced),
    reintroduced: number(view.headline.reintroduced),
    critical: number(severity("critical")),
    high: number(severity("high")),
    generatedAt: new Date(view.run.generatedAt).toISOString().slice(0, 16).replace("T", " ") + " UTC",
  };
}
