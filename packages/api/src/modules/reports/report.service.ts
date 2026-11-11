import { sql } from "drizzle-orm";
import type { FastifyBaseLogger } from "fastify";
import {
  EMPTY_TEAM_FILTER,
  REPORT_DEFAULT_TIMEZONE,
  type AnalyticsReport,
  type ReportDetail,
  type ReportKind,
  type ReportRunSummary,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { ReadScope } from "../environments/environment.service.js";
import type { BlobStore } from "../../services/blob-store/index.js";
import { ConflictError, isPgError, NotFoundError, PG_UNIQUE_VIOLATION } from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { AnalyticsService } from "../analytics/analytics.service.js";
import type { SettingsService } from "../settings/settings.service.js";
import { applicationInScope } from "../environments/environment.service.js";
import { Mailer, renderTemplate } from "./mailer.js";
import { renderReportPdf } from "./pdf.js";
import { currentMonthPeriod, previousMonthPeriod, type ReportPeriod } from "./period.js";

/**
 * Generating, filing and sending the monthly report.
 *
 * The report is the analytics report for the month - the same payload the Analytics page shows,
 * rendered by the same PDF code - generated for one estate and stored with the run. Storing the
 * payload is what makes a run a record rather than a view: live data and the vulnerability
 * database move on, and a report re-read in a year must say what it said when it was sent.
 *
 * Only the monthly series is unique per period. The button generates an ad-hoc run covering the
 * month so far, which never collides with, or stands in for, the scheduled one.
 */

export interface GenerateOptions {
  /** The estate this report describes. One report per estate per month. */
  scope: ReadScope;
  kind: ReportKind;
  /** Injected so the scheduler and the tests can both decide what "now" means. */
  now?: Date;
  timeZone?: string;
  actor?: { id: string; email: string } | undefined;
}

export interface GenerateResult extends ReportDetail {
  /** True when this month's monthly run already existed and this returned it untouched. */
  alreadyExisted: boolean;
}

/** What the history list and the email need, without loading the payload. */
interface StoredTotals {
  applications?: number;
  fixed?: number;
  introduced?: number;
  needAttention?: number;
  openFindings?: number;
  openCritical?: number;
  openHigh?: number;
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
  vuln_db_built_at: Date | string | null;
  pdf_blob_key: string | null;
  sent_at: Date | string | null;
  recipients: unknown;
  delivery_error: string | null;
  totals: StoredTotals | null;
}

const DAY_MS = 86_400_000;

function iso(value: Date | string | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/**
 * The window the analytics report covers for a period: the whole month for a monthly run, the
 * month so far for an ad-hoc one. Never less than a day, so a run on the 1st still has a window.
 */
export function reportWindowDays(period: ReportPeriod, now: Date): number {
  const end = Math.min(now.getTime(), period.end.getTime());
  return Math.max(1, Math.ceil((end - period.start.getTime()) / DAY_MS));
}

/** The headline figures filed with a run, from its analytics payload and the open-finding count. */
export function totalsOf(report: AnalyticsReport, open: { findings: number; critical: number; high: number }): StoredTotals {
  let fixed = 0;
  let introduced = 0;
  for (const p of report.progress.projects) {
    if (!p.vulnerabilities) continue;
    fixed += p.vulnerabilities.fixed;
    introduced += p.vulnerabilities.introduced;
  }
  return {
    applications: report.totals.applications,
    ...(report.meta.vulnScanningEnabled
      ? { fixed, introduced, openFindings: open.findings, openCritical: open.critical, openHigh: open.high }
      : {}),
    needAttention: report.attention.projects.length,
  };
}

/**
 * The values an administrator's template may refer to.
 *
 * Strings rather than numbers, because they go straight into text and a locale-formatted
 * "1,234" is what a reader expects. Every documented placeholder has an entry; one without would
 * render as itself, which is right for a typo and wrong for a documented name. A figure the run
 * did not measure - scanning was off - reads "n/a", never 0.
 */
export function placeholdersFor(run: ReportRunSummary, totals: StoredTotals): Record<string, string> {
  const n = (value: number | undefined) => (value === undefined ? "n/a" : value.toLocaleString("en-US"));
  const net =
    totals.fixed === undefined || totals.introduced === undefined
      ? "n/a"
      : (() => {
          const d = totals.introduced - totals.fixed;
          return d > 0 ? `+${d.toLocaleString("en-US")}` : d.toLocaleString("en-US");
        })();
  return {
    period: run.periodLabel,
    applications: n(totals.applications),
    findings: n(totals.openFindings),
    critical: n(totals.openCritical),
    high: n(totals.openHigh),
    fixed: n(totals.fixed),
    resolved: n(totals.fixed),
    introduced: n(totals.introduced),
    net,
    attention: n(totals.needAttention),
    generatedAt: new Date(run.generatedAt).toISOString().slice(0, 16).replace("T", " ") + " UTC",
  };
}

export class ReportService {
  constructor(
    private readonly deps: {
      db: Database;
      blobStore: BlobStore;
      analytics: AnalyticsService;
      settings: SettingsService;
      mailer: Mailer;
      logger: FastifyBaseLogger;
    },
  ) {}

  /** Produces the analytics report for the period and files it. */
  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const now = options.now ?? new Date();
    const timeZone = options.timeZone ?? REPORT_DEFAULT_TIMEZONE;
    const period: ReportPeriod =
      options.kind === "monthly" ? previousMonthPeriod(now, timeZone) : currentMonthPeriod(now, timeZone);

    // Cheap guard first: a scheduler retrying all month should not rebuild a report it will
    // not keep. The unique index below remains the real guarantee against a race.
    if (options.kind === "monthly") {
      const existing = await this.findMonthly(options.scope, period.start);
      if (existing) return { run: this.summaryOf(existing), alreadyExisted: true };
    }

    const report = await this.deps.analytics.report({
      periodDays: reportWindowDays(period, now),
      generatedBy: options.actor?.email ?? null,
      // The whole estate: a report to management is not narrowed to one team.
      filter: EMPTY_TEAM_FILTER,
      scope: options.scope,
      now,
    });
    const [open, dbBuiltAt] = await Promise.all([this.openFindings(options.scope), this.vulnDbBuiltAt()]);

    const inserted = await this.insertRun({
      scope: options.scope,
      kind: options.kind,
      period,
      timeZone,
      report,
      totals: totalsOf(report, open),
      vulnDbBuiltAt: report.meta.vulnScanningEnabled ? dbBuiltAt : null,
      actor: options.actor,
    });

    if (!inserted) {
      // Another process won the race for this month: return its run, untouched.
      const existing = await this.findMonthly(options.scope, period.start);
      if (!existing) throw new ConflictError("This month's report is already being generated");
      return { run: this.summaryOf(existing), alreadyExisted: true };
    }
    return { run: this.summaryOf(inserted), alreadyExisted: false };
  }

  /** History, newest first. Payloads are not loaded: the list shows totals only. */
  async list(limit = 50): Promise<ReportRunSummary[]> {
    const rows = await this.deps.db.execute<Row<RunRow>>(sql`
      SELECT ${RUN_COLUMNS} FROM report_run r
      ORDER BY r.generated_at DESC
      LIMIT ${limit}
    `);
    return rowsOf(rows).map((row) => this.summaryOf(row));
  }

  async get(id: string): Promise<ReportDetail> {
    const run = await this.findById(id);
    if (!run) throw new NotFoundError("Report");
    return { run: this.summaryOf(run) };
  }

  /**
   * The report as a PDF, rendered once and stored.
   *
   * Rendered from the stored payload rather than a fresh query, so the file downloaded a year
   * from now is the file that was emailed, and cached so the attachment and a later download
   * are the same bytes. A run from the earlier format has no payload; its stored PDF is the
   * record, and if that was never stored there is nothing honest to render in its place.
   */
  async pdf(id: string): Promise<{ buffer: Buffer; filename: string; run: ReportRunSummary }> {
    const row = await this.findById(id);
    if (!row) throw new NotFoundError("Report");
    const run = this.summaryOf(row);
    const filename = `sbom-monthly-report-${run.periodLabel}.pdf`;

    if (row.pdf_blob_key) {
      try {
        return { buffer: await this.deps.blobStore.get(row.pdf_blob_key), filename, run };
      } catch {
        // The row says it was stored and the store disagrees; re-render from the payload below.
      }
    }

    const report = await this.payloadOf(id);
    if (!report) {
      throw new ConflictError(
        "This report was produced in an earlier format and its PDF was not stored, so it cannot be rendered again.",
      );
    }
    const buffer = await renderReportPdf(report, { title: `SBOM monthly report ${run.periodLabel}` });
    const key = `report/${run.periodLabel}/${run.id}.pdf`;
    await this.deps.blobStore.put(key, buffer);
    await this.attachPdf(run.id, key);
    return { buffer, filename, run: { ...run, hasPdf: true } };
  }

  /**
   * Records where a run's rendered PDF was stored. Separate from generation: the payload is the
   * part that cannot be recreated, so it is committed before anything as failure-prone as
   * rendering and mailing is attempted.
   */
  async attachPdf(id: string, blobKey: string): Promise<void> {
    await this.deps.db.execute(sql`UPDATE report_run SET pdf_blob_key = ${blobKey} WHERE id = ${id}::uuid`);
  }

  /**
   * Mails a report to the configured recipients.
   *
   * Claimed before it is sent, with a conditional update that only succeeds while `sent_at` is
   * null, so a second attempt is a no-op: two schedulers racing, or one restarting mid-month,
   * cannot both win. A failed send releases the claim and records why, so the next attempt
   * retries. A crash between claiming and the relay accepting leaves a report marked sent that
   * was not - preferred to a duplicate, and it can be resent from the history page.
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
      const existing = await this.findById(id);
      if (!existing) throw new NotFoundError("Report");
      return { sent: false, recipients: (existing.recipients as string[] | null) ?? [] };
    }

    try {
      const { buffer, filename, run } = await this.pdf(id);
      const row = await this.findById(id);
      const values = placeholdersFor(run, row?.totals ?? {});
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
      await db.execute(sql`
        UPDATE report_run SET sent_at = NULL, delivery_error = ${message}
        WHERE id = ${id}::uuid
      `);
      logger.error({ reportId: id, err }, "monthly report delivery failed");
      return { sent: false, recipients: [], error: message };
    }
  }

  // -- internals -------------------------------------------------------------

  private summaryOf(row: RunRow): ReportRunSummary {
    const t = row.totals ?? {};
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
      hasPdf: row.pdf_blob_key !== null,
      sentAt: iso(row.sent_at),
      recipients: Array.isArray(row.recipients) ? (row.recipients as string[]) : null,
      deliveryError: row.delivery_error,
      totals: {
        applications: num(t.applications) ?? 0,
        fixed: num(t.fixed),
        introduced: num(t.introduced),
        needAttention: num(t.needAttention),
      },
    };
  }

  private async payloadOf(id: string): Promise<AnalyticsReport | null> {
    const rows = await this.deps.db.execute<Row<{ report: AnalyticsReport | null }>>(sql`
      SELECT report FROM report_run WHERE id = ${id}::uuid
    `);
    return rowsOf(rows)[0]?.report ?? null;
  }

  /** Open findings in current builds of the estate, from the same per-build summaries every page reads. */
  private async openFindings(scope: ReadScope): Promise<{ findings: number; critical: number; high: number }> {
    const rows = await this.deps.db.execute<Row<{ findings: number | string; critical: number | string; high: number | string }>>(sql`
      SELECT coalesce(sum(vs.app_findings + vs.os_findings), 0)::int AS findings,
             coalesce(sum(vs.app_critical + vs.os_critical), 0)::int AS critical,
             coalesce(sum(vs.app_high + vs.os_high), 0)::int AS high
      FROM application a
      JOIN scan_vuln_summary vs ON vs.scan_id = a.latest_scan_id
      WHERE a.status <> 'inactive' AND ${applicationInScope("a", scope)}
    `);
    const r = rowsOf(rows)[0];
    return { findings: Number(r?.findings ?? 0), critical: Number(r?.critical ?? 0), high: Number(r?.high ?? 0) };
  }

  /** Build date of the vulnerability database behind the figures, so a stale report is explainable. */
  private async vulnDbBuiltAt(): Promise<string | null> {
    const rows = await this.deps.db.execute<Row<{ built_at: Date | string | null }>>(sql`
      SELECT db_built_at AS built_at FROM scan_vuln_summary
      ORDER BY db_built_at DESC NULLS LAST
      LIMIT 1
    `);
    return iso(rowsOf(rows)[0]?.built_at ?? null);
  }

  private async findById(id: string): Promise<RunRow | null> {
    const rows = await this.deps.db.execute<Row<RunRow>>(sql`
      SELECT ${RUN_COLUMNS} FROM report_run r WHERE r.id = ${id}::uuid
    `);
    return rowsOf(rows)[0] ?? null;
  }

  private async findMonthly(scope: ReadScope, periodStart: Date): Promise<RunRow | null> {
    const rows = await this.deps.db.execute<Row<RunRow>>(sql`
      SELECT ${RUN_COLUMNS} FROM report_run r
      WHERE r.kind = 'monthly' AND r.environment_id = ${scope.id}::uuid
        AND r.period_start = ${periodStart.toISOString()}::timestamptz
    `);
    return rowsOf(rows)[0] ?? null;
  }

  /**
   * Inserts the run, returning null when the monthly guard rejected it. The guard is the unique
   * index rather than the preceding SELECT: a check-then-insert has a window between the two,
   * and a container restart is exactly when that window gets hit.
   */
  private async insertRun(input: {
    scope: ReadScope;
    kind: ReportKind;
    period: ReportPeriod;
    timeZone: string;
    report: AnalyticsReport;
    totals: StoredTotals;
    vulnDbBuiltAt: string | null;
    actor: { id: string; email: string } | undefined;
  }): Promise<RunRow | null> {
    try {
      const rows = await this.deps.db.execute<Row<RunRow>>(sql`
        INSERT INTO report_run (
          environment_id, kind, period_start, period_end, period_label, time_zone,
          generated_by_user_id, generated_by_email, vuln_db_built_at, report, totals
        ) VALUES (
          ${input.scope.id}::uuid,
          ${input.kind},
          ${input.period.start.toISOString()}::timestamptz,
          ${input.period.end.toISOString()}::timestamptz,
          ${input.period.label},
          ${input.timeZone},
          ${input.actor?.id ?? null}::uuid,
          ${input.actor?.email ?? null},
          ${input.vulnDbBuiltAt}::timestamptz,
          ${JSON.stringify(input.report)}::jsonb,
          ${JSON.stringify(input.totals)}::jsonb
        )
        RETURNING ${RUN_COLUMNS_BARE}
      `);
      return rowsOf(rows)[0] ?? null;
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) return null;
      throw err;
    }
  }
}

/** Everything but the payload: listing a year of runs must not transfer a year of reports. */
const RUN_COLUMNS = sql.raw(
  "r.id, r.kind, r.period_start, r.period_end, r.period_label, r.time_zone, r.generated_at, " +
    "r.generated_by_email, r.vuln_db_built_at, r.pdf_blob_key, r.sent_at, r.recipients, r.delivery_error, r.totals",
);
const RUN_COLUMNS_BARE = sql.raw(
  "id, kind, period_start, period_end, period_label, time_zone, generated_at, " +
    "generated_by_email, vuln_db_built_at, pdf_blob_key, sent_at, recipients, delivery_error, totals",
);
