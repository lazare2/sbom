import { z } from "zod";

/**
 * The monthly report: the analytics report for the month, filed and emailed.
 *
 * It is the same payload the Analytics page shows and the same PDF it downloads, generated for
 * one estate over the month and stored with the run - so what management was sent can be
 * re-read later exactly as it was, and never disagrees with what the screen showed that day.
 *
 * Reports produced before this format carried a different document. Their stored PDFs remain
 * downloadable; they have no payload, and their totals are the ones they were filed with.
 */

export const reportKinds = ["monthly", "adhoc"] as const;
export type ReportKind = (typeof reportKinds)[number];

export const generateReportSchema = z.object({
  kind: z.enum(reportKinds).default("adhoc"),
  /** Send it as well as generate it. Defaults false: the button previews, it does not mail. */
  send: z.coerce.boolean().default(false),
});
export type GenerateReportBody = z.infer<typeof generateReportSchema>;

/**
 * Default timezone for the monthly cycle.
 *
 * A default rather than a hardcoding: the period boundary and the send time are both local
 * concepts, and an administrator can change this. It is here rather than in the API's
 * environment because the admin panel has to show the value it is editing.
 */
export const REPORT_DEFAULT_TIMEZONE = "Asia/Tbilisi";

/** One row of report history, as the admin panel lists it. */
export interface ReportRunSummary {
  id: string;
  kind: ReportKind;
  periodStart: string;
  periodEnd: string;
  /** `YYYY-MM` of the month covered, as decided at generation time. */
  periodLabel: string;
  /** The zone whose calendar month the period bounds, recorded so the label stays readable. */
  timeZone: string;
  generatedAt: string;
  /** Null for a scheduled run: nobody pressed anything. */
  generatedBy: string | null;
  vulnDbBuiltAt: string | null;
  hasPdf: boolean;
  sentAt: string | null;
  recipients: string[] | null;
  deliveryError: string | null;
  /**
   * The headline figures the run was filed with. `fixed`, `introduced` and `needAttention` are
   * null for reports from before the current format, which did not measure them - a zero would
   * claim a month in which nothing happened.
   */
  totals: {
    applications: number;
    fixed: number | null;
    introduced: number | null;
    needAttention: number | null;
  };
}

/** A generated report, as returned by the generate endpoint and the history detail view. */
export interface ReportDetail {
  run: ReportRunSummary;
}
