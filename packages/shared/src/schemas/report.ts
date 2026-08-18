import { z } from "zod";

/**
 * The monthly estate report: what changed, and why it changed.
 *
 * The hard requirement is honesty about causation. Findings are matched against *today's*
 * vulnerability database across every retained build, so a count that fell between two
 * reports means one of two very different things:
 *
 *   - somebody upgraded a package, or
 *   - the vulnerability database changed under us
 *
 * A report that presents those as one number ("47 fixed") tells management the team did work
 * it did not do, or hides work it did. Every movement here is therefore attributed to a
 * cause, and the causes are distinguishable because each report stores a snapshot of what it
 * counted alongside the database build it counted against.
 */

/** Snapshot format version, so an older row can be read or refused deliberately. */
export const REPORT_SNAPSHOT_VERSION = 1;

/**
 * Why a finding stopped being reported.
 *
 * The distinction between the first two is the whole point of the report. The first is work
 * the organisation did; the second is the world changing its mind, and crediting it to
 * anyone would be false.
 */
export type ResolvedCause =
  /** The vulnerable package is no longer in the application's current build. */
  | "upgraded-or-removed"
  /** The package is still there; the advisory no longer matches it. */
  | "advisory-withdrawn-or-rescored"
  /** The whole application left the estate, so its findings left with it. */
  | "application-removed";

/** Why a finding started being reported. */
export type IntroducedCause =
  /** A package arrived in a build that was not there before. */
  | "new-dependency"
  /** The package was already there; the advisory is new or newly matched. */
  | "newly-published-advisory"
  /** A newly tracked application arrived carrying it. */
  | "application-added";

export const reportKinds = ["monthly", "adhoc"] as const;
export type ReportKind = (typeof reportKinds)[number];

/**
 * A finding, reduced to the identity that makes it the same finding next month.
 *
 * Version is part of it: `openssl 3.0.11` and `openssl 3.0.14` carrying the same CVE are not
 * the same finding, and treating them as one would report an upgrade that fixed nothing as
 * no change at all.
 */
export interface SnapshotFindingKey {
  applicationId: string;
  componentId: number;
  vulnerabilityId: string;
}

export interface SnapshotApplication {
  id: string;
  name: string;
  status: string;
  lastScanAt: string | null;
}

export interface SnapshotComponent {
  id: number;
  name: string;
  version: string | null;
  ecosystem: string;
  /** `os`/`runtime`/`library`, as recorded on the component. */
  kind: string;
  /**
   * `app` or `os`, decided by the same SQL predicate every other view uses.
   *
   * Stored rather than derived from `kind`, because the split is not `kind = 'library'`: a
   * Debian image carries ~1,500 `library` components with deb purls that are base image, not
   * dependencies. Deriving it here would let the report disagree with every dashboard about
   * what counts as a dependency -- and since base-image findings outnumber real ones by
   * around a hundred to one, that disagreement would be the report's headline number.
   */
  scope: "app" | "os";
}

/**
 * What one report counted.
 *
 * Stored rather than recomputed because neither of the two things it captures survives:
 * a deleted application leaves no rows to diff, and re-running last month's query today
 * answers with today's vulnerability database rather than last month's.
 */
export interface ReportSnapshot {
  version: number;
  takenAt: string;
  /** Build date of the vulnerability database when this was taken. Null if scanning was off. */
  vulnDbBuiltAt: string | null;
  applications: SnapshotApplication[];
  components: SnapshotComponent[];
  /** `applicationId` -> component ids in that application's current build. */
  dependencies: Record<string, number[]>;
  /** Findings as `applicationId|componentId|vulnerabilityId`, flat for cheap set maths. */
  findings: string[];
  /** Severity by vulnerability id, so severity movement can be reported without a re-query. */
  severities: Record<string, string>;
  totals: {
    applications: number;
    components: number;
    findings: number;
    bySeverity: Record<string, number>;
  };
}

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

/** A finding that moved between two reports, with enough context to be acted on. */
export interface FindingMovement {
  applicationId: string;
  applicationName: string;
  component: SnapshotComponent | null;
  vulnerabilityId: string;
  severity: string;
}

export interface ResolvedFinding extends FindingMovement {
  cause: ResolvedCause;
}

export interface IntroducedFinding extends FindingMovement {
  cause: IntroducedCause;
}

/** Everything the report says changed, and why. Computed from two snapshots, never stored. */
export interface ReportDelta {
  /** True when the vulnerability database moved between the two snapshots. */
  databaseChanged: boolean;
  baselineDbBuiltAt: string | null;
  currentDbBuiltAt: string | null;

  applications: {
    added: Array<{ id: string; name: string }>;
    removed: Array<{ id: string; name: string }>;
    total: number;
    previousTotal: number;
  };

  dependencies: {
    /** Distinct (application, component) pairs gained and lost across the estate. */
    added: number;
    removed: number;
    total: number;
    previousTotal: number;
  };

  findings: {
    resolved: ResolvedFinding[];
    introduced: IntroducedFinding[];
    /** Present now, absent in the baseline, present in the report before it. */
    reintroduced: FindingMovement[];
    total: number;
    previousTotal: number;
    bySeverity: Record<string, { now: number; before: number }>;
  };
}

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
  baselineRunId: string | null;
  hasPdf: boolean;
  sentAt: string | null;
  recipients: string[] | null;
  deliveryError: string | null;
  totals: {
    applications: number;
    components: number;
    findings: number;
  };
}

/**
 * A generated report, as returned by the generate endpoint and the history detail view.
 *
 * The snapshot itself is not part of this. It runs to hundreds of kilobytes, exists to be
 * diffed rather than displayed, and every number a reader wants from it is already in the
 * delta or the totals.
 *
 * `delta` is null for the very first report, which has nothing to compare against. Rendering
 * that case as "everything was introduced this month" would be the report's first and worst
 * lie, so the absence is explicit and the renderer says so.
 */
export interface ReportDetail {
  run: ReportRunSummary;
  delta: ReportDelta | null;
}
