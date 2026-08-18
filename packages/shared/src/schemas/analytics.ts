import { z } from "zod";
import type {
  EcosystemBreakdownEntry,
  PlatformBreakdown,
  TopComponentEntry,
} from "./admin.js";
import type { SeverityCounts, VulnFilterState } from "./vulnerability.js";

/**
 * Estate analytics: the numbers behind the `/analytics` page and the PDF report.
 *
 * One shape serves both deliberately. A printed report and a screen that disagree
 * about the same figure is the failure mode that destroys trust in a reporting
 * tool, and the only reliable way to prevent it is for them to be renderings of
 * one payload rather than two query paths that happen to be written similarly.
 *
 * Most figures here are counts and comparisons over SBOM contents, and make no claim
 * about risk — where a section could be mistaken for a risk judgement, its doc comment
 * says what it actually measures.
 *
 * The exception is `vulnerabilities`, which is populated by matching those contents
 * against the Grype database when an administrator has enabled scanning. It is `null`
 * when scanning is off, and that distinction is deliberate: a zero-filled structure
 * cannot be told apart from a clean estate, and reporting an unscanned estate as clean
 * would be the most damaging thing this report could do.
 */

/**
 * Reporting window, in days.
 *
 * Bounds the "what changed" sections. Two years is the ceiling because beyond
 * that the baseline comparison stops being a report and becomes an archaeology
 * exercise over the full scan history.
 */
export const analyticsQuerySchema = z.object({
  periodDays: z.coerce.number().int().min(1).max(730).default(30),
});
export type AnalyticsQuery = z.infer<typeof analyticsQuerySchema>;

/**
 * Query for the coverage section on its own.
 *
 * Exists so the overview can ask "which applications is nobody scanning" without paying for
 * churn, fragmentation and the package rankings it does not display. The answer comes from
 * the same query the full report uses, so the two can never disagree about what is stale.
 */
export const coverageQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(8),
});
export type CoverageQuery = z.infer<typeof coverageQuerySchema>;

/** Provenance. Printed on the report's first page and shown in the page header. */
export interface ReportMeta {
  generatedAt: string;
  /**
   * Login identifier of whoever asked for it, or null for an unattributed
   * render. A report that circulates without a date and an author gets quoted
   * six months later as if it were current.
   */
  generatedBy: string | null;
  periodDays: number;
  /** Start of the reporting window, as an absolute timestamp. */
  periodStart: string;
  staleThresholdDays: number;
}

export interface EstateTotals {
  applications: number;
  activeApplications: number;
  inactiveApplications: number;
  pendingApplications: number;
  scans: number;
  scansInPeriod: number;
  /** Distinct packages known across all retained history. */
  distinctPackages: number;
  /** Distinct packages present in some application's current build. */
  packagesInUse: number;
  latestScanAt: string | null;
}

/**
 * How much of the estate the inventory can actually see.
 *
 * The section nobody requests and every reader needs: totals computed over an
 * inventory with blind spots read as authoritative unless the blind spots are
 * stated next to them. `coveragePct` is the honest qualifier on every other
 * number in the report.
 */
export interface CoverageReport {
  /** Active applications — the denominator. */
  eligible: number;
  /** Active applications with a build inside the stale threshold. */
  covered: number;
  coveragePct: number;
  stale: number;
  neverScanned: number;
  pendingConfirmation: number;
  /**
   * The longest-silent applications, oldest first. Never-scanned applications
   * sort first with a null `lastScanAt` — they are the worst case, not a missing
   * value.
   */
  worstOffenders: Array<{
    applicationId: string;
    name: string;
    lastScanAt: string | null;
    daysSinceScan: number | null;
  }>;
}

/**
 * Applications carrying the most packages in their current build.
 *
 * A size ranking, not a risk ranking. Large images are worth knowing about
 * because they cost more to review, rebuild and patch, but a 2000-package image
 * is not automatically worse than a 40-package one.
 */
export interface TopProjectEntry {
  applicationId: string;
  name: string;
  packages: number;
  /** When the counted build arrived, so the reader can judge the figure's age. */
  scanAt: string | null;
  /** One-line platform summary of that build, e.g. `Alpine 3.20.3 · Node.js 22.11.0`. */
  platform: string | null;
}

/**
 * Packages the estate runs several versions of at the same time.
 *
 * Standardisation targets. Every extra concurrent version multiplies the cost of
 * the next upgrade campaign for that package, and unlike most metrics here this
 * one names work that can actually be finished.
 */
export interface FragmentationEntry {
  name: string;
  ecosystem: string;
  /** Distinct versions in current builds. */
  versions: number;
  /** Applications shipping any version of it. */
  applications: number;
  /** A sample of the versions, capped, so the row is actionable without a drill-down. */
  examples: string[];
}

/**
 * Packages that entered the estate during the window.
 *
 * The supply-chain review queue: what is in our images now that was not here
 * before. `firstSeenAt` is the earliest scan any build carried it, derived from
 * scan timestamps rather than row-insert time so a re-seeded or backfilled
 * database still reports the truth.
 */
export interface NewPackageEntry {
  componentId: string;
  name: string;
  version: string | null;
  ecosystem: string;
  firstSeenAt: string;
  /** Applications currently shipping it. */
  applications: number;
}

/**
 * Dependency churn across the estate over the window.
 *
 * Counted by package *name* within an ecosystem, not by exact version, so a
 * version bump registers as one upgrade rather than one addition plus one
 * removal. This matches what the per-application diff view already shows, and
 * without it a routine patch round would read as thousands of packages added and
 * thousands removed.
 */
export interface VelocitySummary {
  scans: number;
  applicationsScanned: number;
  /** Applications that had a build both before and inside the window. */
  applicationsCompared: number;
  /**
   * Applications with no build before the window — onboarded during it, or
   * scanned for the first time. Excluded from the counts below: every package in
   * a newly onboarded application would otherwise register as an addition and
   * swamp the real churn.
   */
  applicationsWithoutBaseline: number;
  /**
   * Applications whose newest build predates the window entirely, so they are
   * unchanged by definition.
   *
   * Reported rather than left implicit because these three counts have to account
   * for every scanned application: without this one a reader subtracts the other
   * two from the application total and gets a number that does not mean what they
   * think, since the churn buckets span all non-inactive applications while
   * `CoverageReport.eligible` counts only active ones.
   */
  applicationsUnchanged: number;
  packagesAdded: number;
  packagesRemoved: number;
  packagesUpgraded: number;
}

/** One bucket of scan activity, for the trend line. */
export interface ActivityBucket {
  /** Start of the bucket (a week, or a day for short windows). */
  bucketStart: string;
  scans: number;
  /** Distinct applications that reported in this bucket. */
  applications: number;
}

/**
 * One entry in "Top 10 vulnerable applications".
 *
 * Ranked on one half of the split, never on the sum. Application dependencies by
 * default, and base-image findings only when the filter asks for base image alone —
 * measured on a realistic container SBOM, base-image packages account for 99% of
 * findings, so a combined ranking is a base-image-age ranking regardless of what its
 * title claims. The other half is carried alongside for context.
 */
export interface TopVulnerableApplication {
  applicationId: string;
  name: string;
  status: string;
  /**
   * Application-dependency findings matching the active filter, or null when the scope
   * filter excludes application dependencies. Null rather than 0, so a scope that was
   * never counted cannot be rendered as a scope with nothing in it.
   */
  findings: number | null;
  /** Base-image findings for the same build, or null when the scope filter excludes them. */
  baseImageFindings: number | null;
  /**
   * Which half the row was ranked on — `app` unless the filter asks for base image only.
   *
   * The counts below describe that same half, so every number on a row belongs to one
   * set. Ranking never combines the two: on a typical image base-image packages are
   * around 99% of findings, so a combined ranking orders applications by base-image age
   * whatever its column header claims.
   */
  rankedBy: "app" | "os";
  critical: number;
  high: number;
  /** Findings with a fix available — the actionable subset. */
  fixable: number;
  knownExploited: number;
  affectedPackages: number;
  /** Which database build these counts came from, so a stale row is explainable. */
  dbBuiltAt: string | null;
}

/**
 * One entry in "Top 10 vulnerable packages".
 *
 * Ranked by advisory count on the package version itself, over packages in some
 * application's current build. `applications` is the blast radius: a package with four
 * advisories in thirty applications matters more than one with eight in a single service.
 *
 * Application dependencies unless the filter asks for base image alone. A list mixing the
 * two would be a list of distribution packages: they outnumber chosen dependencies by
 * roughly a hundred to one, so they would take every row and the ranking would stop
 * naming anything a team can act on.
 */
export interface TopVulnerablePackage {
  componentId: number;
  name: string;
  version: string | null;
  ecosystem: string;
  /** True when this package came from the base image rather than a dependency manifest. */
  baseImage: boolean;
  findings: number;
  critical: number;
  high: number;
  knownExploited: number;
  /** Applications whose current build contains this package version. */
  applications: number;
  /**
   * The applications behind that count, capped at EXPANDABLE_LIST_CAP.
   *
   * Produced by the same aggregate and the same WHERE clause as the count, so the two
   * cannot disagree on screen. See EXPANDABLE_LIST_CAP for why that is a constraint rather
   * than a convenience.
   */
  applicationList: string[];
  /** True when at least one advisory on it has a fix available. */
  fixAvailable: boolean;
  /** Highest fixed version offered across its advisories, when there is one. */
  fixVersions: string[];
}

/**
 * Totals for one half of the app/base-image split.
 *
 * Symmetric on purpose. Base-image exposure is a first-class half of this report, not a
 * footnote to the application figures, and "is a rebuild going to fix this" is answered
 * by `fixable` on the base-image side exactly as it is on the application side.
 */
export interface VulnScopeTotals {
  counts: SeverityCounts;
  /** Findings with a fix available — the actionable subset. */
  fixable: number;
  knownExploited: number;
  /** Distinct affected package versions across the estate, counted once each. */
  affectedPackages: number;
}

/**
 * Estate-wide vulnerability posture.
 *
 * Null on the report when scanning is disabled, rather than a zero-filled object. A
 * zeroed structure is indistinguishable from a clean estate, and a report that shows a
 * clean bill of health for something never scanned is the worst thing this feature could
 * produce. Consumers must branch on the null.
 *
 * The same rule applies one level down: `app` and `baseImage` are null when the active
 * filter excludes that half, so "not counted" and "counted, found nothing" stay
 * distinguishable everywhere a filter can be applied.
 */
export interface VulnerabilityReport {
  /** Grype's build timestamp for the database these figures came from. */
  dbBuiltAt: string | null;
  dbAgeHours: number | null;
  /** Applications whose current build has been matched. */
  applicationsScanned: number;
  /** Applications with a current build that has not been matched yet. */
  applicationsPending: number;

  /**
   * What every figure below was narrowed by.
   *
   * Carried on the payload so the page header, the PDF cover and any export state the
   * same filter in the same words instead of composing it independently.
   */
  filter: VulnFilterState;

  /** Application-dependency totals, or null when the scope filter excludes them. */
  app: VulnScopeTotals | null;
  /** Base-image and runtime totals, or null when the scope filter excludes them. */
  baseImage: VulnScopeTotals | null;

  /** Applications with at least one finding matching the filter. */
  applicationsAffected: number;

  topVulnerableApplications: TopVulnerableApplication[];
  topVulnerablePackages: TopVulnerablePackage[];
  /**
   * Base-image exposure grouped by distribution, so "who is on an old image" is visible.
   * Null when the scope filter excludes base-image packages.
   */
  baseImageExposure: Array<{
    osName: string | null;
    osVersion: string | null;
    applications: number;
    findings: number;
    critical: number;
    high: number;
  }> | null;

  /**
   * Unfiltered severity totals, present only when a filter is active.
   *
   * The reference point. A filtered report that circulates without one is read as the
   * whole picture, and the reader has no way to tell what was left out — so when a filter
   * narrows the figures, the report also carries what it narrowed them from.
   */
  unfiltered: { app: SeverityCounts; baseImage: SeverityCounts } | null;
}

export interface AnalyticsReport {
  meta: ReportMeta;
  totals: EstateTotals;
  coverage: CoverageReport;
  /** Blast-radius list: packages present in the most applications. */
  topPackages: TopComponentEntry[];
  /** Size list: applications with the most packages. */
  topProjects: TopProjectEntry[];
  fragmentation: FragmentationEntry[];
  newPackages: NewPackageEntry[];
  velocity: VelocitySummary;
  activity: ActivityBucket[];
  ecosystems: EcosystemBreakdownEntry[];
  platforms: PlatformBreakdown;
  /**
   * Vulnerability sections, or null when scanning is disabled.
   *
   * Null rather than empty for the reason given on `VulnerabilityReport`: the PDF and
   * the page both have to say "not assessed" rather than render zeros.
   */
  vulnerabilities: VulnerabilityReport | null;
}
