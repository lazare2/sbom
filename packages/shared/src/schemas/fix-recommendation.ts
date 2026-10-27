import { z } from "zod";
import type { SeverityCounts, VulnSeverity } from "./vulnerability.js";
import { vulnScopeSchema } from "./vulnerability.js";

/**
 * Which version to upgrade each vulnerable package to.
 *
 * The findings table answers "what is wrong" one advisory at a time, and every row carries its
 * own "fixed in". Read that way, a package with five advisories offers five different versions
 * and leaves the reader to work out which one clears them all. This turns them into one answer
 * per package: the lowest version that clears every advisory currently reported against it.
 *
 * ## Then it checks the answer
 *
 * The version that clears today's findings is not necessarily safe - it can be affected by
 * advisories that never applied to the version in use, and nothing in the findings says so,
 * because nothing in the estate ships it. So the candidate is put to the scanner as if it were a
 * package, and if anything comes back the next fix is taken and checked in turn, until either a
 * version with no known vulnerabilities is reached or the remaining advisories have no fix.
 *
 * Both are reported: `minimumVersion`, the least change that clears what is reported now, and
 * `recommendedVersion`, where the checking ended. When they differ, the screen says why.
 *
 * ## What it cannot know
 *
 * Version ordering across ecosystems is a heuristic (see the comparator in the API), and an
 * upgrade the scanner calls clean can still break the build. These are recommendations about
 * vulnerabilities, not about compatibility.
 */

export const fixRecommendationQuerySchema = z.object({
  scope: vulnScopeSchema.default("all"),
  /**
   * Whether to check candidate versions against the scanner.
   *
   * The screen asks twice: first without, which is a single query and answers at once, then
   * with, which may run the scanner. Waiting on the second before drawing anything would leave
   * the page blank for as long as a scanner run takes the first time.
   */
  verify: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .default("true"),
});
export type FixRecommendationQuery = z.infer<typeof fixRecommendationQuerySchema>;

/** One advisory currently reported against the package, and what clears it. */
export interface FixRecommendationAdvisory {
  vulnerabilityId: string;
  severity: VulnSeverity;
  knownExploited: boolean;
  /** Which installed version it was reported against, when the package ships several. */
  installedVersion: string | null;
  fixVersions: string[];
  /** The fix version chosen for this advisory: the lowest one above the installed version. */
  fixedIn: string | null;
  /** `fixed`, `not-fixed`, `wont-fix` or `unknown`, as the scanner reports it. */
  fixState: string;
}

/** An advisory found against a candidate version when it was checked. */
export interface CandidateAdvisory {
  vulnerabilityId: string;
  severity: VulnSeverity;
  /** The fix chosen for it above the candidate, or null when there is none. */
  fixedIn: string | null;
}

/**
 * One version that was put to the scanner, and what it reported.
 *
 * The chain of these is the explanation for a recommendation that differs from the minimum:
 * "2.3 is still affected by CVE-…, fixed in 2.8; 2.8 has no known vulnerabilities."
 */
export interface CandidateCheck {
  version: string;
  advisories: CandidateAdvisory[];
}

export type FixRecommendationStatus =
  /** The recommended version was checked and nothing is known against it. */
  | "clean"
  /** Checked, and still affected by advisories nobody has fixed yet. */
  | "residual"
  /** Not checked - the scanner was unavailable, verification was not asked for, or the cap was hit. */
  | "unverified"
  /** Nothing to recommend: none of the advisories reported against it has a fix. */
  | "no_fix";

export interface FixRecommendation {
  /** `ecosystem:name`, stable across builds - the package, not one version of it. */
  key: string;
  name: string;
  ecosystem: string;
  /** `app` for a dependency, `os` for a base-image package. Same split as everywhere else. */
  origin: "app" | "os";
  /** Every version of it in the current build. Usually one. */
  installedVersions: string[];
  findings: number;
  counts: SeverityCounts;
  highestSeverity: VulnSeverity;
  knownExploited: number;
  advisories: FixRecommendationAdvisory[];
  /**
   * The lowest version that clears every advisory currently reported that has a fix.
   *
   * Null when none of them has one.
   */
  minimumVersion: string | null;
  /** How many of the current findings `minimumVersion` clears. */
  resolvedByMinimum: number;
  /** Where checking ended: the version to upgrade to. Equal to the minimum when unverified. */
  recommendedVersion: string | null;
  status: FixRecommendationStatus;
  /** Each version checked, in order, starting from the minimum. Empty when unverified. */
  checks: CandidateCheck[];
}

export interface FixRecommendationReport {
  applicationId: string;
  /** The build these were computed from. Null for an application with no scans. */
  scanId: string | null;
  scope: z.infer<typeof vulnScopeSchema>;
  verification: {
    /**
     * `verified` when candidates were checked, `skipped` when the caller did not ask,
     * `unavailable` when the scanner could not be used - with `message` saying why.
     */
    status: "verified" | "skipped" | "unavailable" | "partial";
    message: string | null;
    /** The database the checks ran against, when the scanner reports one. */
    databaseBuiltAt: string | null;
  };
  summary: {
    packages: number;
    findings: number;
    /** Findings the recommended upgrades clear. */
    resolvable: number;
    /** Findings with no fix anywhere. Upgrading does not clear these. */
    withoutFix: number;
  };
  recommendations: FixRecommendation[];
}
