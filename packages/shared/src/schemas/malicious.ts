import { z } from "zod";
import { paginationQuerySchema, uuidSchema } from "./common.js";
import type { ComponentLocation } from "./location.js";
import { defineSortTable } from "./sort.js";
import {
  maliciousAckStateSchema,
  type MaliciousAckState,
  type MaliciousFeedOutcome,
  type MaliciousMatchMode,
} from "../enums.js";

/**
 * Malicious package detection.
 *
 * ## Why this is not part of the vulnerability contract
 *
 * A vulnerability is a flaw in a package you chose on purpose; you fix it by upgrading. A
 * malicious package IS the attack, and the harm is already done by the time anybody reads
 * about it -- npm runs `postinstall` and pip runs `setup.py`, so the payload executed on a
 * developer's laptop and on a CI runner before a report existed. The remediation is therefore
 * not "upgrade" but "remove it, then rotate every credential that machine could read".
 *
 * Three consequences run through every type below:
 *
 *   1. **There is no severity.** Nothing here carries a CVSS score or a severity bucket,
 *      because malware is binary and inventing a severity would pollute figures that already
 *      mean something precise.
 *   2. **History is not optional.** A package that left the dependency tree three months ago
 *      still ran its payload on the runner that built it, so `MaliciousFinding` reports the
 *      current estate and the historical one side by side and never collapses them.
 *   3. **Provenance travels with the claim.** Telling somebody they shipped malware starts an
 *      incident. Every finding carries its upstream id, its reporters and a reference URL so
 *      the claim can be checked before anyone starts revoking keys.
 */

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/**
 * Whether detection is on, and what it knows.
 *
 * Stays readable at 200 whatever state the feature is in -- the same rule the vulnerability
 * status endpoint follows. The SPA has to be able to tell "switched off" from "on but the
 * feed has never downloaded" from "broken", and an endpoint that refused would collapse all
 * three into a failure the user cannot act on.
 */
export interface MaliciousStatus {
  enabled: boolean;
  /**
   * When the installed feed snapshot was built, or null if none has ever been fetched.
   *
   * Null is the load-bearing case: it is the difference between "we checked and found
   * nothing" and "we have never looked", and no count anywhere may be shown as zero while
   * this is null.
   */
  feedBuiltAt: string | null;
  /** Live reports in the installed snapshot. Null when no snapshot is installed. */
  reportCount: number | null;
  /** Hours between scheduled feed refreshes. */
  intervalHours: number;
  /** True while a refresh or a match sweep is running. */
  refreshing: boolean;
  sweeping: boolean;
  /**
   * How much of the component set has been matched against the current snapshot.
   *
   * Null when nothing has been fetched. Reported so an estate that is half-swept cannot be
   * read as an estate that is half-clean.
   */
  coverage: { matched: number; pending: number } | null;
  /** The most recent refresh attempt, successful or not. Null before the first attempt. */
  lastUpdate: MaliciousFeedAttempt | null;
}

export interface MaliciousFeedAttempt {
  id: string;
  startedAt: string;
  finishedAt: string | null;
  trigger: string;
  outcome: MaliciousFeedOutcome | null;
  message: string | null;
  sourceUrl: string | null;
  feedBuiltAt: string | null;
  reportsTotal: number | null;
  reportsChanged: number | null;
  reportsWithdrawn: number | null;
  actorEmail: string | null;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * Sortable columns of the findings list.
 *
 * Defaults to `currentApplications` descending, so the packages still in something you ship
 * today sort above the ones already gone. Both are shown; only one is urgent.
 */
export const maliciousFindingSort = defineSortTable(
  {
    currentApplications: "number",
    affectedApplications: "number",
    packageName: "text",
    publishedAt: "date",
    firstShippedAt: "date",
  } as const,
  "currentApplications",
);

/** Which slice of the estate a findings list covers. */
export const maliciousPresenceSchema = z.enum([
  /** Everything ever matched, current or not. The honest default. */
  "all",
  /** Only packages present in some application's current build. */
  "current",
  /** Only packages that were shipped historically and are now gone. */
  "historical",
]);
export type MaliciousPresence = z.infer<typeof maliciousPresenceSchema>;

export const listMaliciousQuerySchema = paginationQuerySchema
  .extend({
    search: z.string().trim().max(255).optional(),
    ecosystem: z.string().trim().max(64).optional(),
    presence: maliciousPresenceSchema.default("all"),
    application: uuidSchema.optional(),
    group: uuidSchema.optional(),
    /** `true` hides findings someone has already acknowledged. Default shows everything. */
    unacknowledged: z
      .enum(["true", "false"])
      .transform((v) => v === "true")
      .default("false"),
  })
  .merge(maliciousFindingSort.querySchema);
export type ListMaliciousQuery = z.infer<typeof listMaliciousQuerySchema>;

/**
 * One malicious package, and how far into the estate it reached.
 *
 * The two application counts are the whole point of the row and must never be merged.
 * `currentApplications` is what you still ship and can remove today; `affectedApplications`
 * counts everything that ever contained it, which is the set whose build credentials are
 * suspect. A package with 0 current and 4 historical is not a clean result -- it is four
 * pipelines that need their tokens rotated.
 */
export interface MaliciousFinding {
  /** Upstream OSV id, e.g. `MAL-2024-1677`. */
  id: string;
  ecosystem: string;
  packageName: string;
  summary: string | null;
  matchMode: MaliciousMatchMode;
  /** Versions of this package found in the estate, not the versions the report lists. */
  observedVersions: string[];
  aliases: string[];
  /** Upstream reporters, e.g. `ghsa-malware`. Shown so a claim can be attributed. */
  sources: string[];
  referenceUrl: string | null;
  publishedAt: string | null;
  /** Applications whose current build still contains it. */
  currentApplications: number;
  /** Applications that have ever contained it, in any retained build. */
  affectedApplications: number;
  /** Earliest and latest build that carried it, across the whole retained history. */
  firstShippedAt: string | null;
  lastShippedAt: string | null;
  /** The strongest acknowledgement covering this report, if any. Never hides the row. */
  acknowledgement: MaliciousAckSummary | null;
}

export interface MaliciousAckSummary {
  id: string;
  state: MaliciousAckState;
  note: string;
  /** Null when the acknowledgement covers the whole estate. */
  applicationId: string | null;
  applicationName: string | null;
  acknowledgedByEmail: string | null;
  createdAt: string;
}

/**
 * One malicious package in full, with every application it ever touched.
 *
 * `details` is upstream's write-up and is usually a precise description of what the payload
 * did -- which files it read, where it posted them. It is the difference between a user
 * knowing to rotate npm tokens specifically and rotating everything in a panic.
 */
export interface MaliciousFindingDetail extends MaliciousFinding {
  details: string | null;
  /** What the report says is affected: exact versions, or a range, or the whole package. */
  affectedVersions: string[];
  modifiedAt: string | null;
  withdrawnAt: string | null;
  impacts: MaliciousApplicationImpact[];
  /** Every acknowledgement on this report, estate-wide and per application. */
  acknowledgements: MaliciousAckSummary[];
}

/**
 * How one application was affected.
 *
 * `inCurrentBuild` separates "remove it now" from "it is already gone, but it ran here" --
 * both of which need action, and different action. `builds` is how many retained scans of
 * this application contained it, which is the closest the platform can get to how many times
 * the payload was installed.
 */
export interface MaliciousApplicationImpact {
  applicationId: string;
  applicationName: string;
  applicationStatus: string;
  inCurrentBuild: boolean;
  versions: string[];
  builds: number;
  firstSeenAt: string;
  lastSeenAt: string;
  /** The most recent build containing it, for a direct link into the scan. */
  lastScanId: string;
  /**
   * Where in this application's artifact the package was found.
   *
   * Unioned across every build that carried it rather than read from the newest one, because
   * a package that moved between builds was genuinely in both places and somebody is about to
   * go and delete it. `origin` separates "your dependency" from "inherited from the base
   * image", which decides whose Dockerfile has to change.
   */
  location: ComponentLocation;
  acknowledgement: MaliciousAckSummary | null;
}

// ---------------------------------------------------------------------------
// Dashboard summary
// ---------------------------------------------------------------------------

/**
 * The estate-wide headline.
 *
 * The whole object is null when detection is off or no feed has been installed -- never a
 * structure of zeros, which would read as a clean estate rather than an unexamined one.
 */
export interface MaliciousSummary {
  /**
   * Distinct UNACKNOWLEDGED malicious packages present in some current build.
   *
   * Every count below excludes findings somebody has already acknowledged, which makes this
   * block different from every other read in the feature. The findings list and the detail
   * view keep acknowledged findings visible and marked, because the record of what was
   * shipped must stay intact. This block feeds the dashboard alert, whose entire job is to
   * interrupt -- and a finding a human has already looked at and written a note about has
   * finished interrupting.
   *
   * The exclusion is per (package, application) pair, so a package cleaned up in one
   * application and untouched in another still counts for the second.
   */
  currentPackages: number;
  /** Applications whose current build contains at least one unacknowledged finding. */
  currentApplications: number;
  /** Distinct unacknowledged packages anywhere in retained history, including current. */
  everPackages: number;
  /** Applications that ever contained an unacknowledged one. */
  everApplications: number;
  /**
   * Packages fully acknowledged everywhere they appear, and therefore excluded above.
   *
   * Reported so the alert can say what it is not showing. A count that vanished silently
   * would leave a reader unable to tell a handled estate from an unexamined one.
   */
  acknowledgedPackages: number;
  feedBuiltAt: string;
  /** Components matched against the current feed, and how many are still queued. */
  matchedComponents: number;
  pendingComponents: number;
  /**
   * Digest of the unacknowledged package ids, or null when there are none.
   *
   * Exists so the dashboard alert can be dismissed without being dismissed forever. The
   * client remembers the signature it dismissed; any change to the outstanding set produces a
   * different one and the alert returns. A permanently dismissible malware banner would be a
   * mute button on the one notice in this platform that must not have one.
   */
  signature: string | null;
}

// ---------------------------------------------------------------------------
// Admin writes
// ---------------------------------------------------------------------------

export const maliciousAckNoteSchema = z
  .string()
  .trim()
  .min(1, "a note is required")
  .max(2000)
  .regex(/^[^\p{C}\n\r]*[^\p{C}]*$/u, "must not contain control characters");

/**
 * Record a decision about a finding.
 *
 * `applicationId` omitted means the whole estate, which is right for a false-positive report
 * and wrong for remediation -- credentials are rotated per pipeline, so a `remediated` state
 * almost always names one application.
 */
export const acknowledgeMaliciousRequestSchema = z.object({
  maliciousPackageId: z.string().trim().min(1).max(128),
  applicationId: uuidSchema.optional(),
  state: maliciousAckStateSchema,
  /** Mandatory. An acknowledgement with no reason cannot be told apart from clearing a banner. */
  note: maliciousAckNoteSchema,
});
export type AcknowledgeMaliciousRequest = z.infer<typeof acknowledgeMaliciousRequestSchema>;

export interface MaliciousSettings {
  enabled: boolean;
  intervalHours: number;
  /** Where the feed is fetched from. Overridable so an air-gapped site can host a mirror. */
  feedUrl: string;
  /** Email alerting for newly discovered findings. */
  alertsEnabled: boolean;
  alertRecipients: string[];
}

export const MALICIOUS_DEFAULT_FEED_URL =
  "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz";

/** Bounds mirror the vulnerability database's: hourly at most, monthly at least. */
export const updateMaliciousSettingsSchema = z
  .object({
    enabled: z.boolean().optional(),
    intervalHours: z.coerce.number().int().min(1).max(24 * 30).optional(),
    feedUrl: z.string().trim().url().max(2048).optional(),
    alertsEnabled: z.boolean().optional(),
    alertRecipients: z.array(z.string().trim().email().max(320)).max(50).optional(),
  })
  .refine((v) => Object.values(v).some((x) => x !== undefined), {
    message: "provide at least one field",
  });
export type UpdateMaliciousSettings = z.infer<typeof updateMaliciousSettingsSchema>;

export const listMaliciousHistoryQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
});
export type ListMaliciousHistoryQuery = z.infer<typeof listMaliciousHistoryQuerySchema>;

/**
 * Human wording for an acknowledgement state.
 *
 * Shared so the page, the detail view and any future report all say the same thing. Two
 * screens describing `not_affected` differently is how a reader concludes the platform is
 * guessing.
 */
export const MALICIOUS_ACK_LABELS: Record<MaliciousAckState, string> = {
  investigating: "Investigating",
  remediated: "Remediated",
  not_affected: "Not affected",
  false_positive: "False positive",
};
