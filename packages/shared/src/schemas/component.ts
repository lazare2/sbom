import { z } from "zod";
import { paginationQuerySchema, type Paginated } from "./common.js";
import { defineSortTable } from "./sort.js";

/**
 * How a package name is compared.
 *
 * `exact` is a case-insensitive equality against `component_name_lower_idx`; `contains`
 * is a substring match served by the pg_trgm GIN index. They are genuinely different
 * queries, not one with a stricter filter, which is why this is a mode rather than a
 * post-filter - and why the UI states which one is in effect.
 */
export const nameMatchModes = ["exact", "contains"] as const;
export const nameMatchSchema = z.enum(nameMatchModes);
export type NameMatchMode = (typeof nameMatchModes)[number];

/** Sortable columns of the package search results table. */
export const componentSearchSort = defineSortTable(
  {
    applicationName: "text",
    applicationStatus: "text",
    componentName: "text",
    componentVersion: "text",
    ecosystem: "text",
    usage: "text",
    lastSeenAt: "date",
  } as const,
  "applicationName",
);

/**
 * Global cross-application package search.
 *
 * `scope=current` searches only each application's latest scan (the common
 * case: "who ships this today"). `scope=historical` searches all retained scan
 * history. `scope=all` returns both, tagging each row.
 */
export const componentSearchQuerySchema = paginationQuerySchema
  .extend({
    /** Package name; partial matches are supported via a trigram index. */
    name: z.string().trim().min(1, "name is required").max(255),
    version: z.string().trim().max(255).optional(),
    ecosystem: z.string().trim().max(64).optional(),
    scope: z.enum(["current", "historical", "all"]).default("current"),
    /** @see nameMatchSchema */
    match: nameMatchSchema.default("contains"),
    /** Include applications whose status is inactive. */
    includeInactive: z.coerce.boolean().default(false),
    /**
     * Which estates to search, by name or id. Omitted means every one the caller can reach,
     * which is what the page opens on.
     *
     * Naming an environment the caller cannot reach is refused rather than quietly dropped:
     * returning fewer estates than were asked for produces an answer that looks complete
     * and is not.
     */
    environments: z
      .union([z.string(), z.array(z.string())])
      .optional()
      .transform((v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v])),
  })
  .merge(componentSearchSort.querySchema);
export type ComponentSearchQuery = z.infer<typeof componentSearchQuerySchema>;

export interface ComponentSearchHit {
  /*
    Package search is the one view that deliberately spans estates.

    "Where does log4j appear" is a question about the whole deployment, and answering it one
    environment at a time invites someone to check production, find nothing, and stop. It
    stays inside the never-mix rule because it is a lookup rather than an aggregate: every
    row names the estate it came from, and no figure is summed across them.
  */
  environmentId: string;
  environmentName: string;
  applicationId: string;
  applicationName: string;
  applicationStatus: "active" | "inactive" | "pending_confirmation";
  componentId: string;
  componentName: string;
  componentVersion: string | null;
  ecosystem: string;
  purl: string | null;
  /**
   * `current` = present in the application's latest scan.
   * `historical` = present in some earlier scan but not the latest.
   */
  usage: "current" | "historical";
  lastSeenScanId: string;
  lastSeenAt: string;
  lastSeenBuildNumber: string | null;
}

// ---------------------------------------------------------------------------
// Package-first search
// ---------------------------------------------------------------------------

/**
 * Sortable columns of the package table.
 *
 * Most-used first by default: a package search is a question about where something is
 * deployed, and the package in the most applications is the one the reader came for.
 */
export const packageSearchSort = defineSortTable(
  {
    name: "text",
    ecosystem: "text",
    environment: "text",
    currentApplications: "number",
    historicalApplications: "number",
    versionsInUse: "number",
    advisories: "number",
    critical: "number",
    vulnerableApplications: "number",
  } as const,
  "currentApplications",
);

/**
 * One row per package, rather than one per package and application.
 *
 * The same filters as the per-application search, so a link can move between the two
 * without changing what it asks. `scope` decides which packages are listed - currently used
 * by some application, dropped by some application, or either - and every row reports both
 * counts regardless, so a reader never has to switch scope to see the other half.
 */
export const packageSearchQuerySchema = paginationQuerySchema
  .extend({
    name: z.string().trim().min(1, "name is required").max(255),
    version: z.string().trim().max(255).optional(),
    ecosystem: z.string().trim().max(64).optional(),
    scope: z.enum(["current", "historical", "all"]).default("current"),
    match: nameMatchSchema.default("contains"),
    includeInactive: z.coerce.boolean().default(false),
    /** @see componentSearchQuerySchema.environments */
    environments: z
      .union([z.string(), z.array(z.string())])
      .optional()
      .transform((v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v])),
  })
  .merge(packageSearchSort.querySchema);
export type PackageSearchQuery = z.infer<typeof packageSearchQuerySchema>;

/**
 * What the vulnerability database says about the versions of a package in current use.
 *
 * Counted over current builds only: a version an application dropped is not exposure. Every
 * count excludes accepted risks, exactly as everywhere else on the platform.
 */
export interface PackageVulnSummary {
  /**
   * False when none of the versions in current use has been matched yet. The counts are then
   * zero because nobody looked, and the page says "not assessed" rather than printing them.
   */
  assessed: boolean;
  /** Versions in current use still waiting for the scanner, when some are and some are not. */
  unassessedVersions: number;
  /** Distinct advisories affecting the versions in current use. */
  advisories: number;
  critical: number;
  high: number;
  knownExploited: number;
  /** Applications currently shipping a version with at least one advisory. */
  vulnerableApplications: number;
}

export interface PackageSearchRow {
  /**
   * One row per estate. Package search spans environments, but a package-level total summed
   * across them would mix estates in one figure, so the same package in two environments is
   * two rows, each naming its estate.
   */
  environmentId: string;
  environmentName: string;
  name: string;
  ecosystem: string;
  /** `library`, or `os` / `runtime` for the base distribution and interpreters. */
  kind: "library" | "os" | "runtime";
  /** Applications whose current build ships some version of this package. */
  currentApplications: number;
  /** Applications that shipped it in an earlier build and ship no version of it now. */
  historicalApplications: number;
  /** Distinct versions in current builds. */
  versionsInUse: number;
  /** Distinct versions ever shipped by applications the reader can see. */
  versionsEver: number;
  /** Up to six of the versions in current use, for reading the spread at a glance. */
  versionSample: string[];
  /** Null when vulnerability scanning is switched off. */
  vulnerabilities: PackageVulnSummary | null;
}

export interface PackageSearchResult extends Paginated<PackageSearchRow> {
  /** True when the query matched more distinct package versions than can be considered. */
  truncated: boolean;
  /** Whether vulnerability scanning is on, so the page can explain an absent column. */
  vulnScanningEnabled: boolean;
}

/** One package in one estate, broken down by version and by application. */
export const packageDetailQuerySchema = z.object({
  name: z.string().trim().min(1).max(255),
  ecosystem: z.string().trim().min(1).max(64),
  /** The estate, by id or name. Required: a package-level breakdown describes one estate. */
  environment: z.string().trim().min(1).max(200),
  includeInactive: z.coerce.boolean().default(false),
});
export type PackageDetailQuery = z.infer<typeof packageDetailQuerySchema>;

export interface PackageAdvisoryCounts {
  advisories: number;
  critical: number;
  high: number;
  knownExploited: number;
}

export interface PackageVersionEntry {
  version: string | null;
  currentApplications: number;
  historicalApplications: number;
  /**
   * Over the applications currently shipping this version, accepted risks excluded. Null
   * when no application currently ships it, or it has not been matched yet - see `assessed`.
   */
  vulnerabilities: PackageAdvisoryCounts | null;
  assessed: boolean;
}

export interface PackageApplicationEntry {
  applicationId: string;
  applicationName: string;
  applicationStatus: "active" | "inactive" | "pending_confirmation";
  /** `current` when the latest build ships it, otherwise the last version it shipped. */
  usage: "current" | "historical";
  /** The versions shipped: every one in the current build, or the last one for a dropped package. */
  versions: Array<string | null>;
  lastSeenScanId: string;
  lastSeenAt: string;
  lastSeenBuildNumber: string | null;
  /** Null for a dropped package, for an unassessed version, or with scanning switched off. */
  vulnerabilities: PackageAdvisoryCounts | null;
}

export interface PackageDetail {
  name: string;
  ecosystem: string;
  environmentId: string;
  environmentName: string;
  vulnScanningEnabled: boolean;
  versions: PackageVersionEntry[];
  applications: PackageApplicationEntry[];
}

/** Typeahead for the search box. Distinct package names only, no app join. */
export const componentSuggestQuerySchema = z.object({
  q: z.string().trim().min(2).max(255),
  limit: z.coerce.number().int().min(1).max(50).default(10),
});
export type ComponentSuggestQuery = z.infer<typeof componentSuggestQuerySchema>;

export interface ComponentSuggestion {
  name: string;
  ecosystem: string;
  versionCount: number;
}
