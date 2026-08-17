import { z } from "zod";
import { paginationQuerySchema } from "./common.js";
import type { ComponentSearchHit } from "./component.js";

/**
 * Bulk package search: take a pasted list, report which of those packages exist
 * anywhere in the estate.
 *
 * A different question from the single search, and the difference shapes the
 * response. "Who ships log4j" wants a list of applications. "Of these 40 packages
 * from an advisory, which are we exposed to" wants a verdict on all 40 —
 * *including the misses*, because if only three are present the answer is mostly
 * about the other thirty-seven. A result that returned hits alone would leave the
 * reader diffing two lists by hand, which is the work this exists to remove.
 */

/**
 * Ceiling on entries per list.
 *
 * Generous enough for a full advisory or a `requirements.txt`, bounded so one
 * paste cannot issue an unbounded number of index probes. The query itself passes
 * the list as arrays and is indifferent to length; this limit protects the
 * response size and the browser rendering it.
 */
export const BULK_SEARCH_MAX_ENTRIES = 1000;

/** How a version on an input line was interpreted. */
export type BulkEntryVersionKind =
  /** No version given — match every version of the package. */
  | "any"
  /** An exact version to match. */
  | "exact"
  /**
   * The line carried a version specifier that is not a single version — a range
   * (`>=4.2`, `^1.2.3`, `~=2.0`), a wildcard (`==4.2.*`), a negation, or a
   * dist-tag (`@latest`). The specifier is shown but not matched on: the name is
   * matched across all versions instead.
   *
   * Deliberately over-reporting. Matching `4.2` exactly because the line said
   * `>=4.2` would be silently wrong, and dropping the line would hide a real hit.
   * An extra row the reader can see and dismiss is the safe direction for an
   * audit; a missing one is not.
   */
  | "version-ignored";

/** One parsed input line. */
export interface BulkEntry {
  /** 1-based line number in the submitted text, for pointing at problems. */
  line: number;
  /** The line as submitted, trimmed. */
  raw: string;
  name: string;
  version: string | null;
  versionKind: BulkEntryVersionKind;
  /** Set only when the line carried one, as a purl or a maven coordinate. */
  ecosystem: string | null;
}

/** A line that could not be read as a package reference. */
export interface BulkParseProblem {
  line: number;
  raw: string;
  reason: string;
}

export interface BulkParseSummary {
  /** Lines with content, ignoring blanks and comments. */
  lines: number;
  /** Entries actually searched, after collapsing duplicates. */
  entries: number;
  duplicatesCollapsed: number;
  /** Entries whose version specifier was not usable; see `version-ignored`. */
  constraintsDropped: number;
  problems: BulkParseProblem[];
  /** True when the list was cut at BULK_SEARCH_MAX_ENTRIES. */
  truncated: boolean;
}

/**
 * One row of the rollup: the verdict on a single input line.
 *
 * `currentApplications` and `historicalApplications` are both always populated,
 * regardless of the requested scope. That is what makes a miss unambiguous:
 * without the historical count, "not found" conflates "never been here" with "we
 * removed it last month", and those are very different answers to a security
 * question.
 */
export interface BulkRollupRow {
  line: number;
  raw: string;
  name: string;
  version: string | null;
  versionKind: BulkEntryVersionKind;
  /**
   * True when the query as asked matched something — including the pinned version,
   * if one was given.
   */
  found: boolean;
  /**
   * True when the package *name* exists in the inventory, whatever its version.
   *
   * Separate from `found` because with a pinned version the two answer different
   * questions, and for an advisory audit the gap between them is the useful part:
   * `express@4.0.0` can be absent while express itself is deployed at 4.19.2 in
   * four applications. Reporting only "not found" would hide that, and reporting
   * only "found" would overstate the exposure.
   */
  nameFound: boolean;
  /** Ecosystems the name was found in — plural when a name exists in several. */
  ecosystems: string[];
  /**
   * Distinct versions of this package present in the estate, capped for display.
   *
   * Every version of the name, not just the ones matching a pinned version — so a
   * miss can say what *is* there instead of only what is not.
   */
  versionsFound: string[];
  /** True when `versionsFound` was cut short. */
  versionsTruncated: boolean;
  /** Applications whose current build contains it. */
  currentApplications: number;
  /** Applications that shipped it once but no longer do. */
  historicalApplications: number;
}

export interface BulkSearchSummary {
  /** Entries present somewhere in the inventory. */
  found: number;
  notFound: number;
  /** Entries in some application's current build — the number that usually matters. */
  inCurrentUse: number;
  /** Distinct applications touched by any entry, within the requested scope. */
  applicationsAffected: number;
}

const bulkOptionsSchema = z.object({
  scope: z.enum(["current", "historical", "all"]).default("current"),
  ecosystem: z.string().trim().max(64).optional(),
  includeInactive: z.coerce.boolean().default(false),
  /**
   * `rollup` is one row per input line. `matches` is the flat package ×
   * application table, which reuses the single search's row shape and is
   * paginated.
   */
  view: z.enum(["rollup", "matches"]).default("rollup"),
});

export const bulkSearchBodySchema = bulkOptionsSchema.merge(paginationQuerySchema).extend({
  /** The pasted text. Parsed server-side so the rules are one testable contract. */
  input: z.string().min(1, "paste at least one package").max(200_000),
});
export type BulkSearchBody = z.infer<typeof bulkSearchBodySchema>;

/** Re-running a saved list: the input comes from the stored row, the options from the URL. */
export const bulkSearchQuerySchema = bulkOptionsSchema.merge(paginationQuerySchema);
export type BulkSearchQuery = z.infer<typeof bulkSearchQuerySchema>;

export interface BulkSearchResult {
  /**
   * Identifier of the saved list, so the results have an address.
   *
   * Every submission gets one — there is no separate "save" action. The list is
   * the question, and the question is what is worth linking to.
   */
  queryId: string;
  scope: "current" | "historical" | "all";
  parse: BulkParseSummary;
  summary: BulkSearchSummary;
  rollup: BulkRollupRow[];
  /** Present only for `view=matches`. */
  matches?: {
    items: ComponentSearchHit[];
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

/** A previously submitted list, for the recent-lists picker. */
export interface SavedPackageList {
  id: string;
  entryCount: number;
  /** First few package names, so the list is recognisable without opening it. */
  preview: string[];
  createdBy: string | null;
  createdAt: string;
  lastAccessedAt: string;
}
