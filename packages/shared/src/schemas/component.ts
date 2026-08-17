import { z } from "zod";
import { paginationQuerySchema } from "./common.js";

/**
 * Global cross-application package search.
 *
 * `scope=current` searches only each application's latest scan (the common
 * case: "who ships this today"). `scope=historical` searches all retained scan
 * history. `scope=all` returns both, tagging each row.
 */
export const componentSearchQuerySchema = paginationQuerySchema.extend({
  /** Package name; partial matches are supported via a trigram index. */
  name: z.string().trim().min(1, "name is required").max(255),
  version: z.string().trim().max(255).optional(),
  ecosystem: z.string().trim().max(64).optional(),
  scope: z.enum(["current", "historical", "all"]).default("current"),
  /** `exact` compares the full name case-insensitively; `contains` is a substring match. */
  match: z.enum(["exact", "contains"]).default("contains"),
  /** Include applications whose status is inactive. */
  includeInactive: z.coerce.boolean().default(false),
});
export type ComponentSearchQuery = z.infer<typeof componentSearchQuerySchema>;

export interface ComponentSearchHit {
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
