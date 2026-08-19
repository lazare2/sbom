import { z } from "zod";
import { applicationStatusSchema, attributeTypeSchema } from "../enums.js";
import { paginationQuerySchema, uuidSchema } from "./common.js";
import { defineSortTable } from "./sort.js";
import type { GroupRef } from "./group.js";
import type { ScanPlatform } from "./scan.js";

/**
 * Application names mirror GitLab project names / Jenkins job names, so the
 * charset is deliberately permissive but excludes whitespace-only and control
 * characters. Uniqueness is enforced case-insensitively in the DB.
 */
export const applicationNameSchema = z
  .string()
  .trim()
  .min(1, "name is required")
  .max(255)
  .regex(/^[^\p{C}]+$/u, "must not contain control characters");

/**
 * Attribute values are free-form scalars stored in a JSONB column. Validation
 * against the admin-defined `attribute_definition` rows (type, select options)
 * happens server-side, since the definitions are runtime data rather than
 * something we can express in a static schema.
 */
export const attributeValueSchema = z.union([z.string().max(2000), z.number(), z.boolean(), z.null()]);
export type AttributeValue = z.infer<typeof attributeValueSchema>;

export const attributesSchema = z.record(z.string().min(1).max(64), attributeValueSchema);
export type Attributes = z.infer<typeof attributesSchema>;

export const createApplicationRequestSchema = z.object({
  name: applicationNameSchema,
  status: z.enum(["active", "inactive"]).default("active"),
  attributes: attributesSchema.default({}),
});
export type CreateApplicationRequest = z.infer<typeof createApplicationRequestSchema>;

export const updateApplicationRequestSchema = z
  .object({
    name: applicationNameSchema.optional(),
    status: z.enum(["active", "inactive"]).optional(),
    /** Merged into the existing attributes; an explicit `null` clears one key. */
    attributes: attributesSchema.optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "no fields to update" });
export type UpdateApplicationRequest = z.infer<typeof updateApplicationRequestSchema>;

/**
 * Sortable columns of the applications table.
 *
 * `platform` sorts on the OS of the current build — the "who is still on Debian 11"
 * column — and is text, so it reads A→Z. The two counts are numbers and open on the
 * largest, which is the question they are usually asked in.
 */
export const applicationSort = defineSortTable(
  {
    name: "text",
    status: "text",
    platform: "text",
    componentCount: "number",
    /**
     * Combined findings of the current build, application dependencies plus base image.
     *
     * Sorts on the total rather than on either half because the column displays the total.
     * Applications whose current build has not been matched against the database sort last
     * in both directions — see `directionNullsLast` at the query site.
     */
    vulnFindings: "number",
    scanCount: "number",
    lastScanAt: "date",
    createdAt: "date",
    /**
     * Sorts on a custom attribute, named by `sortAttribute`.
     *
     * One field rather than one per attribute because the set is administrator-defined and
     * changes at runtime — squad, owner, criticality today, something else next quarter —
     * so a fixed enum could never cover it.
     *
     * This is the one sort whose target is not known at compile time, and it is safe for a
     * specific reason: a jsonb key is a *value* (`attributes->>$1`), not an identifier, so
     * it binds as an ordinary parameter. Nothing from the client is ever concatenated into
     * the ORDER BY.
     */
    attribute: "text",
  } as const,
  "name",
);

export const listApplicationsQuerySchema = paginationQuerySchema.extend({
  search: z.string().trim().max(255).optional(),
  /**
   * Repeatable `status` filter. Defaults, when omitted, to active +
   * pending_confirmation: regular users should not have to opt in to seeing
   * unconfirmed apps, but inactive ones stay hidden until asked for.
   */
  status: z
    .union([applicationStatusSchema, z.array(applicationStatusSchema)])
    .transform((v) => (Array.isArray(v) ? v : [v]))
    .optional(),
  squad: z.string().trim().max(255).optional(),
  owner: z.string().trim().max(255).optional(),
  severity: z.string().trim().max(255).optional(),
  /**
   * Platform filters, matched against the application's CURRENT build. This is
   * the "which apps are still on Debian 11 / Node 18" query, which is the whole
   * reason the platform is extracted from the SBOM at all.
   */
  os: z.string().trim().max(64).optional(),
  osVersion: z.string().trim().max(64).optional(),
  /** Canonical runtime name, e.g. `node`. Combine with `runtimeVersion` to pin one. */
  runtime: z.string().trim().max(64).optional(),
  runtimeVersion: z.string().trim().max(64).optional(),
  /**
   * Only applications in this group.
   *
   * By id rather than name: a group can be renamed, and a bookmarked filter that silently
   * stops matching is worse than one that 404s.
   */
  group: uuidSchema.optional(),
  /** Only applications whose latest scan is older than the stale threshold. */
  staleOnly: z.coerce.boolean().optional(),
  /** Which attribute `sortBy=attribute` means. Ignored for every other sort field. */
  sortAttribute: z.string().trim().max(64).optional(),
}).merge(applicationSort.querySchema);
export type ListApplicationsQuery = z.infer<typeof listApplicationsQuerySchema>;

/**
 * Vulnerability findings of an application's current build.
 *
 * Both halves are carried alongside the total because the ratio between them is the point.
 * Measured on a realistic container SBOM, 2,817 of 2,845 findings came from base-image OS
 * packages — so an application showing 2,829 with 12 from its own dependencies and one
 * showing 2,829 with 800 from its own dependencies are entirely different problems wearing
 * the same number, and only the split tells them apart.
 *
 * `critical` and `high` span both halves, matching `total`.
 */
export interface ApplicationVulnCounts {
  /** `app + os`. */
  total: number;
  /** Findings in dependencies the application chose. The half a squad can act on. */
  app: number;
  /** Findings in base-image and runtime packages. Fixed by rebuilding, not by a lockfile. */
  os: number;
  critical: number;
  high: number;
}

export interface ApplicationSummary {
  id: string;
  name: string;
  status: "active" | "inactive" | "pending_confirmation";
  attributes: Attributes;
  latestScanId: string | null;
  lastScanAt: string | null;
  /** Component count of the latest scan; null when the app has never been scanned. */
  latestComponentCount: number | null;
  /**
   * Findings of the CURRENT build, or null when the number is not known.
   *
   * Null covers three situations that must never collapse into zero: vulnerability scanning
   * is switched off, the application has never been scanned, or its latest scan has not yet
   * been matched against the database. Zero means matched and clean — a far stronger claim,
   * and the one this field must never make by accident.
   *
   * Callers distinguish "never scanned" from "not assessed" through `latestScanId`, which is
   * null only in the former case.
   */
  vulnerabilities: ApplicationVulnCounts | null;
  /**
   * Every group this application belongs to, name-sorted.
   *
   * An array because membership is many-to-many — this is exactly what the single-valued
   * `attributes` cannot express, and the reason groups exist alongside them.
   */
  groups: GroupRef[];
  scanCount: number;
  isStale: boolean;
  createdAt: string;
  /**
   * OS and runtimes of the CURRENT build. Null when the application has never
   * been scanned; a scan whose SBOM revealed no platform yields a `ScanPlatform`
   * with null fields, which is a different and meaningful state.
   */
  platform: ScanPlatform | null;
}

export interface ApplicationDetail extends ApplicationSummary {
  aliases: string[];
  updatedAt: string;
}

// --- pending-confirmation resolution ---------------------------------------

/** Confirm: fill in attributes and flip the app to `active`. */
export const confirmApplicationRequestSchema = z.object({
  name: applicationNameSchema.optional(),
  attributes: attributesSchema.default({}),
});
export type ConfirmApplicationRequest = z.infer<typeof confirmApplicationRequestSchema>;

/**
 * Merge a pending app into an existing one.
 *
 * `always: false` (merge-once) moves the existing scans and deletes the pending
 * app. A future scan under the same unmatched name creates a new pending app.
 *
 * `always: true` (merge-always) does the same and additionally records an alias
 * so future scans with that `app_name` are redirected automatically.
 */
export const mergeApplicationRequestSchema = z.object({
  targetApplicationId: uuidSchema,
  always: z.boolean(),
});
export type MergeApplicationRequest = z.infer<typeof mergeApplicationRequestSchema>;

export interface MergeApplicationResponse {
  targetApplicationId: string;
  scansMoved: number;
  aliasCreated: string | null;
}

// --- attribute definitions --------------------------------------------------

export const attributeDefinitionSchema = z.object({
  key: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9_]*$/, "must be lower_snake_case"),
  label: z.string().trim().min(1).max(128),
  type: attributeTypeSchema,
  options: z.array(z.string().min(1).max(128)).max(200).nullable().default(null),
  sortOrder: z.number().int().min(0).max(9999).default(0),
  isActive: z.boolean().default(true),
});
export type AttributeDefinitionInput = z.infer<typeof attributeDefinitionSchema>;

export const updateAttributeDefinitionSchema = attributeDefinitionSchema.omit({ key: true }).partial();
export type UpdateAttributeDefinitionInput = z.infer<typeof updateAttributeDefinitionSchema>;

export interface AttributeDefinition extends AttributeDefinitionInput {
  id: string;
  createdAt: string;
}
