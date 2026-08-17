import { z } from "zod";
import { applicationStatusSchema, attributeTypeSchema } from "../enums.js";
import { paginationQuerySchema, uuidSchema } from "./common.js";
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
  /** Only applications whose latest scan is older than the stale threshold. */
  staleOnly: z.coerce.boolean().optional(),
  sortBy: z.enum(["name", "createdAt", "lastScanAt", "status"]).default("name"),
  sortDir: z.enum(["asc", "desc"]).default("asc"),
});
export type ListApplicationsQuery = z.infer<typeof listApplicationsQuerySchema>;

export interface ApplicationSummary {
  id: string;
  name: string;
  status: "active" | "inactive" | "pending_confirmation";
  attributes: Attributes;
  latestScanId: string | null;
  lastScanAt: string | null;
  /** Component count of the latest scan; null when the app has never been scanned. */
  latestComponentCount: number | null;
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
