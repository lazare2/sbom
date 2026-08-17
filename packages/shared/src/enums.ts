import { z } from "zod";

/**
 * Application lifecycle status.
 *
 * `pending_confirmation` is set when a scan arrives for an `app_name` that
 * matches no existing application or alias. Those apps are visible to every
 * authenticated user (flagged in the UI) until an admin resolves them.
 */
export const applicationStatuses = ["active", "inactive", "pending_confirmation"] as const;
export const applicationStatusSchema = z.enum(applicationStatuses);
export type ApplicationStatus = z.infer<typeof applicationStatusSchema>;

export const userRoles = ["admin", "user"] as const;
export const userRoleSchema = z.enum(userRoles);
export type UserRole = z.infer<typeof userRoleSchema>;

/**
 * How a scan's SBOM reached the platform.
 *
 * `ci` is a pipeline posting to `POST /api/v1/scans` with an ingest token; `manual`
 * is a signed-in user uploading a file from the application's scan history.
 *
 * Every read path — search, diffs, analytics, the estate totals — treats the two
 * identically, and that is the point: a manually uploaded SBOM *is* the
 * application's current build. This column exists for provenance only, because a
 * hand-uploaded build that cannot be told apart from a pipeline-produced one is a
 * gap in the audit trail, not a simplification.
 *
 * Kept as a distinct column rather than being inferred from
 * `uploaded_by_user_id IS NOT NULL`: deleting a user nulls that reference, and the
 * scan must still be able to say it was uploaded by hand.
 */
export const scanSources = ["ci", "manual"] as const;
export const scanSourceSchema = z.enum(scanSources);
export type ScanSource = z.infer<typeof scanSourceSchema>;

/**
 * Which auth backend owns a given user's credentials. Only `local` is
 * implemented in this phase; the column exists so an LDAP-backed user can be
 * added later without a migration or a rewrite of the login path.
 */
export const authProviderNames = ["local", "ldap"] as const;
export const authProviderNameSchema = z.enum(authProviderNames);
export type AuthProviderName = z.infer<typeof authProviderNameSchema>;

/** Attribute value types supported by the admin-managed attribute definitions. */
export const attributeTypes = ["string", "text", "select", "number", "boolean"] as const;
export const attributeTypeSchema = z.enum(attributeTypes);
export type AttributeType = z.infer<typeof attributeTypeSchema>;

/**
 * How an admin resolved a `pending_confirmation` application. Recorded on the
 * audit trail so "why did this app disappear" is answerable later.
 */
export const pendingResolutions = ["confirm", "merge_once", "merge_always", "delete"] as const;
export const pendingResolutionSchema = z.enum(pendingResolutions);
export type PendingResolution = z.infer<typeof pendingResolutionSchema>;

/**
 * Package ecosystems Syft emits in CycloneDX `purl` / `type` fields. This is
 * an open list on purpose: the DB column is free text so an unrecognised
 * ecosystem is stored verbatim rather than dropped. These constants exist for
 * UI grouping and filter dropdowns only.
 */
export const knownEcosystems = [
  "npm",
  "pypi",
  "gem",
  "maven",
  "golang",
  "cargo",
  "nuget",
  "composer",
  "deb",
  "rpm",
  "apk",
  "alpm",
  "conan",
  "cocoapods",
  "hex",
  "pub",
  "swift",
  "generic",
  "unknown",
] as const;
export type KnownEcosystem = (typeof knownEcosystems)[number];
