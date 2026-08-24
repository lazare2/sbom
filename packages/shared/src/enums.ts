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

/**
 * How a malicious-package report identifies the versions it covers.
 *
 * Derived from the shape of the upstream OSV record rather than invented here, because the
 * three cases need genuinely different matching and collapsing them loses accuracy in the
 * direction that matters. Measured against the OpenSSF feed (236,015 reports):
 *
 *   all_versions   211,804  the package exists only to carry the payload -- a typosquat, a
 *                           dependency-confusion stub. The NAME is the signal; every version
 *                           published under it is malicious.
 *   exact_versions  32,191  a legitimate package whose maintainer account was compromised, or
 *                           which shipped a bad release. Only the listed versions are affected
 *                           and the rest of its history is fine, so this must match exactly --
 *                           widening it would condemn a package most of the estate depends on.
 *   version_range    1,742  an open-ended or bounded range that needs version comparison.
 *
 * The last is under one percent, which is why the matcher can be exact for 99.3% of reports
 * and only needs comparison for the remainder.
 */
export const maliciousMatchModes = ["all_versions", "exact_versions", "version_range"] as const;
export const maliciousMatchModeSchema = z.enum(maliciousMatchModes);
export type MaliciousMatchMode = z.infer<typeof maliciousMatchModeSchema>;

/**
 * What an administrator decided about a malicious-package finding.
 *
 * A finding is never hidden by any of these -- the state is a label on a row that stays
 * visible. "Accept the risk" is deliberately absent: it is a reasonable thing to say about a
 * medium-severity CVE in a library nobody calls, and not a thing anyone should be able to say
 * about a package whose purpose is to exfiltrate credentials.
 */
export const maliciousAckStates = [
  /** Someone owns it and is working on it. */
  "investigating",
  /** Removed, and any credentials exposed at install time have been rotated. */
  "remediated",
  /** Present in the SBOM but never installed anywhere that mattered. Needs the note to say why. */
  "not_affected",
  /** The upstream report is wrong about this package. */
  "false_positive",
] as const;
export const maliciousAckStateSchema = z.enum(maliciousAckStates);
export type MaliciousAckState = z.infer<typeof maliciousAckStateSchema>;

/** What asked for a feed refresh. Mirrors the vulnerability database's triggers. */
export const maliciousFeedTriggers = ["scheduled", "manual", "enable", "import"] as const;
export const maliciousFeedTriggerSchema = z.enum(maliciousFeedTriggers);
export type MaliciousFeedTrigger = z.infer<typeof maliciousFeedTriggerSchema>;

export const maliciousFeedOutcomes = ["updated", "unchanged", "unreachable", "failed"] as const;
export const maliciousFeedOutcomeSchema = z.enum(maliciousFeedOutcomes);
export type MaliciousFeedOutcome = z.infer<typeof maliciousFeedOutcomeSchema>;
