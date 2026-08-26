import { z } from "zod";
import { uuidSchema } from "./common.js";

/**
 * Environments: isolated estates within one deployment.
 *
 * The same service commonly exists in more than one — a `test` copy carrying changes that
 * have not shipped, and a `production` copy that is what customers actually run. They are
 * **two applications**, not one application in two states, because their component lists
 * genuinely differ and neither is a version of the other at any given moment.
 *
 * ## The one rule everything else follows from
 *
 * No number is ever computed across environments. Not a component count, not package usage,
 * not a vulnerability total. A figure that blends a test estate into a production one
 * describes neither, and nobody reading it can tell.
 *
 * ## The one deliberate exception
 *
 * Package search spans every environment the viewer can reach, because "where does log4j
 * appear" is a question about the whole deployment and answering it one estate at a time
 * invites someone to check production and stop. It stays within the rule because it is a
 * lookup rather than an aggregate: every row names its environment, and nothing is summed.
 * See `bulk-search.js` and the environment filter on the search request.
 *
 * ## What is not scoped
 *
 * Users, the vulnerability database, the malicious-package feed, and the attribute
 * definitions. Those describe either the people using the platform or the world outside it,
 * and neither is a property of one estate. Everything the platform *observed* is scoped.
 *
 * ## Names are an ingest identifier
 *
 * A pipeline names its environment in the upload, so this string lives in CI configuration.
 * Renaming one is therefore a change to a published interface, not a cosmetic edit — which
 * is why the admin screen warns rather than treating it as a relabel.
 */

export const environmentNameSchema = z
  .string()
  .trim()
  .min(1, "name is required")
  .max(60)
  /*
   * Stricter than an application or group name, because this one travels through CI
   * configuration and shell arguments. Letters, digits, hyphen, underscore, dot and space:
   * enough for "Production", "pre-prod" or "QA 2", and nothing that needs quoting or that
   * renders as nothing.
   */
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/u,
    "may contain letters, digits, spaces, dots, hyphens and underscores, and must start with a letter or digit",
  );

export const environmentDescriptionSchema = z.string().trim().max(1000);

export interface Environment {
  id: string;
  name: string;
  description: string | null;
  /** How much is in this estate. Both are what makes deleting one a considered act. */
  applicationCount: number;
  scanCount: number;
  createdAt: string;
  updatedAt: string;
}

export const createEnvironmentRequestSchema = z.object({
  name: environmentNameSchema,
  description: environmentDescriptionSchema.optional(),
});
export type CreateEnvironmentRequest = z.infer<typeof createEnvironmentRequestSchema>;

export const updateEnvironmentRequestSchema = z
  .object({
    name: environmentNameSchema.optional(),
    /** Empty string clears it; omitted leaves it unchanged. The two are different. */
    description: environmentDescriptionSchema.nullable().optional(),
  })
  .refine((v) => v.name !== undefined || v.description !== undefined, {
    message: "provide `name`, `description`, or both",
  });
export type UpdateEnvironmentRequest = z.infer<typeof updateEnvironmentRequestSchema>;

/**
 * Deleting an environment destroys every application, build, raw SBOM, group, suppression
 * and report inside it. There is no undo and no soft-delete tombstone to recover from.
 *
 * So the caller has to type the name back. Not a checkbox: a checkbox is one click away from
 * an accident, and this action can erase years of build history. Typing the name also proves
 * the caller knows *which* environment they are on, which a confirmation dialog opened from
 * the wrong row does not.
 */
export const deleteEnvironmentRequestSchema = z.object({
  confirmName: z.string(),
});
export type DeleteEnvironmentRequest = z.infer<typeof deleteEnvironmentRequestSchema>;

/**
 * Which environments a user may read.
 *
 * `all: true` is an administrator, and is not the same as listing every environment id that
 * currently exists: an admin gains access to an environment created tomorrow, whereas a user
 * enumerated today does not. Collapsing the two would silently narrow admins the first time
 * somebody adds an estate.
 */
export interface EnvironmentAccess {
  all: boolean;
  environmentIds: string[];
}

export const setUserEnvironmentsRequestSchema = z.object({
  /**
   * The complete set, not a delta — the admin screen edits a checklist, so the whole set is
   * what it knows, and two admins editing at once would otherwise each apply their delta to
   * a set the other had already changed.
   *
   * An empty array is legal and means the user sees nothing. That is a real state: an
   * account can exist before anyone has decided what it should reach.
   */
  environmentIds: z.array(uuidSchema).max(100),
});
export type SetUserEnvironmentsRequest = z.infer<typeof setUserEnvironmentsRequestSchema>;

/**
 * How a request says which estate it means.
 *
 * Accepts an id or a name so a link can be readable (`?environment=Production`) while the UI
 * sends ids. Names are unique case-insensitively, so neither form is ambiguous.
 */
export const environmentRefSchema = z.string().trim().min(1).max(60);

/** Query parameter carried by every estate-scoped list page, and by the ingest upload. */
export const environmentQuerySchema = z.object({
  environment: environmentRefSchema.optional(),
});
