import { z } from "zod";
import { uuidSchema } from "./common.js";

/**
 * Which applications an account may see, inside the environments it was granted.
 *
 * The platform now restricts along two axes, and they are not the same kind of thing.
 *
 *   environment   a hard partition. Every application is in exactly one, always. Access is
 *                 an enumeration, and an account with no environments sees nothing.
 *   this          a narrowing. An application belongs to no groups, one, or several, so this
 *                 cannot partition anything — it filters within estates already granted.
 *
 * They compose by intersection: an application is visible when its estate is granted AND it
 * passes this filter. Reversing that — letting a group grant reach into an estate the account
 * was never given — would make the environment boundary decorative, and the environment
 * boundary is the one this platform's numbers depend on.
 *
 * ## Unrestricted is not "granted everything"
 *
 * `unrestricted: true` means the account sees every application in its environments,
 * including ones created tomorrow. An account enumerated today does not. Collapsing the two
 * would silently narrow every existing user the first time somebody ingested a new service —
 * which is the same distinction `EnvironmentAccess.all` draws, for the same reason.
 *
 * Restricted with nothing granted is a real state and means exactly nothing is visible. It is
 * reachable deliberately (an account created before anyone decided what it should reach) and
 * must never be confused with unrestricted, which is why the flag is stored rather than
 * inferred from whether any grant rows exist.
 */
export type ApplicationAccess =
  | { unrestricted: true; groupIds: []; applicationIds: [] }
  | { unrestricted: false; groupIds: string[]; applicationIds: string[] };

/** For the paths that are not restricting anybody: an admin, a background job, a seed. */
export const UNRESTRICTED_APPLICATIONS: ApplicationAccess = {
  unrestricted: true,
  groupIds: [],
  applicationIds: [],
};

/**
 * Caps, and what they are actually for.
 *
 * Not about query cost — a hundred uuids in an `= ANY` is nothing. They exist because a
 * grant list that has grown past this stopped being a decision anybody made and became a
 * paste, and a per-application list that long is a sign the groups are wrong.
 */
export const USER_GROUP_GRANT_LIMIT = 200;
export const USER_APPLICATION_GRANT_LIMIT = 500;

export const setUserApplicationAccessSchema = z
  .object({
    /**
     * False clears the restriction; the grant lists are then irrelevant and are stored
     * anyway. Keeping them means switching an account back to restricted restores what it
     * had, rather than silently granting nothing and reading as a broken save.
     */
    restricted: z.boolean(),
    /** The complete set, not a delta — the screen edits a checklist, so it knows the whole. */
    groupIds: z.array(uuidSchema).max(USER_GROUP_GRANT_LIMIT).default([]),
    applicationIds: z.array(uuidSchema).max(USER_APPLICATION_GRANT_LIMIT).default([]),
  })
  .transform((value) => ({
    ...value,
    // The same id twice is one grant. Sent by a UI that let a group be ticked in two places.
    groupIds: [...new Set(value.groupIds)],
    applicationIds: [...new Set(value.applicationIds)],
  }));
export type SetUserApplicationAccess = z.infer<typeof setUserApplicationAccessSchema>;

/** What the admin screen reads back for one account. */
export interface UserApplicationAccess {
  restricted: boolean;
  groupIds: string[];
  applicationIds: string[];
  /**
   * How many applications the account can actually reach right now.
   *
   * Computed rather than derived from the two list lengths, because groups overlap and an
   * application granted directly may also sit in a granted group. An admin setting this up
   * needs the answer to "and how much is that", and two counts they have to reconcile
   * themselves is how somebody concludes a save did not work.
   *
   * Null when the account is unrestricted — the answer is "everything in its environments",
   * and rendering a number there would invite comparing it against a restricted account's.
   */
  visibleApplicationCount: number | null;
}
