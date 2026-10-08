import { z } from "zod";
import { uuidSchema } from "./common.js";

/**
 * People the directory authenticated who have no account here.
 *
 * Accounts are created by an administrator before anyone can use them, which is the whole
 * security posture of this platform — but it leaves a gap it took a real deployment to notice.
 * A colleague clicks "sign in with your organisation account", authenticates perfectly against
 * the directory, and is refused. Nothing records that it happened. They are told to ask an
 * administrator, and whether they do is up to them.
 *
 * This is the queue that closes that gap, modelled on applications awaiting confirmation: a
 * refusal becomes a row, the row raises a count on the admin nav, and an administrator drains
 * it by creating the account.
 *
 * ## Why only single sign-on feeds this
 *
 * By the time a directory sign-in is refused, this platform holds an id token signed by the
 * provider with its issuer, audience and nonce all verified. The address and name below are
 * facts the organisation's directory asserted about one of its own members.
 *
 * A failed password login establishes none of that. The address would be a string typed into a
 * box by somebody who proved nothing, which would make this table an unauthenticated write
 * endpoint: anyone able to reach the sign-in page could insert rows of their choosing, and
 * deduplication cannot bound that because the string is theirs to vary. It would also fill with
 * noise, since most failed passwords are people who already have accounts. So the local path
 * records nothing, and somebody who needs a local account still has to ask for one out of band.
 *
 * ## Why only one refusal of the three feeds it
 *
 * `inactive` means the account exists and an administrator switched it off. `identity_conflict`
 * means an identity needs unlinking, not an account created. Listing either under a button
 * marked "create account" would invite exactly the wrong action, so both stay in the error log
 * where they already are. Only `no_account` arrives here.
 */

/** Why a request was recorded. One value today; see the note above about the two excluded. */
export const accessRequestReasons = ["no_account"] as const;
export type AccessRequestReason = (typeof accessRequestReasons)[number];

/**
 * Where a request stands.
 *
 * `resolved` is reached two ways: an administrator created the account from the queue, or the
 * person simply signed in successfully later. The second matters more than it looks — it means
 * the queue drains itself however the account came to exist, rather than depending on an
 * administrator remembering to press the right button afterwards.
 *
 * `dismissed` is kept distinct from deleted so that a later attempt by the same person creates
 * a fresh row rather than silently reviving a decision somebody already made.
 */
export const accessRequestStatuses = ["pending", "resolved", "dismissed"] as const;
export const accessRequestStatusSchema = z.enum(accessRequestStatuses);
export type AccessRequestStatus = (typeof accessRequestStatuses)[number];

export interface AccessRequest {
  id: string;
  /** Which kind of directory authenticated them. `oidc` today. */
  provider: string;
  /**
   * The address the directory gave for them, lowercased.
   *
   * Nullable because a token need not carry one: `email` arrives only where that claim was
   * consented to, and the fallback to `preferred_username` can also be absent. A request
   * without an address is still worth showing — the name usually identifies the person — so
   * this is null rather than the row being dropped.
   */
  email: string | null;
  /** Their display name, as the directory gave it. Null where the token carried none. */
  displayName: string | null;
  reason: AccessRequestReason;
  status: AccessRequestStatus;
  /**
   * How many times they have tried.
   *
   * The count, not a row per attempt. Somebody refused at nine in the morning tries again at
   * noon and again the next day, and three rows for one person would turn a queue into a log
   * nobody drains. It is also the only thing on the screen that conveys urgency.
   */
  attempts: number;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  /** The administrator who resolved or dismissed it. Null while pending, and null when a
   *  successful sign-in resolved it with nobody present. */
  resolvedByEmail: string | null;
}

export interface AccessRequestList {
  requests: AccessRequest[];
  /** Pending rows only — what the badge on the admin nav counts. */
  pendingCount: number;
  /**
   * Whether single sign-on is switched on.
   *
   * On the screen this is the difference between two readings of an empty queue that must
   * never look alike: nobody has been refused, versus nothing is watching. With sign-on off
   * this queue can never fill, and an empty list under those conditions is not reassurance.
   */
  signOnEnabled: boolean;
}

export const listAccessRequestsQuerySchema = z.object({
  /** Defaults to the pending queue, which is what the screen is for. */
  status: accessRequestStatusSchema.optional(),
});
export type ListAccessRequestsQuery = z.infer<typeof listAccessRequestsQuerySchema>;

/**
 * Marking a request dealt with.
 *
 * `userId` is the account that was created for them, recorded so that "who did we let in off
 * the back of this request" is answerable later. Optional because an administrator may have
 * created the account by hand before opening this screen.
 */
export const resolveAccessRequestSchema = z.object({
  userId: uuidSchema.optional(),
});
export type ResolveAccessRequest = z.infer<typeof resolveAccessRequestSchema>;
