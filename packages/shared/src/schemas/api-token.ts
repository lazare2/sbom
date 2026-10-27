import { z } from "zod";

/**
 * Personal API tokens: the same API the web app uses, authenticated without a browser.
 *
 * There is no second API. Every screen in this platform is drawn by calling `/api/v1`, so a
 * token does not open a new surface - it opens the existing one to a script. That framing
 * matters for what follows: nothing here grants reach the UI did not already have, and the only
 * genuinely new risk is the credential itself, which unlike a session cookie is long-lived,
 * copy-pasteable, and ends up in shell history.
 *
 * ## Permissions are the account's, resolved per request
 *
 * A token carries no permissions of its own. It names a user; the role, environment and group
 * machinery then runs exactly as it does for a session. Narrowing somebody's access, or
 * deactivating them, therefore takes effect on their tokens immediately - which is true by
 * construction only because the answer is never copied into the token.
 */

/**
 * How much of the account's reach this particular string may use.
 *
 * Not a permission system. A `write` token can do no more than its owner can; a `read` token
 * can do less. The split exists because the common reason to want a token - pulling the
 * inventory into a spreadsheet - needs no write access at all, while an administrator's write
 * token is total control of the platform if it leaks. Defaulting to `read` makes the dangerous
 * capability a deliberate choice per token.
 */
export const apiTokenScopes = ["read", "write"] as const;
export const apiTokenScopeSchema = z.enum(apiTokenScopes);
export type ApiTokenScope = (typeof apiTokenScopes)[number];

/**
 * How long a token may live, in days.
 *
 * Capped rather than unbounded, and a cap rather than a fixed value: a token nobody ever
 * rotates is a credential that outlives the laptop it was written on, the job the person held,
 * and usually the project it was minted for. A year is long enough not to be an obstacle and
 * short enough that an abandoned token eventually stops working on its own.
 */
export const API_TOKEN_MAX_DAYS = 365;

export const createApiTokenSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "name is required")
    .max(100)
    .regex(/^[^\p{C}]+$/u, "must not contain control characters"),
  scope: apiTokenScopeSchema.default("read"),
  /**
   * Days until it expires, or null for never.
   *
   * Null is permitted rather than forbidden, because a build agent that nobody can reach at
   * three in the morning to rotate a credential is a real situation - but it is never the
   * default, and the screen says plainly what it means.
   */
  expiresInDays: z.number().int().min(1).max(API_TOKEN_MAX_DAYS).nullable().default(90),
});
export type CreateApiToken = z.infer<typeof createApiTokenSchema>;

/** A token as it is listed back. Never the token itself. */
export interface ApiTokenSummary {
  id: string;
  name: string;
  scope: ApiTokenScope;
  /** Last four characters of the plaintext, the only part ever shown again. */
  tokenSuffix: string;
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  /**
   * Whether it would authenticate a request right now.
   *
   * Computed rather than stored, because it is the conjunction of three independent facts -
   * not revoked, not expired, and the owning account still active - and a stored flag would
   * be a fourth that can disagree with all of them.
   */
  active: boolean;
  /** Why not, when `active` is false. Null while it works. */
  inactiveReason: "revoked" | "expired" | "account_inactive" | null;
}

/**
 * Returned once, at creation.
 *
 * The plaintext is never stored and cannot be recovered; losing it means minting another. Kept
 * a distinct type from `ApiTokenSummary` so that no endpoint can return the secret by
 * accident - a function typed to return a summary cannot carry one.
 */
export interface ApiTokenCreated {
  token: ApiTokenSummary;
  /** The bearer string, shown once. */
  secret: string;
}

/** An administrator's view: every token on the platform, with its owner. */
export interface ApiTokenWithOwner extends ApiTokenSummary {
  userId: string;
  userEmail: string;
  userRole: "admin" | "user";
}

/**
 * What the API access screen tells a developer.
 *
 * `baseUrl` is derived from the deployment's `PUBLIC_URL` rather than from the browser, because
 * it is the address a script on another machine has to use - which is not necessarily the one
 * the person reading the page arrived on, and quietly handing them `localhost` is how an
 * afternoon disappears.
 */
export interface ApiAccessInfo {
  baseUrl: string;
  /** The OpenAPI document's address, relative to the origin. */
  specPath: string;
  /** Interactive reference, relative to the origin. */
  docsPath: string;
  /** How many live tokens the caller currently holds. */
  activeTokenCount: number;
  maxExpiryDays: number;
}

/** The header every authenticated request carries. Named once, used in docs and examples. */
export const API_TOKEN_HEADER = "Authorization";
export const API_TOKEN_PREFIX = "Bearer ";

/**
 * The fixed prefix every personal token starts with.
 *
 * Makes a leaked credential identifiable on sight - in a log, a paste, or a secret scanner -
 * and lets the server reject an obviously-wrong string before it costs a database round trip.
 * `sbp` for "SBOM platform"; the `_` keeps it from running into the random part.
 */
export const API_TOKEN_SECRET_PREFIX = "sbp_";

/**
 * `?permanent=true` on a token DELETE removes the row instead of revoking it.
 *
 * A query flag on the existing route rather than a new one, so every script already calling
 * DELETE to revoke keeps doing exactly that. Revoking stays the default because it keeps the
 * row as a record; deleting is the deliberate choice, made to free a name for reuse.
 */
export const tokenDeleteQuerySchema = z.object({
  permanent: z.enum(["true", "false"]).transform((v) => v === "true").default("false"),
});
