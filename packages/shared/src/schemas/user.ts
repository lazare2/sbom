import { z } from "zod";
import { uuidSchema } from "./common.js";
import { authProviderNameSchema, userRoleSchema, type AuthProviderName } from "../enums.js";
import { emailSchema, passwordSchema } from "./auth.js";
import { paginationQuerySchema } from "./common.js";
import { defineSortTable } from "./sort.js";

/**
 * Admin-driven account creation.
 *
 * There is no invite email and no self-service signup: user "emails" are login
 * identifiers, not mailboxes, so nothing can be delivered to them. The admin
 * either types an initial password or lets the server generate one, and hands
 * it over out of band. Either way the account starts with
 * `mustChangePassword`, so the credential the admin saw stops working the
 * moment the user logs in.
 */
/**
 * A person's name, as typed or as the directory gave it.
 *
 * Blank is folded to null rather than stored as an empty string, so "not known" has one
 * representation and a cleared field reads back as absent rather than as a name of nothing.
 */
export const personNameSchema = z
  .string()
  .trim()
  .max(120)
  .regex(/^[^\p{C}]*$/u, "must not contain control characters")
  .transform((v) => (v === "" ? null : v))
  .nullable();

export const createUserRequestSchema = z.object({
  /**
   * Which environments this account may read. Omitted grants every one that exists.
   *
   * Ignored while the account's role is `admin` -- an administrator reads every estate by
   * definition, including ones created after the account was made.
   */
  environmentIds: z.array(uuidSchema).max(100).optional(),
  email: emailSchema,
  firstName: personNameSchema.optional(),
  lastName: personNameSchema.optional(),
  role: userRoleSchema.default("user"),
  /**
   * Which backend owns this account's credentials.
   *
   * `oidc` creates an account with no password at all: the directory holds the credential and
   * this platform never sees one, so generating a password here would produce a second way in
   * that nobody asked for and nobody would ever rotate.
   */
  authProvider: authProviderNameSchema.default("local"),
  /** Omit to have the server generate one and return it once. Ignored for a directory account. */
  password: passwordSchema.optional(),
  /**
   * Escape hatch for creating a long-lived service account whose password is
   * managed elsewhere. Defaults to true, because the normal case is a person
   * receiving a password someone else has seen.
   */
  mustChangePassword: z.boolean().default(true),
});
export type CreateUserRequest = z.infer<typeof createUserRequestSchema>;

export const updateUserRequestSchema = z
  .object({
    role: userRoleSchema.optional(),
    isActive: z.boolean().optional(),
    /** Null clears the name; omitted leaves it alone. */
    firstName: personNameSchema.optional(),
    lastName: personNameSchema.optional(),
  })
  .refine(
    (v) =>
      v.role !== undefined ||
      v.isActive !== undefined ||
      v.firstName !== undefined ||
      v.lastName !== undefined,
    { message: "at least one of role, isActive, firstName or lastName must be provided" },
  );
export type UpdateUserRequest = z.infer<typeof updateUserRequestSchema>;

/**
 * Changing how an existing account signs in.
 *
 * Added because the alternative was an UPDATE statement. An account created with a password
 * before single sign-on was configured could only be converted by editing `auth_provider` in
 * the database by hand -- which is how the person who set the directory up ends up unable to
 * use it, and how "I ticked the box this time" becomes the documented procedure.
 *
 * A separate request from `updateUserRequestSchema` on purpose. Converting away from the
 * directory has to issue a password, so this returns a credential where that returns a
 * summary, and folding them together would mean a route that sometimes hands back a secret
 * depending on which fields were set.
 */
export const setSignInMethodSchema = z.object({
  /**
   * `directory` rather than `oidc`.
   *
   * The wire value names what an administrator is choosing, not which protocol implements it.
   * `auth_provider` keeps the protocol name, so adding LDAP later changes the mapping in one
   * service rather than every caller and every screen.
   */
  method: z.enum(["local", "directory"]),
});
export type SetSignInMethod = z.infer<typeof setSignInMethodSchema>;

/** Admin-initiated password reset. Omit `password` to have one generated. */
export const resetUserPasswordRequestSchema = z.object({
  password: passwordSchema.optional(),
  mustChangePassword: z.boolean().default(true),
});
export type ResetUserPasswordRequest = z.infer<typeof resetUserPasswordRequestSchema>;

/**
 * Sortable columns of the admin users table.
 *
 * `isActive` is text rather than a boolean kind: it renders as a status word, and sorting
 * it A→Z groups the two states, which is what a reader clicking a "Status" header wants.
 */
export const userSort = defineSortTable(
  {
    email: "text",
    firstName: "text",
    lastName: "text",
    role: "text",
    isActive: "text",
    lastLoginAt: "date",
    activeSessions: "number",
    createdAt: "date",
  } as const,
  "email",
);

export const listUsersQuerySchema = paginationQuerySchema.extend({
  search: z.string().trim().max(320).optional(),
  role: userRoleSchema.optional(),
  isActive: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .optional(),
  /**
   * `none` lists the accounts that can sign in and reach nothing.
   *
   * The working list after directory sign-in started creating accounts on its own: everybody
   * who signed in once and is waiting for an administrator to give them something to see.
   */
  access: z.enum(["none"]).optional(),
}).merge(userSort.querySchema);
export type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;

export interface UserSummary {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  role: "admin" | "user";
  /*
    The shared union, not a copy of it. Spelled out, this narrowed every consumer to
    whatever the providers happened to be on the day it was written, so adding one broke
    a field that only carries the value through.
  */
  authProvider: AuthProviderName;
  isActive: boolean;
  mustChangePassword: boolean;
  /**
   * Whether this account is narrowed to particular groups and applications.
   *
   * The flag alone, not the grants. It is what the user list needs to show that an account
   * is restricted at all; *what* it is restricted to is read when the editor opens, because
   * fetching grants per row would be one request per row to draw one column.
   */
  applicationAccessRestricted: boolean;
  /**
   * The squads this account is a member of, by name.
   *
   * On the row because a squad is now one of the ways an account reaches applications, and an
   * Access column that showed only the account's own grants would describe half of it.
   */
  squads: Array<{ id: string; name: string }>;
  /**
   * False when the account can sign in and reach nothing at all.
   *
   * A non-admin with no estate, or narrowed to nothing, and in no squad that grants anything.
   * Coarse on purpose - it does not intersect grants with estates - because its job is to find
   * the accounts nobody has looked at yet, not to answer what a particular one can see.
   */
  hasAccess: boolean;
  lastLoginAt: string | null;
  /** Live session count, so an admin can see who is currently signed in. */
  activeSessions: number;
  createdAt: string;
}

/**
 * Returned once, and only once, when a password is generated or set by an
 * admin. The plaintext is never stored and cannot be retrieved again - if the
 * admin loses it, the fix is another reset.
 */
export interface UserCredentialResponse {
  user: UserSummary;
  /**
   * Absent for a directory account, which is created with no password at all.
   *
   * Optional rather than an empty string, so a screen cannot render a blank credential box
   * that somebody tries to copy and hand over. The caller has to decide what to show when
   * there is nothing to show.
   */
  temporaryPassword?: string;
}
