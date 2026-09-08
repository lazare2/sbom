import { z } from "zod";
import { uuidSchema } from "./common.js";
import { userRoleSchema } from "../enums.js";
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
export const createUserRequestSchema = z.object({
  /**
   * Which environments this account may read. Omitted grants every one that exists.
   *
   * Ignored while the account's role is `admin` -- an administrator reads every estate by
   * definition, including ones created after the account was made.
   */
  environmentIds: z.array(uuidSchema).max(100).optional(),
  email: emailSchema,
  role: userRoleSchema.default("user"),
  /** Omit to have the server generate one and return it once. */
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
  })
  .refine((v) => v.role !== undefined || v.isActive !== undefined, {
    message: "at least one of role or isActive must be provided",
  });
export type UpdateUserRequest = z.infer<typeof updateUserRequestSchema>;

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
}).merge(userSort.querySchema);
export type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;

export interface UserSummary {
  id: string;
  email: string;
  role: "admin" | "user";
  authProvider: "local" | "ldap";
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
  lastLoginAt: string | null;
  /** Live session count, so an admin can see who is currently signed in. */
  activeSessions: number;
  createdAt: string;
}

/**
 * Returned once, and only once, when a password is generated or set by an
 * admin. The plaintext is never stored and cannot be retrieved again — if the
 * admin loses it, the fix is another reset.
 */
export interface UserCredentialResponse {
  user: UserSummary;
  temporaryPassword: string;
}
