import { z } from "zod";
import { authProviderNameSchema, userRoleSchema } from "../enums.js";

/**
 * The login identifier.
 *
 * Deliberately NOT `z.string().email()`. These are usernames that happen to be
 * written in email form — the platform never sends mail to them, so there is
 * nothing to deliver and no reason to reject an identifier that a directory
 * accepts but a strict RFC parser does not. `admin@localhost` and `svc-ci` are
 * both legitimate here; requiring a TLD would refuse an account the operator
 * meant to create, for no benefit.
 *
 * Stored lowercased and compared case-insensitively. Normalisation happens here
 * so every entry point (login, admin create) treats `Alice@x` and `alice@x` as
 * one account and cannot create a near-duplicate.
 */
export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3, "must be at least 3 characters")
  .max(320)
  // No whitespace or control characters: those are almost always a paste
  // accident, and they make an identifier impossible to type back in.
  .regex(/^\S+$/u, "must not contain spaces")
  .regex(/^[^\p{C}]+$/u, "must not contain control characters");

/**
 * Minimum 12 characters, no composition rules. Length beats character-class
 * requirements, which mostly produce `Password1!`. Upper bound guards against
 * argon2 being handed a megabyte of input as a cheap DoS.
 */
export const passwordSchema = z
  .string()
  .min(12, "must be at least 12 characters")
  .max(1024, "must be at most 1024 characters");

export const loginRequestSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "password is required").max(1024),
});
export type LoginRequest = z.infer<typeof loginRequestSchema>;

export const changePasswordRequestSchema = z.object({
  currentPassword: z.string().min(1).max(1024),
  newPassword: passwordSchema,
});
export type ChangePasswordRequest = z.infer<typeof changePasswordRequestSchema>;

/** The authenticated principal, as returned by `GET /api/v1/auth/me`. */
export const sessionUserSchema = z.object({
  id: z.string().uuid(),
  email: z.string(),
  role: userRoleSchema,
  authProvider: authProviderNameSchema,
  /**
   * Set when an admin issued a temporary password. The UI holds the user on the
   * change-password screen until it clears; the API refuses every other
   * authenticated route in the meantime, so the flag cannot be skipped by
   * navigating directly.
   */
  mustChangePassword: z.boolean(),
  createdAt: z.string(),
});
export type SessionUser = z.infer<typeof sessionUserSchema>;
