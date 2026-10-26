import { z } from "zod";
import { uuidSchema } from "./common.js";
import { USER_APPLICATION_GRANT_LIMIT, USER_GROUP_GRANT_LIMIT } from "./application-access.js";

/**
 * Squads: teams of people, granted applications together.
 *
 * The problem they solve is bookkeeping, not policy. Every rule about what an account may read
 * already existed; what did not exist was a way to say it once for a team. Granting a squad a
 * group means each member reaches the group's applications, now and as the group changes, and
 * adding or removing a member is a single change rather than a review of every application the
 * team owns.
 *
 * ## How a squad grant composes with the account's own
 *
 * It adds. Whatever an account reaches through its own environment and application grants it
 * still reaches, and each squad it is on contributes its applications on top — including the
 * estates those applications live in, so an administrator does not have to remember to grant
 * production separately for a squad that owns a production service. The estate comes along for
 * the squad's applications only; it does not open the rest of that estate to the member.
 *
 * Administrators are unaffected either way: they reach everything by role.
 */

/** Squad names follow group names: short, human, unique without regard to case. */
const squadNameSchema = z
  .string()
  .trim()
  .min(1, "required")
  .max(120)
  .regex(/^[^\p{C}]+$/u, "must not contain control characters");

/**
 * The team's own address.
 *
 * Not a login identifier, unlike an account's: this one is meant to receive mail, so it is
 * checked as an address. Blank clears it.
 */
const squadEmailSchema = z
  .string()
  .trim()
  .max(320)
  .transform((v) => (v === "" ? null : v.toLowerCase()))
  .pipe(z.string().email("must be an email address").nullable())
  .nullable();

const descriptionSchema = z
  .string()
  .trim()
  .max(2000)
  .transform((v) => (v === "" ? null : v))
  .nullable();

export const createSquadSchema = z.object({
  name: squadNameSchema,
  email: squadEmailSchema.optional(),
  description: descriptionSchema.optional(),
});
export type CreateSquad = z.infer<typeof createSquadSchema>;

export const updateSquadSchema = z
  .object({
    name: squadNameSchema.optional(),
    email: squadEmailSchema.optional(),
    description: descriptionSchema.optional(),
  })
  .refine((v) => v.name !== undefined || v.email !== undefined || v.description !== undefined, {
    message: "nothing to change",
  });
export type UpdateSquad = z.infer<typeof updateSquadSchema>;

/** A squad is people, and a few hundred is already a department rather than a team. */
export const SQUAD_MEMBER_LIMIT = 500;

/** The complete member list, not a delta — the screen edits a checklist. */
export const setSquadMembersSchema = z
  .object({ userIds: z.array(uuidSchema).max(SQUAD_MEMBER_LIMIT) })
  .transform((v) => ({ userIds: [...new Set(v.userIds)] }));
export type SetSquadMembers = z.infer<typeof setSquadMembersSchema>;

/** The complete grant set. Same caps as an account's, for the same reason. */
export const setSquadAccessSchema = z
  .object({
    groupIds: z.array(uuidSchema).max(USER_GROUP_GRANT_LIMIT).default([]),
    applicationIds: z.array(uuidSchema).max(USER_APPLICATION_GRANT_LIMIT).default([]),
  })
  .transform((v) => ({
    groupIds: [...new Set(v.groupIds)],
    applicationIds: [...new Set(v.applicationIds)],
  }));
export type SetSquadAccess = z.infer<typeof setSquadAccessSchema>;

/** Setting one account's memberships from the account's side. */
export const setUserSquadsSchema = z
  .object({ squadIds: z.array(uuidSchema).max(100) })
  .transform((v) => ({ squadIds: [...new Set(v.squadIds)] }));
export type SetUserSquads = z.infer<typeof setUserSquadsSchema>;

export interface SquadSummary {
  id: string;
  name: string;
  email: string | null;
  description: string | null;
  memberCount: number;
  groupCount: number;
  /** Directly granted applications, not the applications reached through groups. */
  applicationCount: number;
  /**
   * Distinct applications the squad reaches, through groups and directly.
   *
   * The figure an administrator actually wants from the list. Groups overlap with each other
   * and with direct grants, so the two counts beside it do not add up to this.
   */
  reachableApplicationCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface SquadMember {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  role: "admin" | "user";
  isActive: boolean;
}

/** A granted group or application, named, with the estate it lives in. */
export interface SquadGrant {
  id: string;
  name: string;
  environmentId: string;
  environmentName: string;
}

export interface SquadDetail extends SquadSummary {
  members: SquadMember[];
  groups: SquadGrant[];
  applications: SquadGrant[];
}
