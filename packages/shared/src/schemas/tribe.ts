import { z } from "zod";
import { uuidSchema } from "./common.js";
import { USER_APPLICATION_GRANT_LIMIT } from "./application-access.js";
import { teamDescriptionSchema, teamEmailSchema, teamNameSchema, type TeamRef } from "./squad.js";

/**
 * Tribes: the level above squads.
 *
 * Tribe -> squad -> user. A tribe has no members of its own; its people are the members of its
 * squads, and a squad can sit under more than one tribe. What a tribe adds is a home for
 * applications that belong to the tribe as a whole: every member of every squad in the tribe can
 * see an application assigned to it, in addition to whatever their squads reach.
 *
 * An application's "tribe" attribute lists the tribes it is assigned to directly, and editing the
 * attribute assigns and unassigns, the same way the "squad" attribute works for squads.
 */

export const createTribeSchema = z.object({
  name: teamNameSchema,
  email: teamEmailSchema.optional(),
  description: teamDescriptionSchema.optional(),
});
export type CreateTribe = z.infer<typeof createTribeSchema>;

export const updateTribeSchema = z
  .object({
    name: teamNameSchema.optional(),
    email: teamEmailSchema.optional(),
    description: teamDescriptionSchema.optional(),
  })
  .refine((v) => v.name !== undefined || v.email !== undefined || v.description !== undefined, {
    message: "nothing to change",
  });
export type UpdateTribe = z.infer<typeof updateTribeSchema>;

/** The complete list of squads under a tribe, not a delta. */
export const setTribeSquadsSchema = z
  .object({ squadIds: z.array(uuidSchema).max(500) })
  .transform((v) => ({ squadIds: [...new Set(v.squadIds)] }));
export type SetTribeSquads = z.infer<typeof setTribeSquadsSchema>;

/** The complete list of applications assigned to a tribe directly. */
export const setTribeApplicationsSchema = z
  .object({ applicationIds: z.array(uuidSchema).max(USER_APPLICATION_GRANT_LIMIT) })
  .transform((v) => ({ applicationIds: [...new Set(v.applicationIds)] }));
export type SetTribeApplications = z.infer<typeof setTribeApplicationsSchema>;

export interface TribeSummary {
  id: string;
  name: string;
  email: string | null;
  description: string | null;
  squadCount: number;
  /** Applications assigned to the tribe directly. */
  applicationCount: number;
  /** Distinct people across all of the tribe's squads. */
  memberCount: number;
  createdAt: string;
  updatedAt: string;
}

/** A squad under a tribe, with its size, for the tribe's detail view. */
export interface TribeSquad extends TeamRef {
  memberCount: number;
}

/** An application assigned to a tribe, with the estate it lives in. */
export interface TribeApplication {
  id: string;
  name: string;
  environmentId: string;
  environmentName: string;
}

export interface TribeDetail extends TribeSummary {
  squads: TribeSquad[];
  applications: TribeApplication[];
}
