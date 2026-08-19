import { z } from "zod";
import { paginationQuerySchema, uuidSchema } from "./common.js";
import { defineSortTable } from "./sort.js";
import type { SeverityCounts } from "./vulnerability.js";

/**
 * Named sets of applications: a product assembled from several images, or a trait like
 * "public facing" that cuts across unrelated ones.
 *
 * ## Why the numbers here are not the numbers on the dashboard
 *
 * A group counts **distinct advisories**. The dashboard counts **findings**, which are
 * per-package occurrences summed across applications. For a product built from eight images
 * that share a base layer, those two differ by roughly eight times, and both are correct —
 * they answer different questions:
 *
 *   findings   how much remediation work exists. Eight vulnerable images are eight rebuilds.
 *   advisories how much distinct exposure exists. One CVE is one thing to understand.
 *
 * Summing here would make a group's headline number a count of how many images it has. A
 * sixteen-image group running identical software to an eight-image one would score exactly
 * twice as badly, and ranking groups by risk would rank them by size. Hence distinct, plus
 * `affectedMembers` so "everywhere" and "one corner" stay distinguishable.
 *
 * The two words are kept apart everywhere in the UI for the same reason. They must never
 * appear side by side unlabelled, because a reader seeing 340 and 2,847 for the same group
 * has no way to tell which is real.
 */

export const groupNameSchema = z
  .string()
  .trim()
  .min(1, "name is required")
  .max(120)
  // Same charset rule as application names: permissive, but not whitespace-only and no
  // control characters, which render as nothing and make two groups look identical.
  .regex(/^[^\p{C}]+$/u, "must not contain control characters");

export const groupDescriptionSchema = z.string().trim().max(1000);

export const createGroupRequestSchema = z.object({
  name: groupNameSchema,
  description: groupDescriptionSchema.optional(),
  /** Initial membership, so creating a group and filling it is one action. */
  applicationIds: z.array(uuidSchema).max(500).optional(),
});
export type CreateGroupRequest = z.infer<typeof createGroupRequestSchema>;

export const updateGroupRequestSchema = z
  .object({
    name: groupNameSchema.optional(),
    /** Empty string clears it; omitted leaves it unchanged. The two are different. */
    description: groupDescriptionSchema.nullable().optional(),
  })
  .refine((v) => v.name !== undefined || v.description !== undefined, {
    message: "provide `name`, `description`, or both",
  });
export type UpdateGroupRequest = z.infer<typeof updateGroupRequestSchema>;

/**
 * Membership replacement, sent as the complete list rather than as add/remove deltas.
 *
 * The admin screen edits a checklist, so the whole set is what it knows. Deltas would need
 * the client to track what it started with, and two admins editing at once would each apply
 * their delta to a set the other had already changed.
 */
export const setGroupMembersRequestSchema = z.object({
  applicationIds: z.array(uuidSchema).max(500),
});
export type SetGroupMembersRequest = z.infer<typeof setGroupMembersRequestSchema>;

export const groupSort = defineSortTable(
  {
    name: "text",
    applicationCount: "number",
    advisoryCount: "number",
    createdAt: "date",
  } as const,
  "name",
);

export const listGroupsQuerySchema = paginationQuerySchema
  .extend({
    search: z.string().trim().max(255).optional(),
  })
  .merge(groupSort.querySchema);
export type ListGroupsQuery = z.infer<typeof listGroupsQuerySchema>;

/** A group as referenced from elsewhere — the chips on an application row. */
export interface GroupRef {
  id: string;
  name: string;
}

export interface ApplicationGroupSummary extends GroupRef {
  description: string | null;
  /** Members, including inactive ones. `assessedApplicationCount` is the aggregate's basis. */
  applicationCount: number;
  /**
   * The first few member names, for a preview on the list.
   *
   * Carried on the summary rather than fetched per row. The admin screen shows who is in each
   * group without opening it, and doing that from the detail endpoint would issue one request
   * per row — two hundred of them on a full page. Capped at `EXPANDABLE_LIST_CAP`, with
   * `applicationCount` as the true total, so a preview can state its own overflow.
   */
  memberNames: string[];
  /**
   * Distinct advisories across the members' current builds, or null when the number is not
   * known.
   *
   * Null when vulnerability scanning is off, and null when no member has a build that has
   * been matched against the database. Never zero for either — zero means every member was
   * assessed and nothing was found, which is a claim this platform must only make when it is
   * true. Same rule as an application's own findings.
   */
  vulnerabilities: GroupVulnCounts | null;
  createdAt: string;
}

export interface GroupVulnCounts {
  /** Distinct advisories affecting at least one member's current build. */
  advisories: number;
  /** Distinct advisories by severity. Sums to `advisories`. */
  bySeverity: SeverityCounts;
  /**
   * Members whose current build has been matched against the database.
   *
   * The denominator for everything above, and not the same as `applicationCount`: a member
   * that has never been scanned, or whose build is awaiting the next sweep, contributes
   * nothing. Reported so a group of twenty showing three advisories cannot be misread as
   * healthy when nineteen of its members were simply never looked at.
   */
  assessedApplicationCount: number;
  /** Members with at least one advisory. */
  affectedApplicationCount: number;
}

export interface ApplicationGroupDetail extends ApplicationGroupSummary {
  updatedAt: string;
  members: GroupMember[];
}

export interface GroupMember {
  id: string;
  name: string;
  status: "active" | "inactive" | "pending_confirmation";
  lastScanAt: string | null;
  latestScanId: string | null;
  /**
   * Distinct advisories affecting this member alone, or null when it has not been assessed.
   *
   * Per-member rather than only the group total because "who in this group is the problem"
   * is the next question after "how bad is this group", and answering it should not require
   * opening eight applications one at a time.
   */
  advisories: number | null;
}

/** Sortable columns of a group's advisory list. Defaults to the most widespread. */
export const groupAdvisorySort = defineSortTable(
  { affectedMembers: "number", severity: "text", vulnerabilityId: "text" } as const,
  "affectedMembers",
);

export const listGroupAdvisoriesQuerySchema = paginationQuerySchema
  .extend({
    search: z.string().trim().max(255).optional(),
    severity: z.string().trim().max(64).optional(),
  })
  .merge(groupAdvisorySort.querySchema);
export type ListGroupAdvisoriesQuery = z.infer<typeof listGroupAdvisoriesQuerySchema>;

/**
 * One advisory, with how much of the group it reaches.
 *
 * `affectedMembers` out of `assessedApplicationCount` is the line that makes a group page
 * worth reading: an advisory in one of eight images is a single rebuild, and the same
 * advisory in eight of eight is a base image nobody has updated. The severity alone does not
 * distinguish those, and a flat list of CVEs would present them identically.
 */
export interface GroupAdvisory {
  vulnerabilityId: string;
  severity: string;
  cvssScore: number | null;
  affectedMembers: number;
  /** Distinct packages carrying it across the group, for "one library or fifteen". */
  affectedPackages: number;
  /** True when at least one affected package has a known fix. */
  fixable: boolean;
}
