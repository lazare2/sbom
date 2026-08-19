import { eq, sql } from "drizzle-orm";
import type {
  ApplicationGroupDetail,
  CreateGroupRequest,
  SetGroupMembersRequest,
  UpdateGroupRequest,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { applicationGroup, applicationGroupMember } from "../../db/schema.js";
import {
  BadRequestError,
  ConflictError,
  isPgError,
  NotFoundError,
  PG_UNIQUE_VIOLATION,
} from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import type { GroupsService } from "./groups.service.js";

/**
 * Admin writes for application groups.
 *
 * Separate from `GroupsService` for the same reason the applications module splits its two:
 * reads are open to every authenticated user, writes are admin-only and audited. Keeping them
 * in one class would make it a per-method decision to record an audit entry, and the entry
 * that gets forgotten is always the one someone later needs.
 *
 * Membership is set here and nowhere else — ingest never touches these tables. See the note
 * on `applicationGroupMember` in the schema for why a pipeline is not allowed to declare its
 * own groups.
 */
export class GroupsAdminService {
  constructor(
    private readonly deps: { db: Database; audit: AuditService; groups: GroupsService },
  ) {}

  async create(input: CreateGroupRequest, actor: Actor): Promise<ApplicationGroupDetail> {
    const applicationIds = input.applicationIds ?? [];
    // Verified before the insert so a bad id fails the whole request rather than leaving a
    // created group with silently missing members.
    if (applicationIds.length > 0) await this.assertApplicationsExist(applicationIds);

    const created = await this.deps.db.transaction(async (tx) => {
      let group;
      try {
        [group] = await tx
          .insert(applicationGroup)
          .values({ name: input.name, description: input.description ?? null })
          .returning();
      } catch (err) {
        if (isPgError(err, PG_UNIQUE_VIOLATION)) {
          throw new ConflictError(`A group named "${input.name}" already exists.`);
        }
        throw err;
      }
      if (!group) throw new Error("insert returned no row");

      if (applicationIds.length > 0) {
        await tx
          .insert(applicationGroupMember)
          .values(applicationIds.map((id) => ({ groupId: group!.id, applicationId: id })))
          // Duplicates within one request are a client mistake, not a conflict worth a 409.
          .onConflictDoNothing();
      }

      await this.deps.audit.record(
        {
          actor,
          action: "group.create",
          targetType: "application_group",
          targetId: group.id,
          metadata: { name: group.name, memberCount: applicationIds.length },
        },
        tx,
      );

      return group;
    });

    return this.deps.groups.getById(created.id);
  }

  async update(
    id: string,
    input: UpdateGroupRequest,
    actor: Actor,
  ): Promise<ApplicationGroupDetail> {
    const existing = await this.require(id);

    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (input.name !== undefined) patch.name = input.name;
    // Null clears the description, undefined leaves it. Collapsing the two would make it
    // impossible to remove a description once set.
    if (input.description !== undefined) patch.description = input.description || null;

    try {
      await this.deps.db.update(applicationGroup).set(patch).where(eq(applicationGroup.id, id));
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`A group named "${input.name}" already exists.`);
      }
      throw err;
    }

    await this.deps.audit.record({
      actor,
      action: "group.update",
      targetType: "application_group",
      targetId: id,
      metadata: { from: { name: existing.name }, to: { name: input.name ?? existing.name } },
    });

    return this.deps.groups.getById(id);
  }

  /**
   * Replaces the whole membership.
   *
   * The request carries the complete set rather than add/remove deltas, because the admin
   * screen edits a checklist and the whole set is what it knows. Deltas would also make two
   * admins editing at once apply their changes to a list the other had already altered.
   *
   * Delete-then-insert inside one transaction: an application present before and after keeps
   * its row's `created_at` only if it is not touched, so the delete is scoped to ids that are
   * actually leaving.
   */
  async setMembers(
    id: string,
    input: SetGroupMembersRequest,
    actor: Actor,
  ): Promise<ApplicationGroupDetail> {
    await this.require(id);
    const wanted = [...new Set(input.applicationIds)];
    if (wanted.length > 0) await this.assertApplicationsExist(wanted);

    await this.deps.db.transaction(async (tx) => {
      const before = await tx
        .select({ applicationId: applicationGroupMember.applicationId })
        .from(applicationGroupMember)
        .where(eq(applicationGroupMember.groupId, id));
      const had = new Set(before.map((r) => r.applicationId));

      const added = wanted.filter((appId) => !had.has(appId));
      const removed = [...had].filter((appId) => !wanted.includes(appId));

      if (removed.length > 0) {
        await tx.execute(sql`
          DELETE FROM application_group_member
          WHERE group_id = ${id}::uuid AND application_id = ANY(${sql.param(removed)}::uuid[])
        `);
      }
      if (added.length > 0) {
        await tx
          .insert(applicationGroupMember)
          .values(added.map((appId) => ({ groupId: id, applicationId: appId })))
          .onConflictDoNothing();
      }

      /*
        Recorded even when nothing moved. "An admin opened this and saved it unchanged" is a
        real answer to "who last confirmed this membership", and suppressing the entry would
        make an unchanged save indistinguishable from one that never happened.
      */
      await this.deps.audit.record(
        {
          actor,
          action: "group.members_set",
          targetType: "application_group",
          targetId: id,
          metadata: { added: added.length, removed: removed.length, total: wanted.length },
        },
        tx,
      );

    });

    return this.deps.groups.getById(id);
  }

  /**
   * Deletes the group. Never touches the applications in it.
   *
   * The membership rows go with it through `ON DELETE CASCADE`, which is the whole extent of
   * the damage: a group is a view over applications, not a container for them.
   */
  async remove(id: string, actor: Actor): Promise<{ deleted: true; memberCount: number }> {
    const existing = await this.require(id);

    const memberCount = await this.deps.db
      .select({ n: sql<number>`count(*)::int` })
      .from(applicationGroupMember)
      .where(eq(applicationGroupMember.groupId, id))
      .then((r) => r[0]?.n ?? 0);

    await this.deps.db.delete(applicationGroup).where(eq(applicationGroup.id, id));

    await this.deps.audit.record({
      actor,
      action: "group.delete",
      targetType: "application_group",
      targetId: id,
      metadata: { name: existing.name, memberCount },
    });

    return { deleted: true, memberCount };
  }

  private async require(id: string): Promise<{ id: string; name: string }> {
    const rows = await this.deps.db
      .select({ id: applicationGroup.id, name: applicationGroup.name })
      .from(applicationGroup)
      .where(eq(applicationGroup.id, id));
    const row = rows[0];
    if (!row) throw new NotFoundError("Group");
    return row;
  }

  /**
   * Rejects the whole request when any id is not an application.
   *
   * A foreign key would catch this too, but as a 500-shaped database error naming a
   * constraint. Naming the count of missing ids is what lets the UI say which selection was
   * stale — usually an application deleted while the dialog was open.
   */
  private async assertApplicationsExist(ids: string[]): Promise<void> {
    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      SELECT id FROM application WHERE id = ANY(${sql.param(ids)}::uuid[])
    `);
    const found = new Set(rowsOf(rows).map((r) => r.id));
    const missing = ids.filter((id) => !found.has(id));
    if (missing.length > 0) {
      throw new BadRequestError(
        `${missing.length} of ${ids.length} selected applications no longer exist.`,
        { missing },
      );
    }
  }
}
