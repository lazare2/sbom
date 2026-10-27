import { eq, sql } from "drizzle-orm";
import type {
  CreateSquad,
  SetSquadAccess,
  SquadDetail,
  SquadGrant,
  SquadMember,
  SquadSettings,
  SquadSummary,
  TeamRef,
  UpdateSquad,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { squad } from "../../db/schema.js";
import {
  ConflictError,
  isPgError,
  NotFoundError,
  PG_UNIQUE_VIOLATION,
  ValidationError,
} from "../../lib/errors.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import { SQUAD_APPLICATIONS } from "./reach.js";
import type { TeamAttributes } from "./team-attributes.js";

/**
 * Squads: who is on which team, and what each team is granted.
 *
 * Admin-only throughout, and every write audited, for the reason the access screens are: a
 * squad's membership is an access decision now, not an organisational note. Adding somebody to
 * a squad grants them every application it reaches, so "who added this person, and when" has to
 * be answerable from the trail.
 *
 * What a squad grant *means* for a request is decided in `ApplicationAccessService` and
 * `EnvironmentService.accessFor`, not here. This service only keeps the rows.
 */
export class SquadsService {
  constructor(
    private readonly deps: {
      db: Database;
      audit: AuditService;
      teams: TeamAttributes;
      settings: {
        getSquadSettings(): Promise<SquadSettings>;
        updateSquadSettings(next: SquadSettings): Promise<SquadSettings>;
      };
    },
  ) {}

  async list(): Promise<SquadSummary[]> {
    const rows = await this.deps.db.execute<Row<SquadRowQuery>>(sql`
      SELECT ${SUMMARY_COLUMNS}
        FROM squad s
       ORDER BY lower(s.name) ASC, s.id
    `);
    return rowsOf(rows).map(toSummary);
  }

  async get(id: string): Promise<SquadDetail> {
    const rows = await this.deps.db.execute<Row<SquadRowQuery>>(sql`
      SELECT ${SUMMARY_COLUMNS} FROM squad s WHERE s.id = ${id}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Squad");

    const [members, groups, applications] = await Promise.all([
      this.deps.db.execute<
        Row<{
          id: string;
          email: string;
          first_name: string | null;
          last_name: string | null;
          role: "admin" | "user";
          is_active: boolean;
        }>
      >(sql`
        SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.is_active
          FROM squad_member sm JOIN "user" u ON u.id = sm.user_id
         WHERE sm.squad_id = ${id}::uuid
         ORDER BY lower(coalesce(u.last_name, '')), lower(coalesce(u.first_name, '')), lower(u.email)
      `),
      this.deps.db.execute<Row<GrantRow>>(sql`
        SELECT g.id, g.name, e.id AS environment_id, e.name AS environment_name
          FROM squad_group sg
          JOIN application_group g ON g.id = sg.group_id
          JOIN environment e ON e.id = g.environment_id
         WHERE sg.squad_id = ${id}::uuid
         ORDER BY lower(e.name), lower(g.name)
      `),
      this.deps.db.execute<Row<GrantRow>>(sql`
        SELECT a.id, a.name, e.id AS environment_id, e.name AS environment_name
          FROM squad_application sa
          JOIN application a ON a.id = sa.application_id
          JOIN environment e ON e.id = a.environment_id
         WHERE sa.squad_id = ${id}::uuid
         ORDER BY lower(e.name), lower(a.name)
      `),
    ]);

    return {
      ...toSummary(row),
      members: rowsOf(members).map(
        (m): SquadMember => ({
          id: m.id,
          email: m.email,
          firstName: m.first_name,
          lastName: m.last_name,
          role: m.role,
          isActive: m.is_active,
        }),
      ),
      groups: rowsOf(groups).map(toGrant),
      applications: rowsOf(applications).map(toGrant),
    };
  }

  async create(input: CreateSquad, actor: Actor): Promise<SquadDetail> {
    const tribeIds = input.tribeIds ?? [];
    await this.assertTribeRule(tribeIds);
    await this.assertKnown("tribe", tribeIds);

    let created;
    try {
      created = await this.deps.db.transaction(async (tx) => {
        const [row] = await tx
          .insert(squad)
          .values({
            name: input.name,
            email: input.email ?? null,
            description: input.description ?? null,
          })
          .returning();
        if (!row) throw new Error("insert returned no row");
        for (const tribeId of tribeIds) {
          await tx.execute(sql`
            INSERT INTO squad_tribe (squad_id, tribe_id) VALUES (${row.id}::uuid, ${tribeId}::uuid)
            ON CONFLICT DO NOTHING
          `);
        }
        return row;
      });
    } catch (err) {
      // The case-insensitive index is the authority, so two admins racing get one squad and
      // one readable 409 rather than a 500.
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`A squad named "${input.name}" already exists.`);
      }
      throw err;
    }
    await this.deps.audit.record({
      actor,
      action: "squad.create",
      targetType: "squad",
      targetId: created.id,
      metadata: { name: created.name, email: created.email, tribeIds },
    });

    return this.get(created.id);
  }

  async update(id: string, input: UpdateSquad, actor: Actor): Promise<SquadDetail> {
    const existing = await this.require(id);
    const tribesBefore = (await this.tribesOf(id)).map((t) => t.id);
    if (input.tribeIds !== undefined) {
      await this.assertTribeRule(input.tribeIds);
      await this.assertKnown("tribe", input.tribeIds);
    }

    const patch: Partial<typeof squad.$inferInsert> = { updatedAt: new Date() };
    if (input.name !== undefined) patch.name = input.name;
    // Null clears; undefined leaves alone. The schema already folded blank to null.
    if (input.email !== undefined) patch.email = input.email;
    if (input.description !== undefined) patch.description = input.description;

    let updated;
    try {
      updated = await this.deps.db.transaction(async (tx) => {
        const [row] = await tx.update(squad).set(patch).where(eq(squad.id, id)).returning();
        if (!row) throw new NotFoundError("Squad");
        if (input.tribeIds !== undefined) {
          await tx.execute(sql`
            DELETE FROM squad_tribe
             WHERE squad_id = ${id}::uuid
               AND NOT (tribe_id = ANY(${sql.param(input.tribeIds)}::uuid[]))
          `);
          for (const tribeId of input.tribeIds) {
            await tx.execute(sql`
              INSERT INTO squad_tribe (squad_id, tribe_id) VALUES (${id}::uuid, ${tribeId}::uuid)
              ON CONFLICT DO NOTHING
            `);
          }
        }
        return row;
      });
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`A squad named "${input.name}" already exists.`);
      }
      throw err;
    }

    // A rename changes the name every assigned application's "squad" attribute shows.
    if (updated.name !== existing.name) {
      await this.deps.teams.refresh(await this.deps.teams.applicationsOf("squad", id));
    }

    await this.deps.audit.record({
      actor,
      action: "squad.update",
      targetType: "squad",
      targetId: id,
      metadata: {
        from: { name: existing.name, email: existing.email, tribeIds: tribesBefore },
        to: {
          name: updated.name,
          email: updated.email,
          tribeIds: input.tribeIds ?? tribesBefore,
        },
      },
    });

    return this.get(id);
  }

  /**
   * Deletes the squad. Members keep their accounts and their own grants; they lose only what
   * the squad gave them, at once.
   */
  async remove(id: string, actor: Actor): Promise<{ members: number }> {
    const existing = await this.get(id);

    await this.deps.audit.record({
      actor,
      action: "squad.delete",
      targetType: "squad",
      targetId: id,
      // The member list is the part that is gone for good, so it is what the trail keeps.
      metadata: {
        name: existing.name,
        memberIds: existing.members.map((m) => m.id),
        groupIds: existing.groups.map((g) => g.id),
        applicationIds: existing.applications.map((a) => a.id),
      },
    });

    const assigned = await this.deps.teams.applicationsOf("squad", id);
    await this.deps.db.delete(squad).where(eq(squad.id, id));
    // The cascade removed the assignments; the attributes that named this squad follow.
    await this.deps.teams.refresh(assigned);
    return { members: existing.members.length };
  }

  /**
   * Replaces the member list with exactly this set.
   *
   * Every id must name an account. Silently dropping an unknown one would bring the checklist
   * back with a person missing and nothing to say why -- which reads as the save having failed.
   */
  async setMembers(id: string, userIds: string[], actor: Actor): Promise<SquadDetail> {
    await this.require(id);
    await this.assertKnown("user", userIds);
    const before = await this.memberIds(id);

    await this.deps.db.transaction(async (tx) => {
      await tx.execute(sql`
        DELETE FROM squad_member
         WHERE squad_id = ${id}::uuid
           AND NOT (user_id = ANY(${sql.param(userIds)}::uuid[]))
      `);
      for (const userId of userIds) {
        await tx.execute(sql`
          INSERT INTO squad_member (squad_id, user_id) VALUES (${id}::uuid, ${userId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });

    await this.deps.audit.record({
      actor,
      action: "squad.members_set",
      targetType: "squad",
      targetId: id,
      metadata: {
        added: userIds.filter((u) => !before.includes(u)),
        removed: before.filter((u) => !userIds.includes(u)),
        count: { from: before.length, to: userIds.length },
      },
    });

    return this.get(id);
  }

  /** Replaces what the squad is granted with exactly this set. Same rules as members. */
  async setAccess(id: string, input: SetSquadAccess, actor: Actor): Promise<SquadDetail> {
    const existing = await this.get(id);
    await this.assertKnown("application_group", input.groupIds);
    await this.assertKnown("application", input.applicationIds);

    await this.deps.db.transaction(async (tx) => {
      await tx.execute(sql`DELETE FROM squad_group WHERE squad_id = ${id}::uuid`);
      for (const groupId of input.groupIds) {
        await tx.execute(sql`
          INSERT INTO squad_group (squad_id, group_id) VALUES (${id}::uuid, ${groupId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
      await tx.execute(sql`DELETE FROM squad_application WHERE squad_id = ${id}::uuid`);
      for (const applicationId of input.applicationIds) {
        await tx.execute(sql`
          INSERT INTO squad_application (squad_id, application_id)
          VALUES (${id}::uuid, ${applicationId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });

    // Direct grants are what an application's "squad" attribute lists, so every application
    // that gained or lost one is rewritten.
    await this.deps.teams.refresh([
      ...existing.applications.map((a) => a.id),
      ...input.applicationIds,
    ]);

    const after = await this.get(id);
    await this.deps.audit.record({
      actor,
      action: "squad.access_set",
      targetType: "squad",
      targetId: id,
      // Ids, not names -- a group can be renamed and the trail must still say which one.
      metadata: {
        groupIds: { from: existing.groups.map((g) => g.id), to: input.groupIds },
        applicationIds: {
          from: existing.applications.map((a) => a.id),
          to: input.applicationIds,
        },
        reachable: {
          from: existing.reachableApplicationCount,
          to: after.reachableApplicationCount,
        },
      },
    });

    return after;
  }

  /** The squads one account is on. */
  async forUser(userId: string): Promise<Array<{ id: string; name: string }>> {
    const rows = await this.deps.db.execute<Row<{ id: string; name: string }>>(sql`
      SELECT s.id, s.name FROM squad_member sm JOIN squad s ON s.id = sm.squad_id
       WHERE sm.user_id = ${userId}::uuid
       ORDER BY lower(s.name)
    `);
    return rowsOf(rows);
  }

  /** Sets one account's memberships from the account's side, as one decision. */
  async setForUser(userId: string, squadIds: string[], actor: Actor): Promise<void> {
    await this.assertKnown("squad", squadIds);
    const before = (await this.forUser(userId)).map((s) => s.id);

    await this.deps.db.transaction(async (tx) => {
      await tx.execute(sql`
        DELETE FROM squad_member
         WHERE user_id = ${userId}::uuid
           AND NOT (squad_id = ANY(${sql.param(squadIds)}::uuid[]))
      `);
      for (const squadId of squadIds) {
        await tx.execute(sql`
          INSERT INTO squad_member (squad_id, user_id) VALUES (${squadId}::uuid, ${userId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });

    await this.deps.audit.record({
      actor,
      action: "user.squads_set",
      targetType: "user",
      targetId: userId,
      metadata: {
        added: squadIds.filter((s) => !before.includes(s)),
        removed: before.filter((s) => !squadIds.includes(s)),
      },
    });
  }

  async getSettings(): Promise<SquadSettings> {
    return this.deps.settings.getSquadSettings();
  }

  async updateSettings(next: SquadSettings, actor: Actor): Promise<SquadSettings> {
    const before = await this.deps.settings.getSquadSettings();
    const saved = await this.deps.settings.updateSquadSettings(next);
    await this.deps.audit.record({
      actor,
      action: "squad.settings_update",
      targetType: "setting",
      targetId: null,
      metadata: { from: before, to: saved },
    });
    return saved;
  }

  // -------------------------------------------------------------------------

  /**
   * Refuses a squad with no tribe while an administrator requires one. Checked on create, and
   * on any save that changes the squad's tribes; squads that predate the rule are left alone
   * until somebody edits their tribes.
   */
  private async assertTribeRule(tribeIds: readonly string[]): Promise<void> {
    if (tribeIds.length > 0) return;
    if (!(await this.deps.settings.getSquadSettings()).requireTribe) return;
    throw new ValidationError("Every squad must belong to a tribe", {
      tribeIds: ["Choose at least one tribe. This is required under Admin → Access → Squads."],
    });
  }

  private async tribesOf(id: string): Promise<TeamRef[]> {
    const rows = await this.deps.db.execute<Row<{ id: string; name: string }>>(sql`
      SELECT t.id, t.name FROM squad_tribe st JOIN tribe t ON t.id = st.tribe_id
       WHERE st.squad_id = ${id}::uuid
       ORDER BY lower(t.name)
    `);
    return rowsOf(rows);
  }

  private async require(id: string) {
    const [row] = await this.deps.db.select().from(squad).where(eq(squad.id, id)).limit(1);
    if (!row) throw new NotFoundError("Squad");
    return row;
  }

  private async memberIds(id: string): Promise<string[]> {
    const rows = await this.deps.db.execute<Row<{ user_id: string }>>(
      sql`SELECT user_id FROM squad_member WHERE squad_id = ${id}::uuid`,
    );
    return rowsOf(rows).map((r) => r.user_id);
  }

  /**
   * Refuses a list naming anything that does not exist, without saying which.
   *
   * Echoing back the unknown ids would confirm the existence of everything else by elimination,
   * which is the same reason the account-access routes only count.
   */
  private async assertKnown(
    table: "user" | "squad" | "tribe" | "application" | "application_group",
    ids: readonly string[],
  ): Promise<void> {
    if (ids.length === 0) return;
    const rows = await this.deps.db.execute<Row<{ n: number | string }>>(sql`
      SELECT count(*)::int AS n FROM ${sql.identifier(table)}
       WHERE id = ANY(${sql.param([...ids])}::uuid[])
    `);
    if (Number(rowsOf(rows)[0]?.n ?? 0) !== ids.length) {
      throw new NotFoundError(
        table === "user"
          ? "User"
          : table === "squad"
            ? "Squad"
            : table === "tribe"
              ? "Tribe"
              : table === "application"
              ? "Application"
              : "Group",
      );
    }
  }
}

// ---------------------------------------------------------------------------

/**
 * The summary columns, reachable count included.
 *
 * Reachable is counted rather than summed: a squad granted a group and, directly, an application
 * already in it reaches one application, not two. Applications assigned to the squad's tribes
 * count too, since every member sees them.
 */
const SUMMARY_COLUMNS = sql`
  s.id, s.name, s.email, s.description, s.created_at, s.updated_at,
  COALESCE((
    SELECT json_agg(json_build_object('id', t.id, 'name', t.name) ORDER BY lower(t.name))
      FROM squad_tribe st JOIN tribe t ON t.id = st.tribe_id
     WHERE st.squad_id = s.id
  ), '[]'::json) AS tribes,
  (SELECT count(*) FROM squad_member sm WHERE sm.squad_id = s.id)::int AS member_count,
  (SELECT count(*) FROM squad_group sg WHERE sg.squad_id = s.id)::int AS group_count,
  (SELECT count(*) FROM squad_application sa WHERE sa.squad_id = s.id)::int AS application_count,
  (
    SELECT count(DISTINCT x.application_id) FROM (
      SELECT sa.application_id FROM ${SQUAD_APPLICATIONS} sa WHERE sa.squad_id = s.id
      UNION
      SELECT gm.application_id
        FROM squad_group sg JOIN application_group_member gm ON gm.group_id = sg.group_id
       WHERE sg.squad_id = s.id
    ) x
  )::int AS reachable_application_count`;

interface SquadRowQuery {
  id: string;
  name: string;
  email: string | null;
  description: string | null;
  tribes: TeamRef[] | null;
  created_at: Date | string;
  updated_at: Date | string;
  member_count: number | string;
  group_count: number | string;
  application_count: number | string;
  reachable_application_count: number | string;
}

interface GrantRow {
  id: string;
  name: string;
  environment_id: string;
  environment_name: string;
}

function toSummary(row: SquadRowQuery): SquadSummary {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    description: row.description,
    tribes: row.tribes ?? [],
    memberCount: Number(row.member_count),
    groupCount: Number(row.group_count),
    applicationCount: Number(row.application_count),
    reachableApplicationCount: Number(row.reachable_application_count),
    createdAt: toIso(row.created_at)!,
    updatedAt: toIso(row.updated_at)!,
  };
}

function toGrant(row: GrantRow): SquadGrant {
  return {
    id: row.id,
    name: row.name,
    environmentId: row.environment_id,
    environmentName: row.environment_name,
  };
}
