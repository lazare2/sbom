import { eq, sql } from "drizzle-orm";
import type {
  CreateTribe,
  TribeApplication,
  TribeDetail,
  TribeSquad,
  TribeSummary,
  UpdateTribe,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { tribe } from "../../db/schema.js";
import { ConflictError, isPgError, NotFoundError, PG_UNIQUE_VIOLATION } from "../../lib/errors.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import type { TeamAttributes } from "./team-attributes.js";

/**
 * Tribes: groups of squads, and applications assigned to the tribe as a whole.
 *
 * Admin-only and audited throughout, like squads, because assigning an application to a tribe is
 * an access decision: every member of every squad under the tribe can see it. What that means for
 * a request is decided where squad grants are (see `SQUAD_APPLICATIONS`); this service only keeps
 * the rows, and keeps each application's "tribe" attribute in step with them.
 */
export class TribesService {
  constructor(private readonly deps: { db: Database; audit: AuditService; teams: TeamAttributes }) {}

  async list(): Promise<TribeSummary[]> {
    const rows = await this.deps.db.execute<Row<TribeQueryRow>>(sql`
      SELECT ${SUMMARY_COLUMNS} FROM tribe t ORDER BY lower(t.name) ASC, t.id
    `);
    return rowsOf(rows).map(toSummary);
  }

  async get(id: string): Promise<TribeDetail> {
    const rows = await this.deps.db.execute<Row<TribeQueryRow>>(sql`
      SELECT ${SUMMARY_COLUMNS} FROM tribe t WHERE t.id = ${id}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Tribe");

    const [squads, applications] = await Promise.all([
      this.deps.db.execute<Row<{ id: string; name: string; member_count: number | string }>>(sql`
        SELECT s.id, s.name,
               (SELECT count(*) FROM squad_member sm WHERE sm.squad_id = s.id)::int AS member_count
          FROM squad_tribe st JOIN squad s ON s.id = st.squad_id
         WHERE st.tribe_id = ${id}::uuid
         ORDER BY lower(s.name)
      `),
      this.deps.db.execute<
        Row<{ id: string; name: string; environment_id: string; environment_name: string }>
      >(sql`
        SELECT a.id, a.name, e.id AS environment_id, e.name AS environment_name
          FROM tribe_application ta
          JOIN application a ON a.id = ta.application_id
          JOIN environment e ON e.id = a.environment_id
         WHERE ta.tribe_id = ${id}::uuid
         ORDER BY lower(e.name), lower(a.name)
      `),
    ]);

    return {
      ...toSummary(row),
      squads: rowsOf(squads).map(
        (s): TribeSquad => ({ id: s.id, name: s.name, memberCount: Number(s.member_count) }),
      ),
      applications: rowsOf(applications).map(
        (a): TribeApplication => ({
          id: a.id,
          name: a.name,
          environmentId: a.environment_id,
          environmentName: a.environment_name,
        }),
      ),
    };
  }

  async create(input: CreateTribe, actor: Actor): Promise<TribeDetail> {
    let created;
    try {
      [created] = await this.deps.db
        .insert(tribe)
        .values({ name: input.name, email: input.email ?? null, description: input.description ?? null })
        .returning();
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`A tribe named "${input.name}" already exists.`);
      }
      throw err;
    }
    if (!created) throw new Error("insert returned no row");

    await this.deps.audit.record({
      actor,
      action: "tribe.create",
      targetType: "tribe",
      targetId: created.id,
      metadata: { name: created.name, email: created.email },
    });
    return this.get(created.id);
  }

  async update(id: string, input: UpdateTribe, actor: Actor): Promise<TribeDetail> {
    const existing = await this.require(id);
    const patch: Partial<typeof tribe.$inferInsert> = { updatedAt: new Date() };
    if (input.name !== undefined) patch.name = input.name;
    if (input.email !== undefined) patch.email = input.email;
    if (input.description !== undefined) patch.description = input.description;

    let updated;
    try {
      [updated] = await this.deps.db.update(tribe).set(patch).where(eq(tribe.id, id)).returning();
    } catch (err) {
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`A tribe named "${input.name}" already exists.`);
      }
      throw err;
    }
    if (!updated) throw new NotFoundError("Tribe");

    if (updated.name !== existing.name) {
      await this.deps.teams.refresh(await this.deps.teams.applicationsOf("tribe", id));
    }

    await this.deps.audit.record({
      actor,
      action: "tribe.update",
      targetType: "tribe",
      targetId: id,
      metadata: {
        from: { name: existing.name, email: existing.email },
        to: { name: updated.name, email: updated.email },
      },
    });
    return this.get(id);
  }

  /** Deletes the tribe. Its squads stay; their members lose only the tribe's own applications. */
  async remove(id: string, actor: Actor): Promise<void> {
    const existing = await this.get(id);
    await this.deps.audit.record({
      actor,
      action: "tribe.delete",
      targetType: "tribe",
      targetId: id,
      metadata: {
        name: existing.name,
        squadIds: existing.squads.map((s) => s.id),
        applicationIds: existing.applications.map((a) => a.id),
      },
    });
    await this.deps.db.delete(tribe).where(eq(tribe.id, id));
    await this.deps.teams.refresh(existing.applications.map((a) => a.id));
  }

  /** Replaces the tribe's squads with exactly this set. */
  async setSquads(id: string, squadIds: string[], actor: Actor): Promise<TribeDetail> {
    const existing = await this.get(id);
    await this.assertKnown("squad", squadIds);

    await this.deps.db.transaction(async (tx) => {
      await tx.execute(sql`
        DELETE FROM squad_tribe
         WHERE tribe_id = ${id}::uuid
           AND NOT (squad_id = ANY(${sql.param(squadIds)}::uuid[]))
      `);
      for (const squadId of squadIds) {
        await tx.execute(sql`
          INSERT INTO squad_tribe (squad_id, tribe_id) VALUES (${squadId}::uuid, ${id}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });

    const before = existing.squads.map((s) => s.id);
    await this.deps.audit.record({
      actor,
      action: "tribe.squads_set",
      targetType: "tribe",
      targetId: id,
      metadata: {
        added: squadIds.filter((s) => !before.includes(s)),
        removed: before.filter((s) => !squadIds.includes(s)),
      },
    });
    return this.get(id);
  }

  /** Replaces the applications assigned to the tribe directly, and their "tribe" attributes. */
  async setApplications(id: string, applicationIds: string[], actor: Actor): Promise<TribeDetail> {
    const existing = await this.get(id);
    await this.assertKnown("application", applicationIds);

    await this.deps.db.transaction(async (tx) => {
      await tx.execute(sql`
        DELETE FROM tribe_application
         WHERE tribe_id = ${id}::uuid
           AND NOT (application_id = ANY(${sql.param(applicationIds)}::uuid[]))
      `);
      for (const applicationId of applicationIds) {
        await tx.execute(sql`
          INSERT INTO tribe_application (tribe_id, application_id)
          VALUES (${id}::uuid, ${applicationId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });

    const before = existing.applications.map((a) => a.id);
    await this.deps.teams.refresh([...before, ...applicationIds]);

    await this.deps.audit.record({
      actor,
      action: "tribe.applications_set",
      targetType: "tribe",
      targetId: id,
      metadata: {
        added: applicationIds.filter((a) => !before.includes(a)),
        removed: before.filter((a) => !applicationIds.includes(a)),
      },
    });
    return this.get(id);
  }

  // -------------------------------------------------------------------------

  private async require(id: string) {
    const [row] = await this.deps.db.select().from(tribe).where(eq(tribe.id, id)).limit(1);
    if (!row) throw new NotFoundError("Tribe");
    return row;
  }

  /** Refuses a list naming anything that does not exist, for the reason squads do. */
  private async assertKnown(table: "squad" | "application", ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    const rows = await this.deps.db.execute<Row<{ n: number | string }>>(sql`
      SELECT count(*)::int AS n FROM ${sql.identifier(table)}
       WHERE id = ANY(${sql.param([...ids])}::uuid[])
    `);
    if (Number(rowsOf(rows)[0]?.n ?? 0) !== ids.length) {
      throw new NotFoundError(table === "squad" ? "Squad" : "Application");
    }
  }
}

// ---------------------------------------------------------------------------

const SUMMARY_COLUMNS = sql`
  t.id, t.name, t.email, t.description, t.created_at, t.updated_at,
  (SELECT count(*) FROM squad_tribe st WHERE st.tribe_id = t.id)::int AS squad_count,
  (SELECT count(*) FROM tribe_application ta WHERE ta.tribe_id = t.id)::int AS application_count,
  (
    SELECT count(DISTINCT sm.user_id)
      FROM squad_tribe st JOIN squad_member sm ON sm.squad_id = st.squad_id
     WHERE st.tribe_id = t.id
  )::int AS member_count`;

interface TribeQueryRow {
  id: string;
  name: string;
  email: string | null;
  description: string | null;
  created_at: Date | string;
  updated_at: Date | string;
  squad_count: number | string;
  application_count: number | string;
  member_count: number | string;
}

function toSummary(row: TribeQueryRow): TribeSummary {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    description: row.description,
    squadCount: Number(row.squad_count),
    applicationCount: Number(row.application_count),
    memberCount: Number(row.member_count),
    createdAt: toIso(row.created_at)!,
    updatedAt: toIso(row.updated_at)!,
  };
}
