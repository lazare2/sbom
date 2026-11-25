import { sql } from "drizzle-orm";
import type { SquadDirectoryLink } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { AppError, ConflictError, NotFoundError, isPgError, PG_UNIQUE_VIOLATION } from "../../lib/errors.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import { DirectoryError } from "./connector.js";
import type { DirectoryService } from "./directory.service.js";

export interface SquadLinkRow extends SquadDirectoryLink {
  squadId: string;
  squadName: string;
  memberCount: number;
}

/**
 * Which squad takes its members from which directory group.
 *
 * Linking checks the group exists in the directory now and keeps its name and DN for the screen;
 * the group's id is what is followed later. Unlinking leaves the members as they are: they become
 * hand-managed again, rather than a squad emptying because a link was removed.
 */
export class DirectoryLinksService {
  constructor(private readonly deps: { db: Database; audit: AuditService; directory: DirectoryService }) {}

  async list(): Promise<SquadLinkRow[]> {
    const rows = await this.deps.db.execute<
      Row<{
        squad_id: string;
        squad_name: string;
        member_count: number | string;
        group_id: string;
        group_name: string;
        group_dn: string;
        linked_at: string | Date;
      }>
    >(sql`
      SELECT l.squad_id, s.name AS squad_name,
             (SELECT count(*) FROM squad_member sm WHERE sm.squad_id = s.id)::int AS member_count,
             l.group_id, l.group_name, l.group_dn, l.linked_at
        FROM squad_directory_link l JOIN squad s ON s.id = l.squad_id
       ORDER BY lower(s.name)
    `);
    return rowsOf(rows).map((r) => ({
      squadId: r.squad_id,
      squadName: r.squad_name,
      memberCount: Number(r.member_count),
      groupId: r.group_id,
      groupName: r.group_name,
      groupDn: r.group_dn,
      linkedAt: toIso(r.linked_at)!,
    }));
  }

  async link(squadId: string, groupId: string, actor: Actor): Promise<SquadLinkRow> {
    if (!(await this.deps.directory.enabled())) {
      throw new AppError({
        statusCode: 409,
        code: "module_disabled",
        message: "Switch the directory on (Administration > Directory) before linking squads to its groups.",
      });
    }
    const squad = rowsOf(
      await this.deps.db.execute<Row<{ name: string }>>(sql`SELECT name FROM squad WHERE id = ${squadId}::uuid`),
    )[0];
    if (!squad) throw new NotFoundError("Squad");

    let group;
    try {
      group = await (await this.deps.directory.connector()).group(groupId);
    } catch (error) {
      if (error instanceof DirectoryError) {
        throw new AppError({ statusCode: 502, code: `directory_${error.code}`, message: error.message });
      }
      throw error;
    }
    if (!group) throw new NotFoundError("Directory group");

    try {
      await this.deps.db.execute(sql`
        INSERT INTO squad_directory_link (squad_id, group_id, group_name, group_dn, linked_by)
        VALUES (${squadId}::uuid, ${group.id}, ${group.name}, ${group.dn}, ${actor.id}::uuid)
        ON CONFLICT (squad_id) DO UPDATE
          SET group_id = EXCLUDED.group_id, group_name = EXCLUDED.group_name, group_dn = EXCLUDED.group_dn,
              linked_at = now(), linked_by = EXCLUDED.linked_by
      `);
    } catch (error) {
      if (isPgError(error, PG_UNIQUE_VIOLATION)) {
        const other = rowsOf(
          await this.deps.db.execute<Row<{ name: string }>>(sql`
            SELECT s.name FROM squad_directory_link l JOIN squad s ON s.id = l.squad_id WHERE l.group_id = ${group.id}
          `),
        )[0];
        throw new ConflictError(`The group "${group.name}" already feeds the squad "${other?.name ?? "another squad"}". A group feeds one squad.`);
      }
      throw error;
    }

    await this.deps.audit.record({
      actor,
      action: "squad.directory_link",
      targetType: "squad",
      targetId: squadId,
      metadata: { squad: squad.name, groupId: group.id, group: group.name, dn: group.dn },
    });
    const row = (await this.list()).find((l) => l.squadId === squadId);
    return row!;
  }

  async unlink(squadId: string, actor: Actor): Promise<void> {
    const removed = rowsOf(
      await this.deps.db.execute<Row<{ group_name: string }>>(sql`
        DELETE FROM squad_directory_link WHERE squad_id = ${squadId}::uuid RETURNING group_name
      `),
    )[0];
    if (!removed) throw new NotFoundError("Squad link");
    await this.deps.audit.record({
      actor,
      action: "squad.directory_unlink",
      targetType: "squad",
      targetId: squadId,
      metadata: { group: removed.group_name, membersKept: true },
    });
  }
}
