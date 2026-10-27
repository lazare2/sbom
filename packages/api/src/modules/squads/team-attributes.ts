import { sql } from "drizzle-orm";
import type { Attributes } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { AttributeDefinitionRow } from "../../db/schema.js";
import { ValidationError } from "../../lib/errors.js";
import { rowsOf, type Row } from "../../lib/rows.js";

/** The two kinds of team an application attribute can mirror. */
export type TeamKind = "squad" | "tribe";

/** The attribute key each kind is stored under. Fixed: a linked attribute cannot be renamed. */
export const TEAM_ATTRIBUTE_KEY: Record<TeamKind, string> = { squad: "squad", tribe: "tribe" };

/**
 * What a write asks for: the full set of squads and tribes the application is assigned to
 * directly. `undefined` for a kind the write did not mention, which leaves it as it is.
 */
export interface TeamAssignments {
  squad?: string[];
  tribe?: string[];
}

/**
 * Reads "payments, storefront" as two names. Blank entries are dropped and repeats collapse
 * without regard to case, so "Payments, payments" is one.
 */
export function parseTeamNames(value: unknown): string[] {
  if (value === null || value === undefined) return [];
  const seen = new Set<string>();
  const names: string[] = [];
  for (const part of String(value).split(",")) {
    const name = part.trim();
    if (name === "" || seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    names.push(name);
  }
  return names;
}

/**
 * Keeps an application's "squad" and "tribe" attributes and its direct squad and tribe
 * assignments saying the same thing.
 *
 * The assignment tables are the source of truth; the attribute is their projection, rewritten
 * from them after every change, from either side. Writing the attribute is translated into
 * assignments first (`resolve`, then `assign`), so a value can never name a squad that does not
 * exist, and a squad granted an application from the squad's own screen shows up in the
 * attribute without anybody typing it.
 *
 * Only direct assignments are mirrored. A squad that reaches an application through a group
 * grant is not listed in its attribute: the attribute means "the teams this application is
 * assigned to", not "everyone who can see it".
 */
export class TeamAttributes {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * Splits linked keys out of a validated attribute patch and turns their names into ids.
   *
   * Unknown names are refused, all of them at once, so a script setting fifty values learns
   * about every typo in one round trip rather than one per run.
   */
  async resolve(
    definitions: readonly AttributeDefinitionRow[],
    validated: Attributes,
  ): Promise<{ plain: Attributes; assignments: TeamAssignments }> {
    const plain: Attributes = { ...validated };
    const assignments: TeamAssignments = {};
    const errors: Record<string, string[]> = {};

    for (const def of definitions) {
      const kind = def.linkedTo;
      if (!kind || !(def.key in validated)) continue;
      delete plain[def.key];

      const names = parseTeamNames(validated[def.key]);
      const { ids, unknown } = await this.idsByName(kind, names);
      if (unknown.length > 0) {
        errors[def.key] = unknown.map(
          (name) =>
            `No ${kind} named "${name}". Create it under Admin → Access → ${kind === "squad" ? "Squads" : "Tribes"} first.`,
        );
        continue;
      }
      assignments[kind] = ids;
    }

    if (Object.keys(errors).length > 0) {
      throw new ValidationError("Some squad or tribe names do not exist", errors);
    }
    return { plain, assignments };
  }

  /** Replaces the application's direct assignments of each kind the write mentioned. */
  async assign(applicationId: string, assignments: TeamAssignments, executor?: Database): Promise<void> {
    const db = executor ?? this.deps.db;
    if (assignments.squad) {
      await db.execute(sql`
        DELETE FROM squad_application
         WHERE application_id = ${applicationId}::uuid
           AND NOT (squad_id = ANY(${sql.param(assignments.squad)}::uuid[]))
      `);
      for (const squadId of assignments.squad) {
        await db.execute(sql`
          INSERT INTO squad_application (squad_id, application_id)
          VALUES (${squadId}::uuid, ${applicationId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    }
    if (assignments.tribe) {
      await db.execute(sql`
        DELETE FROM tribe_application
         WHERE application_id = ${applicationId}::uuid
           AND NOT (tribe_id = ANY(${sql.param(assignments.tribe)}::uuid[]))
      `);
      for (const tribeId of assignments.tribe) {
        await db.execute(sql`
          INSERT INTO tribe_application (tribe_id, application_id)
          VALUES (${tribeId}::uuid, ${applicationId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    }
  }

  /**
   * Rewrites both attributes from the assignment tables for these applications.
   *
   * Called after anything that changes an assignment or a team's name. Cheap enough to run on
   * every such change: it touches only the applications named, and the comparison in the WHERE
   * clause skips rows whose attributes would not change, so an untouched application is not
   * rewritten.
   */
  async refresh(applicationIds: readonly string[], executor?: Database): Promise<void> {
    if (applicationIds.length === 0) return;
    const db = executor ?? this.deps.db;
    await db.execute(sql`
      WITH projected AS (
        SELECT a.id,
               (a.attributes - 'squad' - 'tribe')
                 || COALESCE((
                      SELECT jsonb_build_object('squad', string_agg(s.name, ', ' ORDER BY lower(s.name)))
                        FROM squad_application sa JOIN squad s ON s.id = sa.squad_id
                       WHERE sa.application_id = a.id
                      HAVING count(*) > 0), '{}'::jsonb)
                 || COALESCE((
                      SELECT jsonb_build_object('tribe', string_agg(t.name, ', ' ORDER BY lower(t.name)))
                        FROM tribe_application ta JOIN tribe t ON t.id = ta.tribe_id
                       WHERE ta.application_id = a.id
                      HAVING count(*) > 0), '{}'::jsonb) AS attributes
          FROM application a
         WHERE a.id = ANY(${sql.param([...new Set(applicationIds)])}::uuid[])
      )
      UPDATE application a
         SET attributes = p.attributes
        FROM projected p
       WHERE a.id = p.id AND a.attributes IS DISTINCT FROM p.attributes
    `);
  }

  /** The applications a squad or tribe is assigned to directly: whose attribute names it. */
  async applicationsOf(kind: TeamKind, teamId: string, executor?: Database): Promise<string[]> {
    const db = executor ?? this.deps.db;
    const rows = await db.execute<Row<{ application_id: string }>>(
      kind === "squad"
        ? sql`SELECT application_id FROM squad_application WHERE squad_id = ${teamId}::uuid`
        : sql`SELECT application_id FROM tribe_application WHERE tribe_id = ${teamId}::uuid`,
    );
    return rowsOf(rows).map((r) => r.application_id);
  }

  private async idsByName(
    kind: TeamKind,
    names: readonly string[],
  ): Promise<{ ids: string[]; unknown: string[] }> {
    if (names.length === 0) return { ids: [], unknown: [] };
    const lowered = names.map((n) => n.toLowerCase());
    const rows = await this.deps.db.execute<Row<{ id: string; lname: string }>>(
      kind === "squad"
        ? sql`SELECT id, lower(name) AS lname FROM squad WHERE lower(name) = ANY(${sql.param(lowered)}::text[])`
        : sql`SELECT id, lower(name) AS lname FROM tribe WHERE lower(name) = ANY(${sql.param(lowered)}::text[])`,
    );
    const byName = new Map(rowsOf(rows).map((r) => [r.lname, r.id]));
    return {
      ids: lowered.map((n) => byName.get(n)).filter((id): id is string => id !== undefined),
      unknown: names.filter((n) => !byName.has(n.toLowerCase())),
    };
  }
}
