import { sql } from "drizzle-orm";
import type { Database } from "../../db/client.js";
import { rowsOf, type Row } from "../../lib/rows.js";
import { SQUAD_APPLICATIONS } from "./reach.js";

/** Whether a person leads any squad at all. */
export async function leadsAnySquad(db: Database, userId: string): Promise<boolean> {
  const rows = await db.execute<Row<{ lead: boolean }>>(sql`
    SELECT EXISTS (SELECT 1 FROM squad_member WHERE user_id = ${userId}::uuid AND is_lead) AS lead
  `);
  return rowsOf(rows)[0]?.lead === true;
}

/**
 * Whether a person is team lead of a squad this application belongs to.
 *
 * "Belongs to" is the same reach a squad grants for reading: its own applications, its tribes'
 * applications, and the members of its groups. A lead of one squad has no say over another
 * squad's projects, whatever else they may read.
 */
export async function isLeadOf(db: Database, userId: string, applicationId: string): Promise<boolean> {
  const rows = await db.execute<Row<{ lead: boolean }>>(sql`
    SELECT EXISTS (
      SELECT 1 FROM squad_member sm
       WHERE sm.user_id = ${userId}::uuid AND sm.is_lead
         AND (EXISTS (SELECT 1 FROM ${SQUAD_APPLICATIONS} sa
                       WHERE sa.squad_id = sm.squad_id AND sa.application_id = ${applicationId}::uuid)
              OR EXISTS (SELECT 1 FROM squad_group sg
                           JOIN application_group_member gm ON gm.group_id = sg.group_id
                          WHERE sg.squad_id = sm.squad_id AND gm.application_id = ${applicationId}::uuid))
    ) AS lead
  `);
  return rowsOf(rows)[0]?.lead === true;
}
