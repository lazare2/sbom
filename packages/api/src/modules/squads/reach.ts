import { sql } from "drizzle-orm";

/**
 * Every application a squad is given by name, as (squad_id, application_id) rows: the ones
 * granted to the squad itself, and the ones assigned to any tribe the squad sits under.
 *
 * Used in place of a bare squad_application wherever access is decided, so a tribe assignment
 * reaches people through exactly the same paths as a squad's own grant: the application axis,
 * the estates a squad brings with it, the "has any access" test and the reach counts. Groups
 * are separate (squad_group) and are not part of this set.
 *
 * Interpolate it in a FROM clause and give it an alias: ${SQUAD_APPLICATIONS} sa.
 */
export const SQUAD_APPLICATIONS = sql`(
  SELECT squad_id, application_id FROM squad_application
  UNION
  SELECT st.squad_id, ta.application_id
    FROM squad_tribe st
    JOIN tribe_application ta ON ta.tribe_id = st.tribe_id
)`;
