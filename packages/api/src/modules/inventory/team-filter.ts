import { sql, type SQL } from "drizzle-orm";
import type { TeamFilter } from "@sbom/shared";
import { applicationInScope, type ReadScope } from "../environments/environment.service.js";

/**
 * The squad / tribe / group narrowing as SQL over an `application` alias.
 *
 * `TRUE` when nothing is selected, so every call site interpolates it unconditionally - the same
 * trick the other scope helpers use, which makes a forgotten filter a missing interpolation a
 * reviewer can see rather than a silently wider figure.
 *
 * EXISTS rather than joins: these queries aggregate over applications and their packages, and a
 * join to a membership table would multiply each application by its squad count and inflate
 * every total. Names are compared lower-cased, matching the advisory list's filter.
 */
export function teamPredicate(filter: TeamFilter, alias = "a"): SQL {
  const a = sql.raw(alias);
  const lowered = (values: readonly string[]) =>
    sql`${sql.param(values.map((v) => v.toLowerCase()))}::text[]`;
  const parts: SQL[] = [];

  if (filter.squad.length > 0) {
    parts.push(sql`EXISTS (
      SELECT 1 FROM squad_application tf_sa JOIN squad tf_s ON tf_s.id = tf_sa.squad_id
       WHERE tf_sa.application_id = ${a}.id AND lower(tf_s.name) = ANY(${lowered(filter.squad)}))`);
  }
  if (filter.tribe.length > 0) {
    parts.push(sql`EXISTS (
      SELECT 1 FROM tribe_application tf_ta JOIN tribe tf_t ON tf_t.id = tf_ta.tribe_id
       WHERE tf_ta.application_id = ${a}.id AND lower(tf_t.name) = ANY(${lowered(filter.tribe)}))`);
  }
  if (filter.group.length > 0) {
    parts.push(sql`EXISTS (
      SELECT 1 FROM application_group_member tf_gm JOIN application_group tf_g ON tf_g.id = tf_gm.group_id
       WHERE tf_gm.application_id = ${a}.id AND lower(tf_g.name) = ANY(${lowered(filter.group)}))`);
  }
  return parts.length === 0 ? sql`TRUE` : sql.join(parts, sql` AND `);
}

/**
 * The reader's estate and access, then the team narrowing - in that order and always together.
 *
 * Every Inventory and Analytics aggregate goes through this. Access comes first and is never
 * optional, so a team filter can only ever take applications away.
 */
export function filteredApplications(scope: ReadScope, filter: TeamFilter, alias = "a"): SQL {
  return sql`${applicationInScope(alias, scope)} AND ${teamPredicate(filter, alias)}`;
}
