import { sql, type SQL } from "drizzle-orm";
import {
  UNRESTRICTED_APPLICATIONS,
  type ApplicationAccess,
  type SetUserApplicationAccess,
  type UserApplicationAccess,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { UserRow } from "../../db/schema.js";
import { rowsOf, type Row } from "../../lib/rows.js";

/**
 * The second access axis: which applications a read-only account may see.
 *
 * Environments decide which estate; this decides how much of that estate. The two are applied
 * together at every site that reads application data, and the reason they are never applied
 * separately is in `ReadScope` — the estate and the viewer's visibility travel as one value
 * so that a query cannot honour one and forget the other.
 *
 * Nothing here restricts an administrator. That is not a shortcut: it is what keeps every
 * admin write path — merges, suppressions, tokens, report delivery — completely outside this
 * feature's blast radius. A narrowing that only ever applies to reads by non-admins cannot
 * corrupt data by being wrong; it can only hide something, which is recoverable.
 */

/**
 * SQL restricting a query to the applications this caller may see.
 *
 * `alias` is the application table's alias at the call site, written as a literal — never
 * user input. The predicate is deliberately a single expression that is valid in every
 * position, including `TRUE`, so a call site interpolates it unconditionally and one that
 * forgot is a compile error rather than a silently unfiltered figure.
 */
export function visibleApplications(access: ApplicationAccess, alias: string): SQL {
  if (access.unrestricted) return sql`TRUE`;

  const a = sql.raw(alias);
  /*
    `sql.param` on both arrays, not a bare `${array}`.

    Drizzle flattens a bare array into one placeholder per element, so `= ANY($3::uuid[])`
    receives a single uuid and Postgres answers "malformed array literal". It typechecks
    perfectly and fails only at runtime, which is exactly how it got shipped last time.

    An empty array is correct here and means no match, which is what a restricted account
    with no grants should see. `= ANY('{}')` is false rather than an error.
  */
  return sql`(
    ${a}.id = ANY(${sql.param(access.applicationIds)}::uuid[])
    OR EXISTS (
      SELECT 1 FROM application_group_member gm
      WHERE gm.application_id = ${a}.id
        AND gm.group_id = ANY(${sql.param(access.groupIds)}::uuid[])
    )
  )`;
}

/**
 * SQL restricting a query over `application_group` to the groups this caller may see.
 *
 * A restricted account must not be offered groups it cannot read: the group list is a filter
 * dropdown and a navigation target, and one that lists a group returning nothing reads as
 * broken data rather than as a permission.
 *
 * Groups reached only through a direct application grant are deliberately NOT included. The
 * account can see that application, not the group — a group whose other members are invisible
 * would report member counts and advisory totals that do not match what the account can open.
 */
export function visibleGroups(access: ApplicationAccess, alias: string): SQL {
  if (access.unrestricted) return sql`TRUE`;
  return sql`${sql.raw(alias)}.id = ANY(${sql.param(access.groupIds)}::uuid[])`;
}

export class ApplicationAccessService {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * What this user may see.
   *
   * Administrators are unrestricted by role rather than by stored rows, so an application or
   * group created after their account was set up is reachable without anybody re-granting it.
   */
  async accessFor(user: UserRow): Promise<ApplicationAccess> {
    if (user.role === "admin") return UNRESTRICTED_APPLICATIONS;
    if (!user.applicationAccessRestricted) return UNRESTRICTED_APPLICATIONS;

    // One round trip for both lists. Two queries to build one predicate would double the
    // cost of every request made by a restricted account.
    const result = await this.deps.db.execute<Row<{ kind: string; id: string }>>(sql`
      SELECT 'group' AS kind, group_id AS id FROM user_group WHERE user_id = ${user.id}::uuid
      UNION ALL
      SELECT 'application' AS kind, application_id AS id
        FROM user_application WHERE user_id = ${user.id}::uuid
    `);

    const rows = rowsOf(result);
    return {
      unrestricted: false,
      groupIds: rows.filter((r) => r.kind === "group").map((r) => r.id),
      applicationIds: rows.filter((r) => r.kind === "application").map((r) => r.id),
    };
  }

  /** The grants stored for one account, whether or not they are currently in force. */
  async forUser(userId: string): Promise<UserApplicationAccess> {
    const flag = await this.deps.db.execute<Row<{ restricted: boolean }>>(
      sql`SELECT application_access_restricted AS restricted FROM "user" WHERE id = ${userId}::uuid`,
    );
    const restricted = rowsOf(flag)[0]?.restricted ?? false;

    const result = await this.deps.db.execute<Row<{ kind: string; id: string }>>(sql`
      SELECT 'group' AS kind, group_id AS id FROM user_group WHERE user_id = ${userId}::uuid
      UNION ALL
      SELECT 'application' AS kind, application_id AS id
        FROM user_application WHERE user_id = ${userId}::uuid
    `);
    const rows = rowsOf(result);
    const groupIds = rows.filter((r) => r.kind === "group").map((r) => r.id);
    const applicationIds = rows.filter((r) => r.kind === "application").map((r) => r.id);

    return {
      restricted,
      groupIds,
      applicationIds,
      visibleApplicationCount: restricted
        ? await this.countVisible({ unrestricted: false, groupIds, applicationIds })
        : null,
    };
  }

  /**
   * How many applications a restricted grant set actually reaches.
   *
   * Counted rather than added up from the two lists, because a group's members overlap with
   * each other and with directly granted applications. "Three groups and two applications"
   * does not tell an administrator whether they have granted four services or forty.
   */
  private async countVisible(access: ApplicationAccess): Promise<number> {
    const result = await this.deps.db.execute<Row<{ n: number | string }>>(
      sql`SELECT count(*)::int AS n FROM application a WHERE ${visibleApplications(access, "a")}`,
    );
    return Number(rowsOf(result)[0]?.n ?? 0);
  }

  /**
   * Replaces an account's grants with exactly this set.
   *
   * One transaction, because the two lists and the flag are one decision. A partial apply —
   * the flag on, the groups not yet written — is an account that can see nothing, and it
   * would sit that way until somebody noticed and reported it as the platform being broken.
   */
  async setForUser(userId: string, input: SetUserApplicationAccess): Promise<void> {
    await this.deps.db.transaction(async (tx) => {
      await tx.execute(
        sql`UPDATE "user" SET application_access_restricted = ${input.restricted},
              updated_at = now()
            WHERE id = ${userId}::uuid`,
      );

      await tx.execute(sql`DELETE FROM user_group WHERE user_id = ${userId}::uuid`);
      for (const groupId of input.groupIds) {
        await tx.execute(sql`
          INSERT INTO user_group (user_id, group_id)
          VALUES (${userId}::uuid, ${groupId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }

      await tx.execute(sql`DELETE FROM user_application WHERE user_id = ${userId}::uuid`);
      for (const applicationId of input.applicationIds) {
        await tx.execute(sql`
          INSERT INTO user_application (user_id, application_id)
          VALUES (${userId}::uuid, ${applicationId}::uuid)
          ON CONFLICT DO NOTHING
        `);
      }
    });
  }
}
