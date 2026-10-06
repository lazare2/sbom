import { sql, type SQL } from "drizzle-orm";
import {
  UNRESTRICTED_APPLICATIONS,
  type ApplicationAccess,
  type ApplicationAccessEmptyGroup,
  type ApplicationAccessEnvironmentGap,
  type ApplicationAccessPreview,
  type PreviewUserApplicationAccess,
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

    /*
      The environment grants ride along on the same round trip, because the figure below is an
      intersection of both axes and reading them separately would double the cost of opening
      the screen. This is a row read, not an access decision -- which estate a request may
      reach is still decided in one place, by `EnvironmentService.permits`.
    */
    const result = await this.deps.db.execute<Row<{ kind: string; id: string }>>(sql`
      SELECT 'group' AS kind, group_id AS id FROM user_group WHERE user_id = ${userId}::uuid
      UNION ALL
      SELECT 'application' AS kind, application_id AS id
        FROM user_application WHERE user_id = ${userId}::uuid
      UNION ALL
      SELECT 'environment' AS kind, environment_id AS id
        FROM user_environment WHERE user_id = ${userId}::uuid
    `);
    const rows = rowsOf(result);
    const groupIds = rows.filter((r) => r.kind === "group").map((r) => r.id);
    const applicationIds = rows.filter((r) => r.kind === "application").map((r) => r.id);
    const environmentIds = rows.filter((r) => r.kind === "environment").map((r) => r.id);

    return {
      restricted,
      groupIds,
      applicationIds,
      visibleApplicationCount: restricted
        ? await this.countVisible({ unrestricted: false, groupIds, applicationIds }, environmentIds)
        : null,
    };
  }

  /**
   * How many applications a grant set actually reaches.
   *
   * Counted rather than added up from the two lists, because a group's members overlap with
   * each other and with directly granted applications. "Three groups and two applications"
   * does not tell an administrator whether they have granted four services or forty.
   *
   * Intersected with the environment grants rather than filtered by the application axis
   * alone. The two axes intersect everywhere a request is served, so applying one here
   * counted applications the account cannot open: an account granted a group whose members
   * all live in an estate it was never given read "reaches 12" while seeing none, and a
   * figure that is wrong in the reassuring direction is worse than no figure.
   */
  private async countVisible(
    access: ApplicationAccess,
    environmentIds: readonly string[],
  ): Promise<number> {
    const result = await this.deps.db.execute<Row<{ n: number | string }>>(
      sql`SELECT count(*)::int AS n
            FROM application a
           WHERE a.environment_id = ANY(${sql.param([...environmentIds])}::uuid[])
             AND ${visibleApplications(access, "a")}`,
    );
    return Number(rowsOf(result)[0]?.n ?? 0);
  }

  /**
   * Scores a candidate grant set without storing it.
   *
   * Takes the environment grants as an argument rather than reading them, so the screen can
   * score ticks the administrator has not saved on either axis. The caller supplies the
   * stored set when only the application axis is being edited.
   *
   * Nothing here writes. The route is a POST only because the candidate does not fit in a
   * query string, and it records no audit row for the same reason.
   */
  async preview(
    input: Pick<PreviewUserApplicationAccess, "restricted" | "groupIds" | "applicationIds">,
    environmentIds: readonly string[],
  ): Promise<ApplicationAccessPreview> {
    const access: ApplicationAccess = input.restricted
      ? {
          unrestricted: false,
          groupIds: [...new Set(input.groupIds)],
          applicationIds: [...new Set(input.applicationIds)],
        }
      : UNRESTRICTED_APPLICATIONS;

    const [reachableApplicationCount, blockedByEnvironment, emptyGroups] = await Promise.all([
      this.countVisible(access, environmentIds),
      /*
        Both lists are empty for an unrestricted account on purpose. It names no applications
        and no groups, so there is nothing for an estate to hold back and no group whose
        emptiness matters -- reporting either would be a warning about a grant nobody made.
      */
      input.restricted
        ? this.environmentGaps(access, environmentIds)
        : Promise.resolve<ApplicationAccessEnvironmentGap[]>([]),
      input.restricted
        ? this.emptyGroups(input.groupIds)
        : Promise.resolve<ApplicationAccessEmptyGroup[]>([]),
    ]);

    return { reachableApplicationCount, blockedByEnvironment, emptyGroups };
  }

  /**
   * Applications the grants name but the environment axis hides, grouped by estate.
   *
   * This is what turns an unexplained zero into an instruction. "Reaches 0 of 12" reads as a
   * broken save; "0, because all 12 are in production and this account has no access to
   * production" names both the cause and the fix.
   *
   * An empty environment list correctly blocks everything, because `= ANY` over an empty
   * array is false and its negation is true -- which is the right answer for an account that
   * has been granted no estates at all.
   */
  private async environmentGaps(
    access: ApplicationAccess,
    environmentIds: readonly string[],
  ): Promise<ApplicationAccessEnvironmentGap[]> {
    const result = await this.deps.db.execute<
      Row<{ environment_id: string; environment_name: string; application_count: number | string }>
    >(
      sql`SELECT e.id AS environment_id, e.name AS environment_name,
                 count(*)::int AS application_count
            FROM application a
            JOIN environment e ON e.id = a.environment_id
           WHERE ${visibleApplications(access, "a")}
             AND NOT (a.environment_id = ANY(${sql.param([...environmentIds])}::uuid[]))
           GROUP BY e.id, e.name
           ORDER BY count(*) DESC, e.name ASC`,
    );
    return rowsOf(result).map((row) => ({
      environmentId: row.environment_id,
      environmentName: row.environment_name,
      applicationCount: Number(row.application_count),
    }));
  }

  /**
   * Granted groups that contain nothing.
   *
   * Worth its own warning because the grant looks identical to a working one on the screen
   * and in the audit trail: a row exists, a name is ticked, and the reach is zero. Without
   * this an administrator investigates permissions when the fix is group membership.
   */
  private async emptyGroups(groupIds: readonly string[]): Promise<ApplicationAccessEmptyGroup[]> {
    if (groupIds.length === 0) return [];
    const result = await this.deps.db.execute<Row<{ group_id: string; name: string }>>(
      sql`SELECT g.id AS group_id, g.name
            FROM application_group g
           WHERE g.id = ANY(${sql.param([...groupIds])}::uuid[])
             AND NOT EXISTS (
               SELECT 1 FROM application_group_member m WHERE m.group_id = g.id
             )
           ORDER BY g.name ASC`,
    );
    return rowsOf(result).map((row) => ({ groupId: row.group_id, name: row.name }));
  }

  /**
   * How many of these ids name something that exists.
   *
   * Counted in one round trip rather than checked one at a time, and returned as counts
   * rather than as the missing ids: the caller only needs to know whether to refuse, and
   * echoing back which ids were unknown would confirm the existence of everything it did
   * not name — a way to probe for group ids by elimination.
   */
  async countKnown(
    groupIds: string[],
    applicationIds: string[],
  ): Promise<{ groups: number; applications: number }> {
    const result = await this.deps.db.execute<Row<{ groups: number; applications: number }>>(sql`
      SELECT
        (SELECT count(*) FROM application_group
          WHERE id = ANY(${sql.param(groupIds)}::uuid[]))::int AS groups,
        (SELECT count(*) FROM application
          WHERE id = ANY(${sql.param(applicationIds)}::uuid[]))::int AS applications
    `);
    const row = rowsOf(result)[0];
    return { groups: Number(row?.groups ?? 0), applications: Number(row?.applications ?? 0) };
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
