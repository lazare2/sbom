import { eq, sql, type SQL } from "drizzle-orm";
import type {
  CreateUserRequest,
  ListUsersQuery,
  Paginated,
  ResetUserPasswordRequest,
  UpdateUserRequest,
  UserCredentialResponse,
  UserSummary,
  SortDirection,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { user } from "../../db/schema.js";
import { generatePassword } from "../../lib/crypto.js";
import { BadRequestError, ConflictError, isPgError, NotFoundError, PG_UNIQUE_VIOLATION } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
import { hashPassword } from "../auth/password.js";
import type { SessionService } from "../auth/session.service.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "./audit.service.js";

/**
 * Sort clause for the admin users table.
 *
 * `u.id` is the unique tail. Email is unique in the database, but only case-insensitively
 * via an index — `lower(u.email)` is not itself declared unique, so it is not safe to rely
 * on as a total order.
 */
function userOrderBy(sortBy: ListUsersQuery["sortBy"], dir: SortDirection): SQL {
  const dir_ = direction(dir);
  const byEmail = sql`lower(u.email) ASC`;

  switch (sortBy) {
    case "createdAt":
      return orderBy([sql`u.created_at ${dir_}`, byEmail], sql`u.id`);
    case "lastLoginAt":
      // NULLS LAST both ways: never-logged-in is the absence of a login, not the oldest one.
      return orderBy([sql`u.last_login_at ${directionNullsLast(dir)}`, byEmail], sql`u.id`);
    case "role":
      return orderBy([sql`u.role ${dir_}`, byEmail], sql`u.id`);
    case "isActive":
      return orderBy([sql`u.is_active ${dir_}`, byEmail], sql`u.id`);
    case "activeSessions":
      return orderBy(
        [sql`(SELECT count(*) FROM session s WHERE s.user_id = u.id AND s.expires_at > now()) ${dir_}`, byEmail],
        sql`u.id`,
      );
    case "email":
    default:
      return orderBy([sql`lower(u.email) ${dir_}`], sql`u.id`);
  }
}

/**
 * Admin user management.
 *
 * Two invariants are enforced here and nowhere else, both of them about not
 * being able to lock everyone out. With no self-service password reset — user
 * emails are identifiers, not mailboxes — an estate with zero usable admins has
 * no recovery path short of hand-editing the database, so the service refuses
 * to create that state:
 *
 *   1. The last *enabled* admin cannot be deactivated, demoted, or deleted.
 *   2. An admin cannot deactivate or delete their own account, even when
 *      another admin exists. That one is about accidents rather than lockout:
 *      it is the single most common misclick in a user table, and the actor is
 *      by definition mid-session when it happens.
 */
export class AdminUsersService {
  constructor(
    private readonly deps: { db: Database; sessions: SessionService; audit: AuditService },
  ) {}

  async list(query: ListUsersQuery): Promise<Paginated<UserSummary>> {
    const conditions: SQL[] = [sql`TRUE`];

    if (query.search) {
      conditions.push(sql`u.email ILIKE ${"%" + query.search + "%"}`);
    }
    if (query.role) conditions.push(sql`u.role = ${query.role}`);
    if (query.isActive !== undefined) conditions.push(sql`u.is_active = ${query.isActive}`);

    const rows = await this.deps.db.execute<Row<UserQueryRow>>(sql`
      SELECT
        u.id, u.email, u.role, u.auth_provider, u.is_active,
        u.must_change_password, u.last_login_at, u.created_at,
        (
          SELECT count(*) FROM session s
          WHERE s.user_id = u.id AND s.expires_at > now()
        )::int AS active_sessions,
        count(*) OVER () AS total
      FROM "user" u
      WHERE ${sql.join(conditions, sql` AND `)}
      ${userOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    return paginate(rowsOf(rows).map(toUserSummary), totalFromRows(rowsOf(rows)), query);
  }

  async getById(id: string): Promise<UserSummary> {
    const rows = await this.deps.db.execute<Row<UserQueryRow>>(sql`
      SELECT
        u.id, u.email, u.role, u.auth_provider, u.is_active,
        u.must_change_password, u.last_login_at, u.created_at,
        (SELECT count(*) FROM session s WHERE s.user_id = u.id AND s.expires_at > now())::int
          AS active_sessions
      FROM "user" u
      WHERE u.id = ${id}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("User");
    return toUserSummary(row);
  }

  /**
   * Create an account and return its password exactly once.
   *
   * The plaintext is never stored. If the admin loses it before handing it over,
   * the fix is another reset — which is cheap, and far better than a system that
   * can show you a password it should not still know.
   */
  async create(input: CreateUserRequest, actor: Actor): Promise<UserCredentialResponse> {
    const password = input.password ?? generatePassword();
    const passwordHash = await hashPassword(password);

    let created;
    try {
      [created] = await this.deps.db
        .insert(user)
        .values({
          email: input.email,
          role: input.role,
          passwordHash,
          mustChangePassword: input.mustChangePassword,
        })
        .returning();
    } catch (err) {
      // The case-insensitive unique index is the authority, not a prior SELECT:
      // two admins creating the same account concurrently must produce one
      // account and one clean 409, not two rows or a 500.
      if (isPgError(err, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`An account already exists for "${input.email}".`);
      }
      throw err;
    }
    if (!created) throw new Error("insert returned no row");

    await this.deps.audit.record({
      actor,
      action: "user.create",
      targetType: "user",
      targetId: created.id,
      // Never the password, and never its hash.
      metadata: { email: created.email, role: created.role, mustChangePassword: created.mustChangePassword },
    });

    return { user: toUserSummary(rowToQueryRow(created, 0)), temporaryPassword: password };
  }

  async update(id: string, input: UpdateUserRequest, actor: Actor): Promise<UserSummary> {
    const existing = await this.requireUser(id);

    if (input.isActive === false || input.role === "user") {
      await this.assertNotLastAdmin(existing, actor, input);
    }

    const patch: Partial<typeof user.$inferInsert> = { updatedAt: new Date() };
    if (input.role !== undefined) patch.role = input.role;
    if (input.isActive !== undefined) patch.isActive = input.isActive;

    const [updated] = await this.deps.db.update(user).set(patch).where(eq(user.id, id)).returning();
    if (!updated) throw new NotFoundError("User");

    // Deactivation must take effect now, not whenever the cookie happens to
    // expire. This is the reason sessions are server-side rather than JWTs.
    if (input.isActive === false) {
      await this.deps.sessions.revokeAllForUser(id);
    }

    await this.deps.audit.record({
      actor,
      action: "user.update",
      targetType: "user",
      targetId: id,
      metadata: {
        email: updated.email,
        before: { role: existing.role, isActive: existing.isActive },
        after: { role: updated.role, isActive: updated.isActive },
      },
    });

    return this.getById(id);
  }

  /**
   * Issue a new password for someone else's account.
   *
   * Always revokes every session for that user: the reason to reset a password
   * is usually that the old one is compromised or forgotten, and leaving live
   * sessions open would defeat the first case entirely.
   */
  async resetPassword(
    id: string,
    input: ResetUserPasswordRequest,
    actor: Actor,
  ): Promise<UserCredentialResponse> {
    const existing = await this.requireUser(id);

    if (existing.authProvider !== "local") {
      throw new BadRequestError(
        `Passwords for ${existing.authProvider} accounts are managed by that directory, not here.`,
      );
    }

    const password = input.password ?? generatePassword();
    const passwordHash = await hashPassword(password);

    await this.deps.db
      .update(user)
      .set({ passwordHash, mustChangePassword: input.mustChangePassword, updatedAt: new Date() })
      .where(eq(user.id, id));

    const revoked = await this.deps.sessions.revokeAllForUser(id);

    await this.deps.audit.record({
      actor,
      action: "user.reset_password",
      targetType: "user",
      targetId: id,
      metadata: {
        email: existing.email,
        mustChangePassword: input.mustChangePassword,
        generated: input.password === undefined,
        sessionsRevoked: revoked,
      },
    });

    return { user: await this.getById(id), temporaryPassword: password };
  }

  async remove(id: string, actor: Actor): Promise<void> {
    const existing = await this.requireUser(id);
    await this.assertNotLastAdmin(existing, actor, { isActive: false });

    // Recorded before the delete so the actor's own row can still be referenced
    // if an admin ever deletes themselves through a future code path. The audit
    // table's actor FK is ON DELETE SET NULL and `actorEmail` is denormalised,
    // so the trail stays readable either way.
    await this.deps.audit.record({
      actor,
      action: "user.delete",
      targetType: "user",
      targetId: id,
      metadata: { email: existing.email, role: existing.role },
    });

    // `session` cascades on user delete; `audit_log.actor_user_id` nulls out.
    await this.deps.db.delete(user).where(eq(user.id, id));
  }

  // -------------------------------------------------------------------------

  private async requireUser(id: string) {
    const [row] = await this.deps.db.select().from(user).where(eq(user.id, id)).limit(1);
    if (!row) throw new NotFoundError("User");
    return row;
  }

  /**
   * Refuses any change that would leave the estate with no usable admin, and
   * any change an admin makes to their own account's access.
   */
  private async assertNotLastAdmin(
    target: { id: string; role: string; isActive: boolean; email: string },
    actor: Actor,
    change: { role?: "admin" | "user"; isActive?: boolean },
  ): Promise<void> {
    if (target.id === actor.id) {
      throw new BadRequestError(
        "You cannot deactivate, demote, or delete your own account. Ask another administrator.",
      );
    }

    if (target.role !== "admin" || !target.isActive) return;

    const losesAdmin = change.role === "user" || change.isActive === false;
    if (!losesAdmin) return;

    const rows = await this.deps.db.execute<Row<{ count: number | string }>>(sql`
      SELECT count(*)::int AS count FROM "user"
      WHERE role = 'admin' AND is_active = true AND id <> ${target.id}::uuid
    `);
    const remaining = Number(rowsOf(rows)[0]?.count ?? 0);

    if (remaining === 0) {
      throw new BadRequestError(
        `"${target.email}" is the only active administrator. Promote another account first — ` +
          "there is no self-service password recovery, so an estate with no admin cannot be recovered from the UI.",
      );
    }
  }
}

// ---------------------------------------------------------------------------

interface UserQueryRow {
  id: string;
  email: string;
  role: "admin" | "user";
  auth_provider: "local" | "ldap";
  is_active: boolean;
  must_change_password: boolean;
  last_login_at: Date | string | null;
  created_at: Date | string;
  active_sessions: number | string;
  total?: number | string;
}

function toUserSummary(row: UserQueryRow): UserSummary {
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    authProvider: row.auth_provider,
    isActive: row.is_active,
    mustChangePassword: row.must_change_password,
    lastLoginAt: toIso(row.last_login_at),
    activeSessions: Number(row.active_sessions),
    createdAt: toIso(row.created_at)!,
  };
}

/** Adapts a freshly-inserted Drizzle row to the shape the SELECT queries produce. */
function rowToQueryRow(row: typeof user.$inferSelect, activeSessions: number): UserQueryRow {
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    auth_provider: row.authProvider,
    is_active: row.isActive,
    must_change_password: row.mustChangePassword,
    last_login_at: row.lastLoginAt,
    created_at: row.createdAt,
    active_sessions: activeSessions,
  };
}
