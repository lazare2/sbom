import { eq, sql } from "drizzle-orm";
import type { SessionUser } from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { user, type UserRow } from "../../db/schema.js";
import { ForbiddenError, UnauthorizedError } from "../../lib/errors.js";
import { hashPassword, verifyPassword } from "./password.js";
import { AuthProviderRegistry, type AuthContext, type AuthCredentials } from "./provider.js";
import type { IssuedSession, SessionService } from "./session.service.js";

export interface LoginOutcome {
  user: UserRow;
  session: IssuedSession;
}

export function toSessionUser(row: UserRow): SessionUser {
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    authProvider: row.authProvider,
    mustChangePassword: row.mustChangePassword,
    createdAt: row.createdAt.toISOString(),
  };
}

/**
 * Orchestrates login and password changes on top of whichever `AuthProvider`
 * owns a given identity.
 *
 * All provider-specific behaviour is behind the registry; this class only knows
 * about sessions. That is the seam LDAP plugs into later.
 *
 * There is no self-service password reset. User emails are login identifiers,
 * not mailboxes, so a reset link has nowhere to go — recovery is an admin
 * issuing a new password (see AdminUsersService.resetPassword).
 */
export class AuthService {
  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      providers: AuthProviderRegistry;
      sessions: SessionService;
      logger: { warn(obj: unknown, msg?: string): void; error(obj: unknown, msg?: string): void };
    },
  ) {}

  /**
   * Verify credentials and issue a session.
   *
   * Every failure mode except a deactivated account surfaces as the same generic
   * 401. Telling an anonymous caller "no such user" or "wrong password" turns the
   * login form into a directory of who works here.
   */
  async login(credentials: AuthCredentials, ctx: AuthContext): Promise<LoginOutcome> {
    const { db, providers, sessions } = this.deps;

    const [existing] = await db
      .select({ authProvider: user.authProvider })
      .from(user)
      .where(sql`lower(${user.email}) = ${credentials.email}`)
      .limit(1);

    // An existing row's provider column decides who handles it. Only when there
    // is no row do we offer the attempt to providers that can provision.
    const candidates = existing
      ? [providers.require(existing.authProvider)]
      : providers.provisioningProviders();

    for (const provider of candidates) {
      const result = await provider.authenticate(credentials, ctx);

      if (result.ok) {
        const session = await sessions.create(result.user.id, ctx);
        await db
          .update(user)
          .set({ lastLoginAt: new Date() })
          .where(eq(user.id, result.user.id));
        return { user: result.user, session };
      }

      switch (result.reason) {
        case "not_handled":
          continue;
        case "account_inactive":
          // Worth distinguishing: the credentials were correct, so this is a
          // real user who needs to be told to contact an admin rather than
          // retrying their password.
          throw new ForbiddenError("This account has been deactivated. Contact an administrator.");
        case "password_not_set":
          throw new UnauthorizedError(
            "This account has no password set. Ask an administrator to issue one.",
          );
        case "provider_unavailable":
          this.deps.logger.error({ provider: provider.name }, "auth provider unavailable");
          throw new UnauthorizedError("Authentication is temporarily unavailable. Try again shortly.");
        case "invalid_credentials":
          throw new UnauthorizedError("Invalid email or password");
      }
    }

    // No provider claimed the identity. Same message as a wrong password.
    throw new UnauthorizedError("Invalid email or password");
  }

  async logout(token: string): Promise<void> {
    await this.deps.sessions.revoke(token);
  }

  /**
   * Change the password of an already-authenticated user.
   *
   * Keeps the caller's own session alive and revokes the rest, so changing a
   * password doesn't log you out of the tab you're using but does evict anyone
   * else. Clears `mustChangePassword` — this is the only thing that does, which
   * is what makes the forced-change gate un-skippable.
   */
  async changePassword(opts: {
    userId: string;
    currentPassword: string;
    newPassword: string;
    currentSessionTokenHash?: string;
  }): Promise<void> {
    const { db, providers, sessions } = this.deps;

    const [row] = await db.select().from(user).where(eq(user.id, opts.userId)).limit(1);
    if (!row) throw new UnauthorizedError();

    const provider = providers.get(row.authProvider);
    if (!provider?.supportsPasswordChange) {
      throw new ForbiddenError(
        `Passwords for ${row.authProvider} accounts are not managed by this application.`,
      );
    }

    if (!row.passwordHash || !(await verifyPassword(row.passwordHash, opts.currentPassword))) {
      throw new UnauthorizedError("Current password is incorrect");
    }

    // Rejected rather than silently accepted: re-entering the admin-issued
    // password would clear the flag while leaving the credential someone else
    // has seen in place, which defeats the entire mechanism.
    if (opts.currentPassword === opts.newPassword) {
      throw new ForbiddenError("The new password must be different from the current one.");
    }

    const passwordHash = await hashPassword(opts.newPassword);
    await db
      .update(user)
      .set({ passwordHash, mustChangePassword: false, updatedAt: new Date() })
      .where(eq(user.id, row.id));

    await sessions.revokeAllForUser(
      row.id,
      opts.currentSessionTokenHash ? { exceptTokenHash: opts.currentSessionTokenHash } : {},
    );
  }
}
