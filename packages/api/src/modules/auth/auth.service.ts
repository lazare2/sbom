import { eq, sql } from "drizzle-orm";
import { emailDomainAllowed, type SessionUser } from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { user, type UserRow } from "../../db/schema.js";
import { ForbiddenError, UnauthorizedError } from "../../lib/errors.js";
import { hashPassword, verifyPassword } from "./password.js";
import { AuthProviderRegistry, type AuthContext, type AuthCredentials } from "./provider.js";
import type { IssuedSession, SessionService } from "./session.service.js";
import type { VerifiedIdentity } from "../../services/auth/id-token.js";
import type { AccessRequestService } from "./access-request.service.js";
import type { AuditService } from "../admin/audit.service.js";

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
/**
 * Why a directory sign-in did not produce a session.
 *
 * Enumerated rather than thrown, because every one of these ends in a redirect back to the
 * sign-in page and the reason has to survive the round trip as something short and safe to put
 * in a URL.
 */
export type DirectorySignIn =
  | { ok: true; user: UserRow; session: IssuedSession }
  /**
   * Nobody has created an account for this identity.
   *
   * `requested` says whether the refusal made it onto the access-request queue, and the
   * sign-in page needs it to choose between two sentences. One of them tells the person
   * administrators have been notified, and that must not appear when the write failed --
   * somebody told to wait for a notification nobody received waits forever.
   */
  | { ok: false; reason: "no_account"; requested: boolean }
  /**
   * An account exists for this address, but it signs in with a password.
   *
   * Not created over, and not linked automatically: converting an account to the directory
   * discards its password, which is an administrator's decision rather than a side effect of
   * somebody clicking the other button on the sign-in page.
   */
  | { ok: false; reason: "inactive" | "identity_conflict" | "local_account" };

export class AuthService {
  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      providers: AuthProviderRegistry;
      sessions: SessionService;
      /**
       * The queue of directory identities nobody has provisioned.
       *
       * Injected rather than handled by the route, because the two things that touch it are
       * both decided here: which refusal warrants a request, and the successful sign-in that
       * closes one. Splitting those across a route and a service is how the second half gets
       * forgotten and the queue fills with entries that are already dealt with.
       */
      accessRequests: AccessRequestService;
      logger: { warn(obj: unknown, msg?: string): void; error(obj: unknown, msg?: string): void };
      /**
       * Whether a directory identity with no account is given one, and for which domains.
       *
       * Optional, and absent means no: the safe reading of "nobody wired this up" is the
       * pre-provisioning behaviour, where the refusal is queued for an administrator.
       */
      provisioning?: () => Promise<{ enabled: boolean; allowedEmailDomains: string[] }>;
      /** Where a provisioned account is recorded. Optional for the same reason. */
      audit?: Pick<AuditService, "record">;
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

  /**
   * Starts a session for an identity the directory has already authenticated.
   *
   * An identity the provider vouches for is a person who works at the organisation; it is not a
   * person who should see this platform's data, and that difference is the whole access model.
   * So when provisioning is on and nobody has an account for them, one is created that *reaches
   * nothing*: a read-only role, narrowed to no applications, in no environment. They are in, and
   * can see that they are; what they may read is still decided by an administrator granting
   * something or adding them to a squad. With provisioning off, the refusal is queued instead.
   *
   * Matching runs subject first, email second:
   *
   *   - `auth_subject` is the directory's immutable identifier and the authority once it has
   *     been recorded. An address that changes upstream cannot orphan an account matched this
   *     way.
   *   - The email is used once, for the first sign-in to an account an administrator created
   *     by address and nobody has used yet. The subject is bound at that moment, and from then
   *     on the address is irrelevant.
   *
   * An email that matches an account already bound to a *different* subject is refused rather
   * than taken over. That is the shape of a reassigned mailbox -- somebody has left, their
   * address was given to a new joiner -- and silently admitting the new holder to the old
   * account is the worst available outcome.
   */
  async signInWithDirectory(
    identity: VerifiedIdentity,
    ctx: AuthContext,
  ): Promise<DirectorySignIn> {
    const { db, sessions, accessRequests } = this.deps;

    const [bySubject] = await db
      .select()
      .from(user)
      .where(sql`${user.authProvider} = 'oidc' AND ${user.authSubject} = ${identity.subject}`)
      .limit(1);

    let account = bySubject ?? null;

    if (!account && identity.email) {
      const [byEmail] = await db
        .select()
        .from(user)
        .where(sql`${user.authProvider} = 'oidc' AND lower(${user.email}) = ${identity.email}`)
        .limit(1);

      if (byEmail) {
        if (byEmail.authSubject !== null) return { ok: false, reason: "identity_conflict" };

        /*
          Bound only while it is still unbound. Two sign-ins racing on a first login would
          otherwise both write, and the partial unique index would abort one of them with a
          constraint error rather than a refusal anybody can read. The guard makes the loser a
          no-op, and it re-reads to find out which it was.
        */
        const bound = await db
          .update(user)
          .set({ authSubject: identity.subject, updatedAt: new Date() })
          .where(sql`${user.id} = ${byEmail.id} AND ${user.authSubject} IS NULL`)
          .returning();

        account = bound[0] ?? null;
        if (!account) {
          const [after] = await db.select().from(user).where(eq(user.id, byEmail.id)).limit(1);
          if (!after || after.authSubject !== identity.subject) {
            return { ok: false, reason: "identity_conflict" };
          }
          account = after;
        }
      }
    }

    if (!account) {
      const provisioned = await this.provision(identity);
      if (provisioned.outcome === "created") account = provisioned.account;
      else if (provisioned.outcome === "local_account") return { ok: false, reason: "local_account" };
    }

    if (!account) {
      /*
        The directory vouched for this person and this platform has nobody by that identity.

        Queued rather than only refused. Everything up to here verified a token the provider
        signed, so this is a colleague of theirs, not a stranger -- and the old behaviour left
        no trace at all, so whether an administrator ever heard about it depended on the
        refused person speaking up.

        Only this refusal is queued. A deactivated account was switched off by an administrator
        on purpose, and a conflicting identity needs unlinking rather than creating, so listing
        either under a button marked "create account" would invite precisely the wrong action.
      */
      const requested = await accessRequests.record(identity, {
        provider: "oidc",
        reason: "no_account",
      });
      return { ok: false, reason: "no_account", requested };
    }
    if (!account.isActive) return { ok: false, reason: "inactive" };

    const session = await sessions.create(account.id, ctx);
    await db
      .update(user)
      .set({
        lastLoginAt: new Date(),
        /*
          Names fill in only where empty. The directory is the better source on day one, but
          once an administrator has corrected a name -- the split of a display name is a guess --
          the next sign-in must not quietly put the guess back.
        */
        firstName: sql`COALESCE(${user.firstName}, ${identity.givenName})`,
        lastName: sql`COALESCE(${user.lastName}, ${identity.familyName})`,
      })
      .where(eq(user.id, account.id));

    /*
      Whoever got in no longer needs to be on the queue.

      This is what makes the queue drain itself. An administrator who creates the account from
      the queue screen resolves the row directly, but one who creates it from the Users page or
      reactivates a disabled account does not -- and a queue that empties only when somebody
      presses the right button accumulates entries that are already dealt with, which is how a
      triage screen stops being read.
    */
    await accessRequests.resolveOnSignIn({
      provider: "oidc",
      subject: identity.subject,
      userId: account.id,
    });

    return { ok: true, user: account, session };
  }

  /**
   * Creates the account for a directory identity seen for the first time, when that is allowed.
   *
   * Every refusal here is quiet and falls back to the access-request queue, except one. An
   * identity with no address cannot have an account (the address is the identifier), and one
   * outside the allowed domains is not meant to; both are things an administrator may still
   * want to act on, which is what the queue is for. A *local* account already holding the
   * address is different: it needs converting, not creating, and says so.
   *
   * The insert is `ON CONFLICT DO NOTHING` against both unique indexes -- the address and the
   * bound subject -- rather than a check followed by a write. Two first sign-ins racing (two
   * tabs, a double click) would otherwise both pass the check and one would die on the index
   * with a 500 instead of signing in.
   */
  private async provision(
    identity: VerifiedIdentity,
  ): Promise<
    | { outcome: "created"; account: UserRow }
    | { outcome: "local_account" }
    | { outcome: "not_provisioned" }
  > {
    const { db, provisioning, audit, logger } = this.deps;
    const settings = provisioning ? await provisioning() : null;
    if (!settings?.enabled || !identity.email) return { outcome: "not_provisioned" };
    if (!emailDomainAllowed(identity.email, settings.allowedEmailDomains)) {
      return { outcome: "not_provisioned" };
    }

    const inserted = await db
      .insert(user)
      .values({
        email: identity.email,
        firstName: identity.givenName,
        lastName: identity.familyName,
        role: "user",
        authProvider: "oidc",
        authSubject: identity.subject,
        passwordHash: null,
        mustChangePassword: false,
        /*
          Restricted, with no grants and no environments: an account that can sign in and read
          nothing. Unrestricted would be the default for an administrator-created account, and
          here it would hand every colleague who finds the URL the whole of every estate they
          were later given -- the exact outcome the old refusal existed to prevent.
        */
        applicationAccessRestricted: true,
      })
      .onConflictDoNothing()
      .returning();

    const created = inserted[0];
    if (created) {
      try {
        await audit?.record({
          // Nobody: the directory vouched, the platform acted. Recorded so "who let this person
          // in" has an answer -- the setting did, at this moment, for this identity.
          actor: null,
          action: "user.provision",
          targetType: "user",
          targetId: created.id,
          metadata: { email: created.email, provider: "oidc", restricted: true, environments: 0 },
        });
      } catch (error) {
        // The account exists and the person is mid-sign-in; losing the audit row is worse than
        // nothing only if it is silent, so it is logged rather than failing the sign-in.
        logger.warn({ err: error }, "could not audit a provisioned account");
      }
      return { outcome: "created", account: created };
    }

    // Lost a race to a concurrent first sign-in by the same person: use what it created.
    const [bySubject] = await db
      .select()
      .from(user)
      .where(sql`${user.authProvider} = 'oidc' AND ${user.authSubject} = ${identity.subject}`)
      .limit(1);
    if (bySubject) return { outcome: "created", account: bySubject };

    // Otherwise the address belongs to an account the directory lookups above did not match,
    // which can only be one that signs in some other way.
    return { outcome: "local_account" };
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
