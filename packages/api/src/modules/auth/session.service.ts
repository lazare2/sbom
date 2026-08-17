import { and, eq, lt, sql } from "drizzle-orm";
import type { Database } from "../../db/client.js";
import { session, user, type SessionRow, type UserRow } from "../../db/schema.js";
import { generateToken, sha256Hex } from "../../lib/crypto.js";
import type { AuthContext } from "./provider.js";

export interface IssuedSession {
  /** The plaintext value to put in the cookie. Never persisted. */
  token: string;
  expiresAt: Date;
}

export interface ActiveSession {
  user: UserRow;
  session: SessionRow;
}

/**
 * Only refresh `last_seen_at` / slide the expiry once per this interval. Without
 * the throttle, every authenticated request would issue a write, which for a
 * dashboard that polls is a lot of WAL for no information gain.
 */
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;

export class SessionService {
  constructor(
    private readonly db: Database,
    private readonly ttlHours: number,
  ) {}

  private expiryFromNow(): Date {
    return new Date(Date.now() + this.ttlHours * 60 * 60 * 1000);
  }

  async create(userId: string, ctx: AuthContext = {}): Promise<IssuedSession> {
    const token = generateToken(32);
    const expiresAt = this.expiryFromNow();
    await this.db.insert(session).values({
      tokenHash: sha256Hex(token),
      userId,
      expiresAt,
      ipAddress: ctx.ipAddress ?? null,
      userAgent: ctx.userAgent?.slice(0, 512) ?? null,
    });
    return { token, expiresAt };
  }

  /**
   * Resolve a cookie value to its user, or null.
   *
   * Joins `user` on every call rather than trusting a claim in the token: this
   * is what makes "admin deactivates a user" take effect on the next request
   * instead of whenever the token would have expired.
   */
  async validate(token: string): Promise<ActiveSession | null> {
    const tokenHash = sha256Hex(token);
    const [row] = await this.db
      .select({ session, user })
      .from(session)
      .innerJoin(user, eq(session.userId, user.id))
      .where(eq(session.tokenHash, tokenHash))
      .limit(1);

    if (!row) return null;

    if (row.session.expiresAt.getTime() <= Date.now()) {
      // Clean up eagerly so an expired cookie doesn't keep costing a lookup.
      await this.revoke(token);
      return null;
    }

    if (!row.user.isActive) {
      await this.revokeAllForUser(row.user.id);
      return null;
    }

    await this.touch(row.session);
    return { user: row.user, session: row.session };
  }

  /**
   * Slide the expiry and refresh `last_seen_at`, at most once per
   * TOUCH_INTERVAL_MS. Rolling expiry keeps a dashboard left open all week from
   * logging the user out mid-task, while an abandoned session still ages out.
   */
  private async touch(current: SessionRow): Promise<void> {
    const since = Date.now() - current.lastSeenAt.getTime();
    if (since < TOUCH_INTERVAL_MS) return;
    const now = new Date();
    const expiresAt = this.expiryFromNow();
    await this.db
      .update(session)
      .set({ lastSeenAt: now, expiresAt })
      .where(eq(session.tokenHash, current.tokenHash));
    current.lastSeenAt = now;
    current.expiresAt = expiresAt;
  }

  async revoke(token: string): Promise<void> {
    await this.db.delete(session).where(eq(session.tokenHash, sha256Hex(token)));
  }

  /**
   * Drop every session for a user. Called on password change/reset and on
   * deactivation, so a compromised or stale credential cannot outlive it.
   */
  async revokeAllForUser(userId: string, opts: { exceptTokenHash?: string } = {}): Promise<number> {
    const predicate = opts.exceptTokenHash
      ? and(eq(session.userId, userId), sql`${session.tokenHash} <> ${opts.exceptTokenHash}`)
      : eq(session.userId, userId);
    const deleted = await this.db.delete(session).where(predicate).returning({ tokenHash: session.tokenHash });
    return deleted.length;
  }

  /** Housekeeping; called on a timer from the server bootstrap. */
  async deleteExpired(): Promise<number> {
    const deleted = await this.db
      .delete(session)
      .where(lt(session.expiresAt, new Date()))
      .returning({ tokenHash: session.tokenHash });
    return deleted.length;
  }
}
