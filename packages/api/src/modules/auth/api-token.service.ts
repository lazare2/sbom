import { randomBytes, createHash } from "node:crypto";
import { and, eq, sql } from "drizzle-orm";
import {
  API_TOKEN_SECRET_PREFIX,
  type ApiTokenCreated,
  type ApiTokenScope,
  type ApiTokenSummary,
  type ApiTokenWithOwner,
  type CreateApiToken,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { apiToken, user, type ApiTokenRow, type UserRow } from "../../db/schema.js";
import { ConflictError, isPgError, NotFoundError, PG_UNIQUE_VIOLATION } from "../../lib/errors.js";
import { rowsOf, type Row } from "../../lib/rows.js";
import { toIso } from "../applications/applications.service.js";

/**
 * Minting, listing and revoking personal API tokens, and authenticating with them.
 *
 * The security properties worth stating, because each is a decision rather than a default:
 *
 * **Only the hash is stored.** Same as sessions: a dump of this table cannot be replayed.
 * There is no recovery path for a lost token, only a new one.
 *
 * **The user is resolved on every request, not cached in the token.** `authenticate` joins to
 * the account and returns it, so a deactivated or narrowed account takes effect immediately on
 * every token it owns. Nothing about the account's reach is copied into the row.
 *
 * **Expiry is enforced here, not swept.** A lapsed token stops working at the instant it
 * lapses, because the predicate is part of the lookup rather than a job that runs later.
 */

/** 32 random bytes, base64url, behind a recognisable prefix. */
function mintSecret(): string {
  return `${API_TOKEN_SECRET_PREFIX}${randomBytes(32).toString("base64url")}`;
}

const hashOf = (secret: string): string => createHash("sha256").update(secret).digest("hex");

/**
 * What a token authenticated, when it worked.
 *
 * The account comes back whole rather than as an id, so the caller never has to decide whether
 * to trust a cached copy — there is no cached copy.
 */
export interface AuthenticatedToken {
  tokenId: string;
  tokenName: string;
  scope: ApiTokenScope;
  user: UserRow;
}

export class ApiTokenService {
  constructor(
    private readonly deps: {
      db: Database;
      logger: { warn(obj: unknown, msg?: string): void };
    },
  ) {}

  /**
   * Resolve a bearer string to an account, or null.
   *
   * Null for every failure, deliberately indistinguishable: a revoked token, an expired one,
   * one for a deactivated account and one that never existed all produce the same answer, so
   * that an unauthenticated caller cannot use the difference to learn which of its guesses was
   * once real.
   *
   * The prefix check is a cheap reject, not a security measure — it saves a query and a hash
   * on the garbage that arrives at any public endpoint.
   */
  async authenticate(secret: string): Promise<AuthenticatedToken | null> {
    if (!secret.startsWith(API_TOKEN_SECRET_PREFIX)) return null;

    const rows = await this.deps.db
      .select({ token: apiToken, account: user })
      .from(apiToken)
      .innerJoin(user, eq(user.id, apiToken.userId))
      .where(
        and(
          eq(apiToken.tokenHash, hashOf(secret)),
          sql`${apiToken.revokedAt} IS NULL`,
          sql`(${apiToken.expiresAt} IS NULL OR ${apiToken.expiresAt} > now())`,
          eq(user.isActive, true),
        ),
      )
      .limit(1);

    const found = rows[0];
    if (!found) return null;

    /*
      Recorded but never awaited into the request's critical path, and failures are swallowed.
      "Last used" exists to make tidying up possible; it is not worth failing a request over,
      and a write on every API call is the one part of this that could become a bottleneck.
    */
    void this.deps.db
      .update(apiToken)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiToken.id, found.token.id))
      .catch((error: unknown) => {
        this.deps.logger.warn({ err: error }, "could not stamp api token last-used");
      });

    return {
      tokenId: found.token.id,
      tokenName: found.token.name,
      scope: found.token.scope as ApiTokenScope,
      user: found.account,
    };
  }

  /**
   * Mint one for an account.
   *
   * Returns the plaintext exactly once. The caller is responsible for not logging it, which is
   * why it is a separate field on a distinct return type rather than part of the summary.
   */
  async create(userId: string, input: CreateApiToken): Promise<ApiTokenCreated> {
    const secret = mintSecret();
    const expiresAt =
      input.expiresInDays === null
        ? null
        : new Date(Date.now() + input.expiresInDays * 24 * 60 * 60 * 1000);

    let created: ApiTokenRow | undefined;
    try {
      [created] = await this.deps.db
        .insert(apiToken)
        .values({
          userId,
          name: input.name,
          tokenHash: hashOf(secret),
          // The visible tail, for telling two tokens apart in a list.
          tokenSuffix: secret.slice(-4),
          scope: input.scope,
          expiresAt,
        })
        .returning();
    } catch (error) {
      /*
        The index is the authority rather than a prior SELECT: two tabs submitting the same
        name must produce one token and one readable conflict, not two rows.
      */
      if (isPgError(error, PG_UNIQUE_VIOLATION)) {
        throw new ConflictError(`You already have a token named "${input.name}".`);
      }
      throw error;
    }
    if (!created) throw new Error("insert returned no row");

    return { token: toSummary(created, true), secret };
  }

  /** Every token for one account, newest first. Never the secret. */
  async listForUser(userId: string, accountActive: boolean): Promise<ApiTokenSummary[]> {
    const rows = await this.deps.db
      .select()
      .from(apiToken)
      .where(eq(apiToken.userId, userId))
      .orderBy(sql`${apiToken.createdAt} DESC`);
    return rows.map((row) => toSummary(row, accountActive));
  }

  /**
   * Revoke one, scoped to its owner.
   *
   * `userId` is part of the predicate rather than checked afterwards, so one person cannot
   * revoke another's token by guessing an id — the row simply does not match.
   */
  async revokeForUser(userId: string, tokenId: string): Promise<void> {
    const revoked = await this.deps.db
      .update(apiToken)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(apiToken.id, tokenId),
          eq(apiToken.userId, userId),
          sql`${apiToken.revokedAt} IS NULL`,
        ),
      )
      .returning({ id: apiToken.id });

    // Not a silent success: "I pressed revoke and nothing happened" has to be
    // distinguishable from "it was already revoked".
    if (revoked.length === 0) throw new NotFoundError("API token");
  }

  /** How many of this account's tokens would authenticate a request right now. */
  async activeCountForUser(userId: string): Promise<number> {
    const result = await this.deps.db.execute<Row<{ n: number }>>(sql`
      SELECT count(*)::int AS n
        FROM api_token
       WHERE user_id = ${userId}::uuid
         AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > now())
    `);
    return Number(rowsOf(result)[0]?.n ?? 0);
  }

  /**
   * Every token on the platform, for an administrator.
   *
   * The oversight half of letting people mint their own. Without it, self-service means
   * nobody can answer "how many write tokens exist and who holds them", which is the question
   * that matters after an incident.
   */
  async listAll(): Promise<ApiTokenWithOwner[]> {
    const rows = await this.deps.db
      .select({ token: apiToken, account: user })
      .from(apiToken)
      .innerJoin(user, eq(user.id, apiToken.userId))
      .orderBy(sql`${apiToken.createdAt} DESC`);

    return rows.map(({ token, account }) => ({
      ...toSummary(token, account.isActive),
      userId: account.id,
      userEmail: account.email,
      userRole: account.role,
    }));
  }

  /** Revoke anyone's token. Admin only; the route audits it. */
  async revokeAny(tokenId: string): Promise<ApiTokenWithOwner> {
    const rows = await this.deps.db
      .update(apiToken)
      .set({ revokedAt: new Date() })
      .where(and(eq(apiToken.id, tokenId), sql`${apiToken.revokedAt} IS NULL`))
      .returning();

    const revoked = rows[0];
    if (!revoked) throw new NotFoundError("API token");

    const [account] = await this.deps.db
      .select()
      .from(user)
      .where(eq(user.id, revoked.userId))
      .limit(1);

    return {
      ...toSummary(revoked, account?.isActive ?? false),
      userId: revoked.userId,
      userEmail: account?.email ?? "(deleted)",
      userRole: account?.role ?? "user",
    };
  }

  /** Revoke every token for an account. Used when an account is deactivated or converted. */
  async revokeAllForUser(userId: string): Promise<number> {
    const rows = await this.deps.db
      .update(apiToken)
      .set({ revokedAt: new Date() })
      .where(and(eq(apiToken.userId, userId), sql`${apiToken.revokedAt} IS NULL`))
      .returning({ id: apiToken.id });
    return rows.length;
  }
}

/**
 * Row to summary, computing `active` from the three facts that decide it.
 *
 * `accountActive` is passed in rather than read here because the caller already has the
 * account — and because a token on a deactivated account is refused by `authenticate`'s
 * predicate whatever this says. This is the explanation, not the enforcement.
 */
function toSummary(row: ApiTokenRow, accountActive: boolean): ApiTokenSummary {
  const expired = row.expiresAt !== null && row.expiresAt.getTime() <= Date.now();
  const reason = row.revokedAt !== null
    ? "revoked"
    : expired
      ? "expired"
      : !accountActive
        ? "account_inactive"
        : null;

  return {
    id: row.id,
    name: row.name,
    scope: row.scope as ApiTokenScope,
    tokenSuffix: row.tokenSuffix,
    createdAt: toIso(row.createdAt)!,
    expiresAt: toIso(row.expiresAt),
    lastUsedAt: toIso(row.lastUsedAt),
    revokedAt: toIso(row.revokedAt),
    active: reason === null,
    inactiveReason: reason,
  };
}
