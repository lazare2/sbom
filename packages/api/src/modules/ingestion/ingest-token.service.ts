import { and, desc, eq } from "drizzle-orm";
import type { IngestTokenSummary } from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { ingestToken } from "../../db/schema.js";
import { generateToken, safeCompareHex, sha256Hex, tokenSuffix } from "../../lib/crypto.js";

export interface VerifiedIngestToken {
  /** Named token that authenticated the request, recorded on the scan row. */
  name: string;
  source: "env" | "db";
}

/** Throttle for `last_used_at`: one write per token per minute, not one per scan. */
const LAST_USED_THROTTLE_MS = 60_000;

/**
 * Bearer-token authentication for the CI/CD ingest endpoint.
 *
 * These tokens attest "a trusted CI system is calling", not which application is
 * being reported — application identity comes entirely from the `app_name` form
 * field, per the integration design. That means a leaked token can write a scan
 * for any application name, which is the accepted trade-off for a single
 * group-level CI variable; individually-named tokens exist so the blast radius
 * can be scoped and rotated per environment.
 */
export class IngestTokenService {
  /** Precomputed hashes of the env-configured tokens, so verification is a compare. */
  private readonly envTokenHashes: ReadonlyArray<{ name: string; hash: string }>;
  private readonly lastUsedWrites = new Map<string, number>();

  constructor(
    private readonly deps: { db: Database; config: Config },
  ) {
    this.envTokenHashes = deps.config.INGEST_TOKENS.map((t) => ({
      name: t.name,
      hash: sha256Hex(t.token),
    }));
  }

  /** True when no token is configured anywhere, which the server warns about at boot. */
  hasEnvTokens(): boolean {
    return this.envTokenHashes.length > 0;
  }

  /**
   * Extract a bearer token from an Authorization header.
   *
   * Returns null rather than throwing so the caller decides the status code;
   * a missing and a malformed header are the same 401 to the client.
   */
  static parseBearer(headerValue: string | undefined): string | null {
    if (!headerValue) return null;
    const match = /^Bearer\s+(.+)$/i.exec(headerValue.trim());
    return match?.[1]?.trim() || null;
  }

  async verify(token: string): Promise<VerifiedIngestToken | null> {
    const hash = sha256Hex(token);

    // Env tokens are compared in constant time. The DB path looks the token up
    // by its hash in a unique index instead, which reveals nothing through
    // timing because the hash is what is being matched, not the secret.
    for (const candidate of this.envTokenHashes) {
      if (safeCompareHex(candidate.hash, hash)) {
        return { name: candidate.name, source: "env" };
      }
    }

    const [row] = await this.deps.db
      .select({ id: ingestToken.id, name: ingestToken.name })
      .from(ingestToken)
      .where(and(eq(ingestToken.tokenHash, hash), eq(ingestToken.isActive, true)))
      .limit(1);

    if (!row) return null;

    void this.recordUsage(row.id);
    return { name: row.name, source: "db" };
  }

  /**
   * Best-effort `last_used_at` bookkeeping, throttled and deliberately not
   * awaited by the caller: it is operational nice-to-have, and an ingest must
   * never fail because this write did.
   */
  private async recordUsage(tokenId: string): Promise<void> {
    const now = Date.now();
    const previous = this.lastUsedWrites.get(tokenId) ?? 0;
    if (now - previous < LAST_USED_THROTTLE_MS) return;
    this.lastUsedWrites.set(tokenId, now);
    try {
      await this.deps.db
        .update(ingestToken)
        .set({ lastUsedAt: new Date(now) })
        .where(eq(ingestToken.id, tokenId));
    } catch {
      // Ignored on purpose.
    }
  }

  /**
   * Every token the ingest endpoint would accept, database and environment
   * alike.
   *
   * Env tokens are included deliberately. Listing only the database rows would
   * tell an admin "there are no tokens" on a deployment where CI is
   * authenticating perfectly well through `INGEST_TOKENS`, and the natural next
   * step from that — minting a replacement — is exactly the wrong move.
   */
  async list(): Promise<IngestTokenSummary[]> {
    const rows = await this.deps.db.select().from(ingestToken).orderBy(desc(ingestToken.createdAt));

    const fromDb: IngestTokenSummary[] = rows.map((r) => ({
      id: r.id,
      name: r.name,
      tokenSuffix: r.tokenSuffix,
      isActive: r.isActive,
      source: "db",
      lastUsedAt: r.lastUsedAt?.toISOString() ?? null,
      revokedAt: r.revokedAt?.toISOString() ?? null,
      createdAt: r.createdAt.toISOString(),
    }));

    const fromEnv: IngestTokenSummary[] = this.deps.config.INGEST_TOKENS.map((t) => ({
      id: null,
      name: t.name,
      tokenSuffix: tokenSuffix(t.token),
      isActive: true,
      source: "env",
      lastUsedAt: null,
      revokedAt: null,
      createdAt: null,
    }));

    return [...fromEnv, ...fromDb];
  }

  /**
   * Mint a new named token. The plaintext is returned exactly once — only its
   * hash is stored, so it cannot be recovered afterwards.
   */
  async create(opts: { name: string; createdByUserId?: string | null }): Promise<{ token: string; id: string }> {
    const token = generateToken(32);
    const [row] = await this.deps.db
      .insert(ingestToken)
      .values({
        name: opts.name,
        tokenHash: sha256Hex(token),
        tokenSuffix: tokenSuffix(token),
        createdByUserId: opts.createdByUserId ?? null,
      })
      .returning({ id: ingestToken.id });
    if (!row) throw new Error("failed to create ingest token");
    return { token, id: row.id };
  }

  async revoke(id: string): Promise<boolean> {
    const rows = await this.deps.db
      .update(ingestToken)
      .set({ isActive: false, revokedAt: new Date() })
      .where(eq(ingestToken.id, id))
      .returning({ id: ingestToken.id });
    return rows.length > 0;
  }
}
