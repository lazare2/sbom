import { eq, sql } from "drizzle-orm";
import type { Database } from "../../../db/client.js";
import { user } from "../../../db/schema.js";
import { burnPasswordTiming, hashPassword, needsRehash, verifyPassword } from "../password.js";
import type { AuthContext, AuthCredentials, AuthProvider, AuthResult } from "../provider.js";

/**
 * Email + argon2 password authentication against the local `user` table.
 *
 * Accounts are created by admins only, so this provider never provisions on
 * login. It does own the credential, so it supports both reset and change.
 */
export class LocalPasswordProvider implements AuthProvider {
  readonly name = "local" as const;
  readonly canProvisionOnLogin = false;
  readonly supportsPasswordReset = true;
  readonly supportsPasswordChange = true;

  constructor(private readonly db: Database) {}

  async authenticate(credentials: AuthCredentials, _ctx: AuthContext): Promise<AuthResult> {
    const [row] = await this.db
      .select()
      .from(user)
      .where(sql`lower(${user.email}) = ${credentials.email}`)
      .limit(1);

    // Unknown account and no-password-set both still pay the argon2 cost, so
    // login latency does not reveal which emails have accounts.
    if (!row) {
      await burnPasswordTiming(credentials.password);
      return { ok: false, reason: "invalid_credentials" };
    }

    if (row.authProvider !== "local") {
      return { ok: false, reason: "not_handled" };
    }

    if (!row.passwordHash) {
      await burnPasswordTiming(credentials.password);
      return { ok: false, reason: "password_not_set" };
    }

    const valid = await verifyPassword(row.passwordHash, credentials.password);
    if (!valid) {
      return { ok: false, reason: "invalid_credentials" };
    }

    // Checked after the password, not before: an attacker probing a known-good
    // password should not learn that the account merely got deactivated.
    if (!row.isActive) {
      return { ok: false, reason: "account_inactive" };
    }

    // Opportunistic upgrade if the cost parameters have been raised since this
    // hash was written. Best-effort — a failure here must not fail the login.
    if (needsRehash(row.passwordHash)) {
      try {
        const rehashed = await hashPassword(credentials.password);
        await this.db
          .update(user)
          .set({ passwordHash: rehashed, updatedAt: new Date() })
          .where(eq(user.id, row.id));
        row.passwordHash = rehashed;
      } catch {
        // Ignored on purpose; the user is authenticated either way.
      }
    }

    return { ok: true, user: row };
  }
}
