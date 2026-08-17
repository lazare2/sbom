import type { AuthProviderName } from "@sbom/shared";
import type { UserRow } from "../../db/schema.js";

/**
 * THE AUTH ABSTRACTION.
 *
 * Everything above this interface — the login route, session creation, RBAC
 * guards — is provider-agnostic. Adding LDAP later means writing one class that
 * implements `AuthProvider` and registering it; no route, session, or
 * permission code changes.
 *
 * The three capability flags exist because LDAP differs from local passwords in
 * exactly three ways, and each one would otherwise force an `if (ldap)` branch
 * somewhere in the routes:
 *   - it can create a user record on first successful bind (`canProvisionOnLogin`)
 *   - it cannot reset a password we don't own (`supportsPasswordReset`)
 *   - it has no local hash to change (`supportsPasswordChange`)
 */

export interface AuthCredentials {
  /** Already normalised to lowercase by the request schema. */
  email: string;
  password: string;
}

export interface AuthContext {
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

export type AuthFailureReason =
  /** Wrong password, unknown user, or a bind rejection — deliberately not distinguished. */
  | "invalid_credentials"
  /** Credentials were correct but the account is deactivated. */
  | "account_inactive"
  /** Account exists with no password set; the user must complete setup first. */
  | "password_not_set"
  /** This provider does not own the given identity. */
  | "not_handled"
  /** The upstream directory was unreachable. Distinct from a rejection on purpose. */
  | "provider_unavailable";

export type AuthResult =
  | { ok: true; user: UserRow }
  | { ok: false; reason: AuthFailureReason; message?: string };

export interface AuthProvider {
  readonly name: AuthProviderName;

  /**
   * True if this provider may create a local `user` row the first time an
   * identity authenticates successfully. Local password auth: false — accounts
   * are admin-created only. A future LDAP provider: true, so directory members
   * don't each need manual pre-registration.
   */
  readonly canProvisionOnLogin: boolean;

  /** True if this provider owns a credential the app can reset (i.e. local hashes). */
  readonly supportsPasswordReset: boolean;

  /** True if an authenticated user can change their own password through this app. */
  readonly supportsPasswordChange: boolean;

  /**
   * Verify credentials. Must not create a session, set a cookie, or record a
   * login timestamp — the caller owns all of that, which is what keeps session
   * handling identical across providers.
   */
  authenticate(credentials: AuthCredentials, ctx: AuthContext): Promise<AuthResult>;
}

/**
 * Chooses which provider handles a login attempt.
 *
 * Resolution order:
 *   1. If a user row exists, its `auth_provider` column decides. An account
 *      migrated to LDAP keeps working without touching the login route.
 *   2. Otherwise, offer the attempt to each provider that can provision on
 *      login, in configured priority order.
 *   3. If nothing handles it, the caller reports `invalid_credentials` — never
 *      "no such user", which would turn the login form into an account oracle.
 */
export class AuthProviderRegistry {
  private readonly byName = new Map<AuthProviderName, AuthProvider>();
  private readonly order: AuthProvider[] = [];

  register(provider: AuthProvider): this {
    if (this.byName.has(provider.name)) {
      throw new Error(`auth provider "${provider.name}" is already registered`);
    }
    this.byName.set(provider.name, provider);
    this.order.push(provider);
    return this;
  }

  get(name: AuthProviderName): AuthProvider | undefined {
    return this.byName.get(name);
  }

  /** Registered providers in configured priority order. */
  all(): readonly AuthProvider[] {
    return this.order;
  }

  provisioningProviders(): readonly AuthProvider[] {
    return this.order.filter((p) => p.canProvisionOnLogin);
  }

  require(name: AuthProviderName): AuthProvider {
    const provider = this.byName.get(name);
    if (!provider) {
      throw new Error(
        `auth provider "${name}" is not registered; check AUTH_PROVIDERS. ` +
          `A user row references it, so logins for that account cannot be processed.`,
      );
    }
    return provider;
  }
}
