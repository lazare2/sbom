import { z } from "zod";

/**
 * Single sign-on against an OpenID Connect provider.
 *
 * Configured by issuer URL rather than by vendor, and every endpoint is read from that
 * issuer's discovery document at `/.well-known/openid-configuration`. Entra ID was the
 * deployment this was written for, and hardcoding its endpoints would have made the second
 * organisation to adopt this platform a code change rather than a settings change — the same
 * reasoning that keeps the provider enum's value `oidc` instead of a vendor name.
 *
 * ## Why this is a settings row and not environment variables
 *
 * Turning sign-on on, correcting a typo in a client id, or replacing an expiring secret all
 * have to be possible without an environment edit and a container restart. Environment
 * variables would also give "is single sign-on enabled" two answers that can disagree, and
 * the environment would win silently.
 *
 * ## Accounts created on first sign-in
 *
 * With `provisionOnSignIn` on, somebody the directory authenticates and this platform has no
 * account for is given one on the spot — a read-only account, narrowed to nothing, in no
 * environment. They can sign in and see that they are in; they cannot see a single application
 * until an administrator grants one or adds them to a squad. That is the line that makes
 * provisioning safe to switch on: the decision about what somebody may *read* is still made by
 * a person, and only the paperwork of creating the row is automated.
 *
 * `allowedEmailDomains` arrived in the same change, as this note always said it had to. The
 * provider decides who can authenticate at all; this narrows which of those people get an
 * account made for them, for the tenant that also holds guests and contractors. Empty means
 * every identity the provider vouches for.
 */

/**
 * The provider's issuer identifier, which is also where its configuration is discovered.
 *
 * For Entra ID this is `https://login.microsoftonline.com/<tenant-id>/v2.0`.
 *
 * https is required, and loopback is the only exception. An issuer reached over plain http
 * would carry the client secret and the authorization code across the network in the clear,
 * and unlike the Xray base URL — where plain http is a real internal deployment this platform
 * has to support — every OIDC provider worth integrating publishes TLS. The exception exists
 * so a developer can run Keycloak on localhost without a certificate.
 */
export const oidcIssuerUrlSchema = z
  .string()
  .trim()
  .min(1, "required")
  .max(500)
  .superRefine((value, ctx) => {
    const fail = (message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });

    let url: URL;
    try {
      url = new URL(value);
    } catch {
      fail("must be a full URL, for example https://login.microsoftonline.com/<tenant-id>/v2.0");
      return;
    }

    const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol !== "https:" && !loopback) {
      fail("must use https — the client secret and authorization code travel over this");
      return;
    }
    if (url.search || url.hash) fail("must not carry a query string or fragment");
    if (url.username || url.password) fail("must not embed credentials");
    /*
      A trailing slash makes the discovery URL contain `//`, which some providers serve and
      others 404. Rejected here rather than trimmed silently, because the issuer is also
      compared byte-for-byte against the `iss` claim of every token, and quietly editing the
      value an administrator typed would make a later mismatch inexplicable.
    */
    if (url.pathname.endsWith("/") && url.pathname !== "/") {
      fail("must not end with a slash");
    }
  });

/**
 * What an administrator submits.
 *
 * The client secret is write-only across the whole API: accepted here, encrypted before
 * storage, never returned by any endpoint. `undefined` on an update means "leave the stored
 * one alone", which is what lets somebody correct a typo in the issuer without pasting the
 * secret again — and is why it is optional rather than defaulted to an empty string.
 */
export const oidcConnectionInputSchema = z.object({
  issuerUrl: oidcIssuerUrlSchema,
  clientId: z.string().trim().min(1, "required").max(200),
  clientSecret: z.string().trim().min(1).max(4000).optional(),
  /**
   * Whether the sign-in button is offered at all.
   *
   * Separate from whether a connection is stored, because the two states differ and the
   * difference is operationally useful: a connection can be configured and tested before
   * anyone is allowed to use it, and can be switched off during an incident without
   * destroying the credential and needing it re-issued.
   */
  enabled: z.boolean().default(false),
  /**
   * The directory group whose members are expected to be able to sign in.
   *
   * Recorded, never enforced — enforcement lives in the provider, where "user assignment
   * required" is configured. It is here because the platform cannot read group membership
   * and nobody can otherwise answer "who is supposed to have access" six months later
   * without going back to the directory team.
   */
  securityGroupName: z.string().trim().max(400).optional(),
  /**
   * When the client secret stops working.
   *
   * Optional because not every provider imposes one, and recorded because the failure it
   * produces is total, silent and dated: sign-in works until the stroke of expiry and then
   * every attempt fails with a rejected client. A date on the screen is the only warning
   * anybody gets.
   */
  secretExpiresOn: z.string().trim().max(40).optional(),
  /**
   * Whether an identity with no account here is given one when it signs in.
   *
   * On by default: the account it creates can reach nothing, so the default costs no exposure
   * and saves every new colleague a round trip through an administrator just to exist. Off
   * restores pre-provisioning, where the refusal goes onto the access-request queue instead.
   */
  provisionOnSignIn: z.boolean().default(true),
  /**
   * Address domains an account may be created for, lowercased, without the `@`.
   *
   * Only consulted when creating. An account that already exists signs in whatever its domain,
   * because an administrator made or kept it on purpose.
   */
  allowedEmailDomains: z
    .array(
      z
        .string()
        .trim()
        .toLowerCase()
        .transform((v) => v.replace(/^@/, ""))
        .pipe(
          z
            .string()
            .min(1)
            .max(253)
            .regex(/^[a-z0-9.-]+$/, "must be a domain such as example.com"),
        ),
    )
    .max(50)
    .default([]),
});
export type OidcConnectionInput = z.infer<typeof oidcConnectionInputSchema>;

/** What the admin screen reads back. Never the secret. */
export interface OidcConnection {
  issuerUrl: string;
  clientId: string;
  /** Whether a secret is stored. The value itself is never returned. */
  clientSecretConfigured: boolean;
  enabled: boolean;
  securityGroupName: string | null;
  secretExpiresOn: string | null;
  provisionOnSignIn: boolean;
  allowedEmailDomains: string[];
}

/**
 * Whether an address may have an account created for it under these domains.
 *
 * Exact domain or a subdomain of it, never a suffix match on the raw string: `evilexample.com`
 * must not pass a list naming `example.com`.
 */
export function emailDomainAllowed(email: string, domains: readonly string[]): boolean {
  if (domains.length === 0) return true;
  const at = email.lastIndexOf("@");
  if (at < 0) return false;
  const domain = email.slice(at + 1).toLowerCase();
  return domains.some((allowed) => domain === allowed || domain.endsWith(`.${allowed}`));
}

export interface OidcSettings {
  connection: OidcConnection | null;
  /** The last diagnosis recorded by a connection test, so the screen opens with a verdict. */
  lastTest: OidcDiagnosis | null;
}

/**
 * The result of testing a connection, shaped like the Xray and SMTP diagnoses for the same
 * reason: the useful part is not the raw error but which of the handful of things went wrong.
 *
 * `redirectUri` is reported even on success. A redirect URI the provider does not have
 * registered is the single most common way an OIDC integration fails, the provider's error
 * for it arrives in the browser rather than here, and the fix is a string comparison nobody
 * can perform without being shown both strings.
 */
export interface OidcDiagnosis {
  ok: boolean;
  code: OidcDiagnosisCode;
  summary: string;
  hint: string | null;
  detail: string | null;
  /** Populated once discovery succeeded, so the screen can show what was actually found. */
  issuer: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  jwksKeyCount: number | null;
  /**
   * Whether the token endpoint accepted the client id and secret.
   *
   * Null when the question could not be reached. Established without a user present by
   * asking for a client-credentials grant: a wrong secret is refused as `invalid_client`,
   * while a correct secret on an app holding no application permissions is refused for a
   * different reason entirely. That distinction is the whole test — it separates "your
   * secret is wrong" from "your secret is fine and this app simply cannot do that", which
   * are the two answers an administrator needs told apart.
   */
  credentialsAccepted: boolean | null;
  /** The exact redirect URI this deployment will send, for comparison with the registered one. */
  redirectUri: string;
  checkedAt: string;
}

export const oidcDiagnosisCodes = [
  "ok",
  /** Nothing stored yet. */
  "not_configured",
  /** SECRETS_KEY is absent, so a secret cannot be encrypted or read back. */
  "secrets_key_missing",
  /** The discovery document could not be fetched: DNS, firewall, proxy, or a dead pinned address. */
  "issuer_unreachable",
  /** Something answered, but not an OIDC discovery document. */
  "issuer_not_oidc",
  /** The document's own `issuer` disagrees with the configured URL, which no token can satisfy. */
  "issuer_mismatch",
  /** The signing keys could not be read, so no token could ever be verified. */
  "jwks_unreadable",
  /** The provider refused the client id or secret. */
  "client_rejected",
  "unknown",
] as const;
export type OidcDiagnosisCode = (typeof oidcDiagnosisCodes)[number];

/** Body for the connection test: absent `connection` means test what is stored. */
export const testOidcConnectionSchema = z.object({
  connection: oidcConnectionInputSchema.optional(),
});
export type TestOidcConnection = z.infer<typeof testOidcConnectionSchema>;

/**
 * The path the provider redirects back to, relative to the deployment's public URL.
 *
 * One constant, used to build the URI sent in the authorization request, the URI reported by
 * the connection test, and the route that receives the redirect. Three separate spellings of
 * this string is the defect the constant exists to prevent: the provider compares it exactly,
 * and a mismatch is rejected in the browser with an error the platform never sees.
 */
export const OIDC_CALLBACK_PATH = "/api/v1/auth/oidc/callback";
