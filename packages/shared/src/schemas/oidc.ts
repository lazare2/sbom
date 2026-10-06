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
 * ## What is deliberately not here
 *
 * No list of permitted email domains. Accounts are created by an administrator before anyone
 * can use them, so an identity the directory authenticates but nobody has provisioned is
 * refused on that basis alone — a domain filter would be a second, weaker gate in front of a
 * stronger one. If just-in-time provisioning is ever added, this is where the filter belongs
 * and it must arrive in the same change.
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
