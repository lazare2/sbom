import type { OidcDiagnosis, OidcDiagnosisCode } from "@sbom/shared";

/**
 * The HTTP conversation with an OpenID Connect provider.
 *
 * Separated from the auth provider that uses it so discovery, key handling and the response
 * translation can each be tested without a network, and so the operational quirks below sit
 * in one place instead of being rediscovered.
 *
 * ## Everything is read from the issuer, nothing is hardcoded
 *
 * Endpoints and signing keys come from `<issuer>/.well-known/openid-configuration`. Writing
 * Entra ID's URLs in here would have worked for exactly one deployment and made the second
 * organisation a code change — and this platform is already shipped as an offline bundle to
 * organisations that configure it themselves.
 *
 * ## Two things that break against corporate infrastructure
 *
 * Every request carries a deadline. On a host whose egress is filtered, a blocked address
 * does not refuse the connection, it swallows it: without a timeout the discovery fetch hangs
 * until the platform's own request timeout, and a sign-in attempt hangs with it. A refusal
 * after ten seconds is a diagnosis; a hang is a mystery.
 *
 * Node's `fetch` does **not** honour `HTTP_PROXY` or `HTTPS_PROXY`. Grype does, because it is
 * a Go binary, which is why those variables exist in the compose file and why an administrator
 * may reasonably expect them to apply here too. They do not, so a deployment that reaches the
 * internet only through a proxy cannot complete sign-on, and `issuer_unreachable` says so
 * rather than leaving somebody to infer it from a timeout.
 */

/** Ten seconds. Long enough for a cold TLS handshake through a corporate firewall, short
 *  enough that a blocked address reports a failure rather than occupying a request. */
const REQUEST_TIMEOUT_MS = 10_000;

/** One hour. Providers rotate signing keys on the order of weeks, and a stale document costs
 *  a failed sign-in that a refresh fixes — so this trades a negligible request for not
 *  pinning a key set that has already been retired. */
const METADATA_TTL_MS = 60 * 60 * 1000;

export interface OidcProviderMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  endSessionEndpoint: string | null;
  /** Whether the provider advertises PKCE with S256. Recorded for the diagnosis; the
   *  challenge is sent regardless, because a provider that ignores it is no worse off. */
  supportsPkceS256: boolean;
}

export class OidcError extends Error {
  constructor(
    message: string,
    readonly code: OidcDiagnosisCode,
    readonly detail: string | null = null,
  ) {
    super(message);
    this.name = "OidcError";
  }
}

export interface OidcClientConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class OidcClient {
  private metadata: { value: OidcProviderMetadata; at: number } | null = null;
  private keys: { value: unknown[]; at: number } | null = null;
  private readonly http: FetchLike;

  constructor(
    private readonly config: OidcClientConfig,
    deps: { fetchImpl?: FetchLike } = {},
  ) {
    this.http = deps.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  /** `<issuer>/.well-known/openid-configuration`, as the spec defines it. */
  get discoveryUrl(): string {
    return `${this.config.issuerUrl.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  }

  private async send(url: string, init?: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await this.http(url, { ...init, signal: controller.signal });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      const aborted = controller.signal.aborted;
      throw new OidcError(
        aborted
          ? `No answer from ${new URL(url).host} within ${REQUEST_TIMEOUT_MS / 1000} seconds.`
          : `Could not reach ${new URL(url).host}.`,
        "issuer_unreachable",
        reason,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * The provider's configuration, cached.
   *
   * The `issuer` in the document is compared against the configured URL and a disagreement is
   * fatal here rather than later. Every token this platform will ever accept carries an `iss`
   * claim that must equal the document's issuer, so a mismatch means no sign-in can ever
   * succeed — and the failure would otherwise surface as "token rejected" on somebody's first
   * attempt, which points at the wrong thing entirely.
   */
  async discover(force = false): Promise<OidcProviderMetadata> {
    if (!force && this.metadata && Date.now() - this.metadata.at < METADATA_TTL_MS) {
      return this.metadata.value;
    }

    const response = await this.send(this.discoveryUrl);
    if (!response.ok) {
      throw new OidcError(
        `The issuer answered ${response.status} for its configuration document.`,
        response.status === 404 ? "issuer_not_oidc" : "issuer_unreachable",
        `GET ${this.discoveryUrl} -> ${response.status}`,
      );
    }

    let doc: Record<string, unknown>;
    try {
      doc = (await response.json()) as Record<string, unknown>;
    } catch {
      throw new OidcError(
        "The issuer answered, but not with an OpenID Connect configuration document.",
        "issuer_not_oidc",
        "response body was not JSON",
      );
    }

    const str = (key: string): string | null =>
      typeof doc[key] === "string" && (doc[key] as string).length > 0 ? (doc[key] as string) : null;

    const issuer = str("issuer");
    const authorizationEndpoint = str("authorization_endpoint");
    const tokenEndpoint = str("token_endpoint");
    const jwksUri = str("jwks_uri");

    const missing = [
      issuer === null ? "issuer" : null,
      authorizationEndpoint === null ? "authorization_endpoint" : null,
      tokenEndpoint === null ? "token_endpoint" : null,
      jwksUri === null ? "jwks_uri" : null,
    ].filter((f): f is string => f !== null);

    if (missing.length > 0) {
      throw new OidcError(
        "That document is missing fields every OpenID Connect provider publishes.",
        "issuer_not_oidc",
        `absent: ${missing.join(", ")}`,
      );
    }

    if (issuer !== this.config.issuerUrl) {
      throw new OidcError(
        "The provider identifies itself by a different URL than the one configured.",
        "issuer_mismatch",
        `configured ${this.config.issuerUrl}, document says ${issuer}`,
      );
    }

    const methods = Array.isArray(doc["code_challenge_methods_supported"])
      ? (doc["code_challenge_methods_supported"] as unknown[])
      : [];

    const value: OidcProviderMetadata = {
      issuer: issuer!,
      authorizationEndpoint: authorizationEndpoint!,
      tokenEndpoint: tokenEndpoint!,
      jwksUri: jwksUri!,
      endSessionEndpoint: str("end_session_endpoint"),
      supportsPkceS256: methods.includes("S256"),
    };
    this.metadata = { value, at: Date.now() };
    return value;
  }

  /** The provider's signing keys, cached alongside the document that named them. */
  async signingKeys(force = false): Promise<unknown[]> {
    if (!force && this.keys && Date.now() - this.keys.at < METADATA_TTL_MS) {
      return this.keys.value;
    }
    const metadata = await this.discover(force);
    const response = await this.send(metadata.jwksUri);
    if (!response.ok) {
      throw new OidcError(
        `The provider answered ${response.status} for its signing keys.`,
        "jwks_unreadable",
        `GET ${metadata.jwksUri} -> ${response.status}`,
      );
    }
    const body = (await response.json().catch(() => null)) as { keys?: unknown } | null;
    const keys = Array.isArray(body?.keys) ? (body!.keys as unknown[]) : null;
    if (!keys || keys.length === 0) {
      throw new OidcError(
        "The provider published no signing keys, so no token from it could be verified.",
        "jwks_unreadable",
        "jwks document contained no keys",
      );
    }
    this.keys = { value: keys, at: Date.now() };
    return keys;
  }

  /**
   * Whether the provider accepts this client id and secret, established with nobody signed in.
   *
   * Asks for a client-credentials grant and ignores whether the grant itself is allowed. Only
   * one thing is being measured: did client authentication pass. A wrong secret is refused as
   * `invalid_client`; a correct secret on an application that holds no application permissions,
   * or on a provider where this grant is disabled, is refused for some other reason. Treating
   * every refusal as a bad secret would tell an administrator to re-issue a credential that
   * was never the problem.
   *
   * No scope is requested, deliberately. A scope would have to be either vendor-specific or
   * meaningless, and the answer this needs arrives before any scope is considered.
   */
  async credentialsAccepted(): Promise<{ accepted: boolean; detail: string | null }> {
    const metadata = await this.discover();
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    const response = await this.send(metadata.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: body.toString(),
    });

    if (response.ok) return { accepted: true, detail: null };

    const payload = (await response.json().catch(() => null)) as
      | { error?: unknown; error_description?: unknown }
      | null;
    const error = typeof payload?.error === "string" ? payload.error : null;
    /*
      Truncated, and only ever the provider's own error text. The secret was in the request
      body; nothing from that body goes into a message that reaches a screen or the error log.
    */
    const description =
      typeof payload?.error_description === "string"
        ? payload.error_description.slice(0, 300)
        : null;

    const rejected = error === "invalid_client" || response.status === 401;
    return {
      accepted: !rejected,
      detail: description ?? error ?? `token endpoint answered ${response.status}`,
    };
  }

  /**
   * One verdict an administrator can act on.
   *
   * `redirectUri` is reported whatever the outcome. A redirect URI the provider does not have
   * registered is the commonest way this integration fails, the provider reports it in the
   * browser where this platform never sees it, and the fix is a string comparison that nobody
   * can make without being shown both strings.
   */
  async diagnose(redirectUri: string): Promise<OidcDiagnosis> {
    const d = await this.diagnoseInner(redirectUri);
    return {
      ...d,
      summary: this.scrub(d.summary),
      hint: this.scrub(d.hint),
      detail: this.scrub(d.detail),
    };
  }

  /**
   * Removes the client secret from anything leaving this class.
   *
   * Not a defence against the ordinary case: the secret travels in a request body, and no
   * normal failure quotes a body back. It is a defence against the fields this code does not
   * author. `detail` carries text from an HTTP client and from the provider, and it is
   * rendered on an admin screen and written to the error log -- so a credential that reaches
   * either has to be re-issued, which needs the directory team. A string replace on every
   * diagnosis is a negligible price for never having that conversation.
   *
   * split/join rather than a regular expression: a secret is arbitrary text and may contain
   * characters that would otherwise need escaping.
   */
  private scrub<T extends string | null>(text: T): T {
    if (text === null || this.config.clientSecret.length === 0) return text;
    return text.split(this.config.clientSecret).join("<redacted>") as T;
  }

  private async diagnoseInner(redirectUri: string): Promise<OidcDiagnosis> {
    const base = {
      redirectUri,
      checkedAt: new Date().toISOString(),
      issuer: null,
      authorizationEndpoint: null,
      tokenEndpoint: null,
      jwksKeyCount: null,
      credentialsAccepted: null,
    };

    try {
      const metadata = await this.discover(true);
      const keys = await this.signingKeys(true);
      const credentials = await this.credentialsAccepted();

      const found = {
        ...base,
        issuer: metadata.issuer,
        authorizationEndpoint: metadata.authorizationEndpoint,
        tokenEndpoint: metadata.tokenEndpoint,
        jwksKeyCount: keys.length,
        credentialsAccepted: credentials.accepted,
      };

      if (!credentials.accepted) {
        return {
          ...found,
          ok: false,
          code: "client_rejected",
          summary: "The provider refused this client id and secret.",
          hint:
            "Check the client id, and that the secret is the value shown once at creation " +
            "rather than the secret id beside it. A secret past its expiry fails this way too.",
          detail: credentials.detail,
        };
      }

      return {
        ...found,
        ok: true,
        code: "ok",
        summary: `Reached ${new URL(metadata.issuer).host} and the credentials were accepted.`,
        hint: `Confirm this exact redirect URI is registered with the provider: ${redirectUri}`,
        detail: credentials.detail,
      };
    } catch (error) {
      if (error instanceof OidcError) {
        return {
          ...base,
          ok: false,
          code: error.code,
          summary: error.message,
          hint: HINTS[error.code] ?? null,
          detail: error.detail,
        };
      }
      return {
        ...base,
        ok: false,
        code: "unknown",
        summary: "The connection test failed for a reason this platform does not recognise.",
        hint: null,
        detail: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

/**
 * What to do about each outcome.
 *
 * Written for somebody who did not configure the provider and cannot see it. The
 * `issuer_unreachable` text names the proxy limitation explicitly because the compose file
 * sets `HTTPS_PROXY` for Grype, which makes it reasonable to assume it applies here as well.
 */
const HINTS: Partial<Record<OidcDiagnosisCode, string>> = {
  issuer_unreachable:
    "The server itself has to reach the provider, not just the browser. Check that outbound " +
    "443 to the issuer's host is open from this machine. Note that an outbound proxy set " +
    "through HTTP_PROXY or HTTPS_PROXY does not apply to this request — those reach Grype " +
    "only. If a provider address has been pinned in docker-compose.override.yml, that address " +
    "may have been withdrawn.",
  issuer_not_oidc:
    "Something answered but it was not a provider. The issuer URL should be the one the " +
    "provider publishes, with no trailing slash — for Entra ID, " +
    "https://login.microsoftonline.com/<tenant-id>/v2.0",
  issuer_mismatch:
    "Use the URL the provider states as its own issuer. Every token carries that value and " +
    "is checked against it, so no sign-in can succeed while the two disagree.",
  jwks_unreadable:
    "The provider was reached but its signing keys were not. If the host is behind a filter " +
    "that allows only some paths, the key endpoint may be blocked while discovery is not.",
  secrets_key_missing:
    "SECRETS_KEY is not set on this deployment, so a client secret cannot be stored. Add it " +
    "to the environment and restart, then save the connection again.",
  not_configured: "Save an issuer URL, client id and client secret first.",
};
