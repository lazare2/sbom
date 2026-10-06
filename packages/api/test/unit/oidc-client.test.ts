import { describe, expect, it, vi } from "vitest";
import { OidcClient } from "../../src/services/auth/oidc-client.js";

/**
 * Talking to an OpenID Connect provider, and telling an administrator what went wrong.
 *
 * Almost everything here is about the diagnosis rather than the happy path, because the happy
 * path announces itself and the failures do not. Three of them look identical from a browser —
 * an unreachable issuer, a wrong client secret, and an issuer URL that disagrees with the
 * provider's own — and all three are reported by the provider in a redirect this platform
 * never sees. If this code cannot tell them apart, nobody can.
 *
 * The guarantee that matters most is negative: the client secret is sent in a request body on
 * every one of these paths, and must never appear in anything shown on a screen or written to
 * the error log.
 *
 * Token verification is not here. It belongs with the sign-in flow and is enforced against the
 * signing keys this fetches, not against anything decided in this file.
 */

const ISSUER = "https://login.microsoftonline.com/ff8c7147-558a-4fd9-8f51-f013ef93a9c6/v2.0";
const SECRET = "s3cret~Value.ThatMustNeverBeEchoed";
const REDIRECT = "https://tvm-sbom.bog.ge/api/v1/auth/oidc/callback";

/** Shaped like what Entra ID actually publishes, trimmed to the fields that are read. */
const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint:
    "https://login.microsoftonline.com/ff8c7147-558a-4fd9-8f51-f013ef93a9c6/oauth2/v2.0/authorize",
  token_endpoint:
    "https://login.microsoftonline.com/ff8c7147-558a-4fd9-8f51-f013ef93a9c6/oauth2/v2.0/token",
  jwks_uri:
    "https://login.microsoftonline.com/ff8c7147-558a-4fd9-8f51-f013ef93a9c6/discovery/v2.0/keys",
  end_session_endpoint:
    "https://login.microsoftonline.com/ff8c7147-558a-4fd9-8f51-f013ef93a9c6/oauth2/v2.0/logout",
  code_challenge_methods_supported: ["plain", "S256"],
  response_types_supported: ["code", "id_token", "code id_token"],
};

const JWKS = { keys: [{ kty: "RSA", kid: "key-one", n: "...", e: "AQAB" }] };

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/**
 * One route table per test, overridden per case. `calls` is kept so caching can be asserted
 * by counting rather than by reaching into the client's private state.
 */
function harness(
  over: {
    discovery?: () => Response;
    jwks?: () => Response;
    token?: () => Response;
    throws?: Error;
  } = {},
) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (url: string) => {
    calls.push(url);
    if (over.throws) throw over.throws;
    if (url.includes(".well-known")) return (over.discovery ?? (() => json(DISCOVERY)))();
    if (url.includes("/discovery/v2.0/keys")) return (over.jwks ?? (() => json(JWKS)))();
    if (url.endsWith("/token")) return (over.token ?? (() => json({ access_token: "a" })))();
    throw new Error(`unexpected request to ${url}`);
  });

  const client = new OidcClient(
    { issuerUrl: ISSUER, clientId: "client-abc", clientSecret: SECRET },
    { fetchImpl: fetchImpl as never },
  );
  return { client, calls, fetchImpl };
}

describe("reading a provider's configuration", () => {
  it("builds the discovery URL the spec defines", () => {
    const { client } = harness();
    expect(client.discoveryUrl).toBe(`${ISSUER}/.well-known/openid-configuration`);
  });

  it("refuses a provider whose stated issuer differs from the configured one", async () => {
    /*
      Fatal here rather than later. Every token carries `iss` and is checked against this
      value, so the two disagreeing means no sign-in can ever succeed -- and the failure would
      otherwise arrive as "token rejected" on somebody's first attempt, which sends the reader
      looking at the token instead of at one character in a URL.
    */
    const { client } = harness({
      discovery: () => json({ ...DISCOVERY, issuer: `${ISSUER}/extra` }),
    });
    const d = await client.diagnose(REDIRECT);

    expect(d.ok).toBe(false);
    expect(d.code).toBe("issuer_mismatch");
    expect(d.detail).toContain(ISSUER);
  });

  it("names the fields a document was missing rather than reporting it as unreachable", async () => {
    const { client } = harness({ discovery: () => json({ issuer: ISSUER }) });
    const d = await client.diagnose(REDIRECT);

    expect(d.code).toBe("issuer_not_oidc");
    expect(d.detail).toContain("token_endpoint");
    expect(d.detail).toContain("jwks_uri");
  });

  it("reports a non-JSON answer as not-a-provider, not as a network failure", async () => {
    const { client } = harness({ discovery: () => new Response("<html>proxy login</html>") });
    const d = await client.diagnose(REDIRECT);

    // A captive proxy answering 200 with HTML is the realistic case, and calling it
    // unreachable would send somebody to the firewall team for a problem that is not theirs.
    expect(d.code).toBe("issuer_not_oidc");
  });

  it("reports an unreachable issuer with a hint that names the proxy limitation", async () => {
    const { client } = harness({ throws: new Error("getaddrinfo ENOTFOUND") });
    const d = await client.diagnose(REDIRECT);

    expect(d.code).toBe("issuer_unreachable");
    // HTTP_PROXY is set in the compose file for Grype, so assuming it applies here is the
    // reasonable wrong conclusion, and the hint has to pre-empt it.
    expect(d.hint).toContain("HTTP_PROXY");
  });

  it("caches the document instead of fetching it per sign-in", async () => {
    const { client, calls } = harness();
    await client.discover();
    await client.discover();
    expect(calls.filter((u) => u.includes(".well-known"))).toHaveLength(1);
  });
});

describe("establishing whether the credentials work, with nobody signed in", () => {
  it("treats invalid_client as a rejected secret", async () => {
    const { client } = harness({
      token: () =>
        json({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret" }, 401),
    });
    const d = await client.diagnose(REDIRECT);

    expect(d.credentialsAccepted).toBe(false);
    expect(d.code).toBe("client_rejected");
    expect(d.hint).toContain("secret id");
  });

  it("treats any other refusal as the credentials being fine", async () => {
    /*
      The load-bearing distinction. This application holds delegated permissions only, so a
      client-credentials grant is refused even when the secret is perfect. Reading every
      refusal as a bad secret would tell an administrator to re-issue a credential that was
      never the problem -- and re-issuing is the one step that needs the directory team.
    */
    for (const error of ["unauthorized_client", "invalid_scope", "unsupported_grant_type"]) {
      const { client } = harness({ token: () => json({ error }, 400) });
      const d = await client.diagnose(REDIRECT);

      expect(d.credentialsAccepted, error).toBe(true);
      expect(d.ok, error).toBe(true);
    }
  });

  it("accepts a grant that simply succeeds", async () => {
    const { client } = harness();
    const d = await client.diagnose(REDIRECT);
    expect(d.ok).toBe(true);
    expect(d.code).toBe("ok");
  });
});

describe("the verdict an administrator reads", () => {
  it("reports the redirect URI whatever the outcome", async () => {
    // The commonest failure in this integration is a redirect URI the provider does not have
    // registered, which it reports in the browser where this platform never sees it. The fix
    // is comparing two strings, and nobody can do that without being shown ours.
    const ok = await harness().client.diagnose(REDIRECT);
    const bad = await harness({ throws: new Error("ECONNREFUSED") }).client.diagnose(REDIRECT);

    expect(ok.redirectUri).toBe(REDIRECT);
    expect(bad.redirectUri).toBe(REDIRECT);
  });

  it("carries what was discovered, so the screen shows what it actually found", async () => {
    const d = await harness().client.diagnose(REDIRECT);

    expect(d.issuer).toBe(ISSUER);
    expect(d.tokenEndpoint).toBe(DISCOVERY.token_endpoint);
    expect(d.jwksKeyCount).toBe(1);
  });

  it("never echoes the client secret, on any path", async () => {
    const cases = [
      harness(),
      harness({ throws: new Error(`connect failed while sending ${SECRET}`) }),
      harness({ token: () => json({ error: "invalid_client", error_description: SECRET }, 401) }),
      harness({ discovery: () => json({ ...DISCOVERY, issuer: "https://elsewhere.example/v2" }) }),
    ];

    for (const { client } of cases) {
      const d = await client.diagnose(REDIRECT);
      // Every field that reaches a screen or the error log, including the ones fed directly
      // from the provider's own error text.
      expect(JSON.stringify(d)).not.toContain(SECRET);
    }
  });
});
