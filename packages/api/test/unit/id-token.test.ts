import { createHmac, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { IdTokenError, verifyIdToken } from "../../src/services/auth/id-token.js";

/**
 * The single check standing between a stranger and a session.
 *
 * Everything before this point narrows *who can reach it*; nothing before it establishes *who
 * they are*. That is decided here, from a signature, and the failure that matters is not a
 * rejected sign-in — it is an accepted one by the wrong person, which looks exactly like an
 * ordinary login in every log this platform keeps.
 *
 * So the cases below are mostly forgeries, and they are signed with real keys rather than
 * mocked: a fake verifier would agree with whatever the test asserted. Each one is a token a
 * provider would never issue, and every one of them has worked against somebody's production
 * system at some point.
 */

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const { privateKey: otherPrivateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

const JWK = { ...publicKey.export({ format: "jwk" }), kid: "key-one", alg: "RS256" };

const ISSUER = "https://login.microsoftonline.com/ff8c7147-558a-4fd9-8f51-f013ef93a9c6/v2.0";
const CLIENT_ID = "11111111-2222-3333-4444-555555555555";
const NONCE = "nonce-for-this-attempt";
const NOW = new Date("2026-10-06T12:00:00Z");

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** Shaped like an Entra ID v2 token, with the claims the verifier actually reads. */
function claims(over: Record<string, unknown> = {}) {
  return {
    iss: ISSUER,
    aud: CLIENT_ID,
    exp: Math.floor(NOW.getTime() / 1000) + 3600,
    iat: Math.floor(NOW.getTime() / 1000) - 60,
    nonce: NONCE,
    oid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    sub: "pairwise-subject-for-this-app",
    preferred_username: "Lazare.Shavgulidze@bog.ge",
    name: "Lazare Shavgulidze",
    tid: "ff8c7147-558a-4fd9-8f51-f013ef93a9c6",
    ...over,
  };
}

function signToken(
  payload: Record<string, unknown>,
  opts: { header?: Record<string, unknown>; key?: typeof privateKey } = {},
) {
  const header = { alg: "RS256", kid: "key-one", typ: "JWT", ...opts.header };
  const input = `${b64(header)}.${b64(payload)}`;
  const signature = cryptoSign("sha256", Buffer.from(input), opts.key ?? privateKey);
  return `${input}.${signature.toString("base64url")}`;
}

const verify = (token: string, over: Partial<Parameters<typeof verifyIdToken>[1]> = {}) =>
  verifyIdToken(token, {
    keys: [JWK],
    issuer: ISSUER,
    clientId: CLIENT_ID,
    nonce: NONCE,
    now: NOW,
    ...over,
  });

const reasonOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    if (error instanceof IdTokenError) return error.reason;
    return `threw ${String(error)}`;
  }
  return "did not throw";
};

describe("accepting a genuine token", () => {
  it("returns the identity it names", () => {
    const identity = verify(signToken(claims()));

    expect(identity.subject).toBe("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    expect(identity.name).toBe("Lazare Shavgulidze");
  });

  it("prefers oid over sub", () => {
    // Entra's `sub` is pairwise -- a different value per application -- while `oid` is the
    // directory object and the same everywhere. Matching on `sub` would silently orphan an
    // account if this platform were ever re-registered as a new application.
    expect(verify(signToken(claims())).subject).toBe("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    expect(verify(signToken(claims({ oid: undefined }))).subject).toBe(
      "pairwise-subject-for-this-app",
    );
  });

  it("falls back to the UPN when the email claim was never granted", () => {
    // `email` arrives only where that claim was consented to and the directory holds one.
    // Without this fallback, a tenant that granted User.Read and nothing else could never
    // match a pre-created account.
    expect(verify(signToken(claims({ email: "Lazare@bog.ge" }))).email).toBe("lazare@bog.ge");
    expect(verify(signToken(claims())).email).toBe("lazare.shavgulidze@bog.ge");
  });

  it("accepts a token whose audience is a list containing this client", () => {
    expect(verify(signToken(claims({ aud: ["someone-else", CLIENT_ID] }))).subject).toBeTruthy();
  });

  it("tolerates a minute of clock drift", () => {
    // A corporate server and a cloud provider disagree by seconds. A token rejected for being
    // one second stale is indistinguishable, to the person signing in, from a broken platform.
    const justExpired = claims({ exp: Math.floor(NOW.getTime() / 1000) - 30 });
    expect(verify(signToken(justExpired)).subject).toBeTruthy();
  });
});

describe("refusing a forgery", () => {
  it("refuses a token with the signature removed", () => {
    // The oldest JWT attack: set alg to none, drop the signature, keep the claims.
    const header = b64({ alg: "none", typ: "JWT" });
    const token = `${header}.${b64(claims())}.`;
    expect(reasonOf(() => verify(token))).toBe("unsupported_algorithm");
  });

  it("refuses a token signed with the provider's public key as an HMAC secret", () => {
    /*
      Key confusion. The verifier is told the algorithm by the token it is verifying; if it
      obeys, an attacker signs with HS256 using the provider's *public* key -- which is public,
      so they have it -- and the signature checks out. The algorithm is matched against a fixed
      list before the key is even looked up, which is why this cannot start working again.
    */
    const header = b64({ alg: "HS256", kid: "key-one", typ: "JWT" });
    const body = `${header}.${b64(claims())}`;
    const pem = publicKey.export({ type: "spki", format: "pem" }) as string;
    const mac = createHmac("sha256", pem).update(body).digest("base64url");

    expect(reasonOf(() => verify(`${body}.${mac}`))).toBe("unsupported_algorithm");
  });

  it("refuses a token signed by a different key", () => {
    expect(reasonOf(() => verify(signToken(claims(), { key: otherPrivateKey })))).toBe(
      "bad_signature",
    );
  });

  it("refuses a correctly signed token with tampered claims", () => {
    const token = signToken(claims());
    const [header, , signature] = token.split(".");
    const swapped = `${header}.${b64(claims({ oid: "somebody-else" }))}.${signature}`;
    expect(reasonOf(() => verify(swapped))).toBe("bad_signature");
  });

  it("refuses a token from another issuer", () => {
    expect(reasonOf(() => verify(signToken(claims({ iss: `${ISSUER}/../other` })))).valueOf()).toBe(
      "wrong_issuer",
    );
  });

  it("refuses a token issued to a different application", () => {
    // Correctly signed, genuinely from the right directory, and not addressed to us. Another
    // application in the same tenant can obtain one of these for its own users.
    expect(reasonOf(() => verify(signToken(claims({ aud: "another-app-in-this-tenant" }))))).toBe(
      "wrong_audience",
    );
  });

  it("refuses a token that answers a different sign-in attempt", () => {
    // Replay. The nonce was minted for one attempt and kept in a cookie the browser returns,
    // so a token captured anywhere else carries the wrong one.
    expect(reasonOf(() => verify(signToken(claims({ nonce: "a-different-attempt" }))))).toBe(
      "wrong_nonce",
    );
    expect(reasonOf(() => verify(signToken(claims({ nonce: undefined }))))).toBe("wrong_nonce");
  });

  it("refuses an expired token", () => {
    const old = claims({ exp: Math.floor(NOW.getTime() / 1000) - 3600 });
    expect(reasonOf(() => verify(signToken(old)))).toBe("expired");
  });

  it("refuses a token naming nobody", () => {
    expect(reasonOf(() => verify(signToken(claims({ oid: undefined, sub: undefined }))))).toBe(
      "no_subject",
    );
  });

  it("refuses something that is not a token at all", () => {
    expect(reasonOf(() => verify("not-a-token"))).toBe("malformed");
    expect(reasonOf(() => verify("a.b.c"))).toBe("malformed");
  });
});

describe("key rotation", () => {
  it("reports an unknown key distinctly, so the caller can refresh and retry", () => {
    // Providers publish new signing keys continuously. A token signed with one minted after
    // the key set was cached is legitimate, and treating it as a bad signature would turn a
    // routine rotation into an outage nobody could explain.
    const token = signToken(claims(), { header: { kid: "key-published-after-we-cached" } });
    expect(reasonOf(() => verify(token, { keys: [JWK] }))).toBe("unknown_key");
  });
});
