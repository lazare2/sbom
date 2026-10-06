import { createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";

/**
 * Verifying an ID token.
 *
 * This is the only thing standing between a stranger and a session. Everything upstream — the
 * redirect, the state cookie, the code exchange — narrows who can reach this point; nothing
 * upstream establishes *who they are*. That is decided here, from a signature, and a mistake
 * is not a failed sign-in but a silent one by the wrong person.
 *
 * Deliberately takes the key set as an argument rather than fetching it. A verifier that can
 * reach the network is a verifier that can be tested only against the network, and these
 * checks are exactly the ones that have to be exercised against tokens no provider would ever
 * issue.
 *
 * ## The checks, and what each one stops
 *
 * `alg` is matched against a fixed list before anything else. A token asking for `none` is a
 * forgery with the signature removed; one asking for `HS256` is the key-confusion attack,
 * where the provider's *public* key is offered as an HMAC secret — public, so the attacker
 * has it, and so can sign anything. Reading the algorithm out of the token and trusting it is
 * how both succeed.
 *
 * `iss` stops a token from a different tenant, or a different provider entirely, being
 * replayed here. `aud` stops a token this platform was never the audience for: a token issued
 * to some other application in the same directory is correctly signed, genuinely from the
 * right issuer, and still not addressed to us.
 *
 * `nonce` stops replay. The value was minted for one sign-in attempt and stored in a cookie
 * the browser sends back, so a token captured elsewhere carries the wrong one.
 *
 * `exp` stops a token that was all of those things an hour ago.
 */

export type IdTokenFailure =
  | "malformed"
  | "unsupported_algorithm"
  | "unknown_key"
  | "bad_signature"
  | "wrong_issuer"
  | "wrong_audience"
  | "wrong_nonce"
  | "expired"
  | "no_subject";

export class IdTokenError extends Error {
  constructor(
    readonly reason: IdTokenFailure,
    message: string,
  ) {
    super(message);
    this.name = "IdTokenError";
  }
}

/** Who the provider says this is. */
export interface VerifiedIdentity {
  /**
   * The immutable identifier this account is matched on.
   *
   * `oid` where the provider sends one, because Entra's `sub` is pairwise — different per
   * application — while `oid` is the directory object and the same everywhere. Falling back to
   * `sub` keeps providers that publish no `oid` working, and the two never collide because a
   * deployment talks to one issuer.
   */
  subject: string;
  /** Best available address, for matching a pre-created account. May be absent. */
  email: string | null;
  name: string | null;
}

/**
 * Only RSASSA-PKCS1-v1_5. Entra signs with RS256 and this list is an allowlist rather than a
 * blocklist on purpose: a blocklist admits whatever is invented next.
 */
const ALGORITHMS: Record<string, "sha256" | "sha384" | "sha512"> = {
  RS256: "sha256",
  RS384: "sha384",
  RS512: "sha512",
};

/**
 * Sixty seconds.
 *
 * Clocks on a corporate server and at a cloud provider disagree by seconds, and a token
 * rejected for being one second early is indistinguishable to the person signing in from the
 * platform being broken. Wide enough to absorb ordinary drift, far short of the lifetime of
 * anything it would let through.
 */
const CLOCK_SKEW_SECONDS = 60;

interface JwtHeader {
  alg?: unknown;
  kid?: unknown;
}

interface JwtPayload {
  iss?: unknown;
  aud?: unknown;
  exp?: unknown;
  nonce?: unknown;
  oid?: unknown;
  sub?: unknown;
  email?: unknown;
  preferred_username?: unknown;
  name?: unknown;
}

function decodeSegment(segment: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new IdTokenError("malformed", `The token's ${what} is not readable.`);
  }
  if (!parsed || typeof parsed !== "object") {
    throw new IdTokenError("malformed", `The token's ${what} is not an object.`);
  }
  return parsed as Record<string, unknown>;
}

/** Equal-length comparison that does not leak where two values first differ. */
export function safeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export interface VerifyOptions {
  /** The provider's published keys, as JWKs. */
  keys: readonly unknown[];
  /** The issuer from the discovery document, compared exactly. */
  issuer: string;
  /** This deployment's client id, which the token must be addressed to. */
  clientId: string;
  /** The value minted for this sign-in attempt. */
  nonce: string;
  /** Injectable so expiry can be tested without waiting. */
  now?: Date;
}

export function verifyIdToken(token: string, options: VerifyOptions): VerifiedIdentity {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new IdTokenError("malformed", "An ID token has three parts; this does not.");
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  const header = decodeSegment(headerSegment, "header") as JwtHeader;
  const alg = typeof header.alg === "string" ? header.alg : "";
  const hash = ALGORITHMS[alg];
  if (!hash) {
    // Named rather than generic: `none` and `HS256` are attacks, not misconfigurations, and
    // the distinction matters to whoever reads the error log.
    throw new IdTokenError(
      "unsupported_algorithm",
      `The token is signed with "${alg || "nothing"}", which this platform does not accept.`,
    );
  }

  const kid = typeof header.kid === "string" ? header.kid : null;
  const jwk = options.keys.find(
    (candidate) =>
      candidate !== null &&
      typeof candidate === "object" &&
      (kid === null || (candidate as { kid?: unknown }).kid === kid),
  );
  if (!jwk) {
    // Recoverable by the caller: providers rotate keys, and a token signed with one published
    // after the key set was cached is legitimate. The caller refreshes and tries once more.
    throw new IdTokenError("unknown_key", "The token was signed with a key the provider has not published to us.");
  }

  let ok = false;
  try {
    const key = createPublicKey({ key: jwk as Parameters<typeof createPublicKey>[0], format: "jwk" } as never);
    ok = cryptoVerify(
      hash,
      Buffer.from(`${headerSegment}.${payloadSegment}`, "utf8"),
      key,
      Buffer.from(signatureSegment, "base64url"),
    );
  } catch {
    throw new IdTokenError("bad_signature", "The token's signature could not be checked.");
  }
  if (!ok) throw new IdTokenError("bad_signature", "The token's signature does not match.");

  const payload = decodeSegment(payloadSegment, "payload") as JwtPayload;

  if (typeof payload.iss !== "string" || !safeEquals(payload.iss, options.issuer)) {
    throw new IdTokenError("wrong_issuer", "The token was issued by a different provider.");
  }

  // `aud` is a string or an array of them; both are legal and both mean the same thing here.
  const audiences =
    typeof payload.aud === "string"
      ? [payload.aud]
      : Array.isArray(payload.aud)
        ? payload.aud.filter((a): a is string => typeof a === "string")
        : [];
  if (!audiences.some((a) => safeEquals(a, options.clientId))) {
    throw new IdTokenError("wrong_audience", "The token was issued for a different application.");
  }

  if (typeof payload.nonce !== "string" || !safeEquals(payload.nonce, options.nonce)) {
    throw new IdTokenError("wrong_nonce", "The token does not answer this sign-in attempt.");
  }

  const nowSeconds = Math.floor((options.now?.getTime() ?? Date.now()) / 1000);
  if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_SECONDS < nowSeconds) {
    throw new IdTokenError("expired", "The token has expired.");
  }

  const subject =
    typeof payload.oid === "string" && payload.oid !== ""
      ? payload.oid
      : typeof payload.sub === "string" && payload.sub !== ""
        ? payload.sub
        : null;
  if (subject === null) {
    throw new IdTokenError("no_subject", "The token names nobody this platform can match.");
  }

  /*
    `email` is only present when the claim was granted and the directory holds one.
    `preferred_username` is the UPN and is sent regardless, so it is the fallback that keeps
    matching working on a tenant where the email claim was never consented to.
  */
  const email =
    typeof payload.email === "string" && payload.email !== ""
      ? payload.email
      : typeof payload.preferred_username === "string" && payload.preferred_username !== ""
        ? payload.preferred_username
        : null;

  return {
    subject,
    email: email?.toLowerCase() ?? null,
    name: typeof payload.name === "string" && payload.name !== "" ? payload.name : null,
  };
}
