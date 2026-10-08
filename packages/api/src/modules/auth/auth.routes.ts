import { createHash, randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import { changePasswordRequestSchema, loginRequestSchema, OIDC_CALLBACK_PATH } from "@sbom/shared";
import { OidcClient } from "../../services/auth/oidc-client.js";
import { IdTokenError, safeEquals, verifyIdToken } from "../../services/auth/id-token.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { toSessionUser } from "./auth.service.js";

/** Strict limits on the endpoints an anonymous caller can hammer. */
const AUTH_RATE_LIMIT = { max: 10, timeWindow: "1 minute" } as const;

export async function authRoutes(fastify: FastifyInstance): Promise<void> {
  const { auth, config, sessions, settings } = fastify.ctx;

  function setSessionCookie(reply: FastifyReply, token: string, expiresAt: Date): void {
    reply.setCookie(config.SESSION_COOKIE_NAME, token, {
      httpOnly: true,
      // Set only over https, so a local http deployment still works while a
      // real one never sends the cookie in the clear.
      secure: config.cookieSecure,
      // `lax` rather than `strict`: strict drops the cookie on any inbound
      // navigation from another origin, including a link to an application page
      // pasted into a ticket or a chat client. Cross-site POSTs are still
      // blocked, which is the protection that matters here.
      sameSite: "lax",
      path: "/",
      expires: expiresAt,
    });
  }

  // -------------------------------------------------------------------------
  // Login / logout / whoami
  // -------------------------------------------------------------------------

  fastify.post("/login", { config: { rateLimit: AUTH_RATE_LIMIT } }, async (request, reply) => {
    const body = parseOrThrow(loginRequestSchema, request.body);

    const outcome = await auth.login(body, {
      ipAddress: request.ip,
      userAgent: request.headers["user-agent"],
    });

    setSessionCookie(reply, outcome.session.token, outcome.session.expiresAt);
    return reply.send({ user: toSessionUser(outcome.user) });
  });

  fastify.post("/logout", async (request, reply) => {
    const token = request.cookies[config.SESSION_COOKIE_NAME];
    if (token) await auth.logout(token);
    reply.clearCookie(config.SESSION_COOKIE_NAME, { path: "/" });
    // 204 whether or not a session existed — logging out is idempotent.
    return reply.status(204).send();
  });

  /**
   * Behind `requireAuth`, not `requireActiveUser`: a user who must change their
   * password still needs to read their own identity, or the client cannot tell
   * why it is being refused everywhere else.
   */
  fastify.get("/me", { preHandler: fastify.requireSession }, async (request, reply) => {
    return reply.send({ user: toSessionUser(getUser(request)) });
  });

  // -------------------------------------------------------------------------
  // Change own password
  // -------------------------------------------------------------------------

  /**
   * Also behind plain `requireAuth`, for the same reason: this is the one route
   * a must-change-password user is allowed to reach, because it is the only way
   * to clear the flag.
   */
  fastify.post(
    "/change-password",
    { preHandler: fastify.requireSession, config: { rateLimit: AUTH_RATE_LIMIT } },
    async (request, reply) => {
      const body = parseOrThrow(changePasswordRequestSchema, request.body);
      const user = getUser(request);

      await auth.changePassword({
        userId: user.id,
        currentPassword: body.currentPassword,
        newPassword: body.newPassword,
        ...(request.currentSessionTokenHash
          ? { currentSessionTokenHash: request.currentSessionTokenHash }
          : {}),
      });

      return reply.send({ message: "Password changed. Other sessions have been signed out." });
    },
  );

  // -------------------------------------------------------------------------
  // Session management
  // -------------------------------------------------------------------------

  /** Sign out everywhere, including the caller. Useful after a suspected compromise. */
  fastify.post("/logout-all", { preHandler: fastify.requireSession }, async (request, reply) => {
    const user = getUser(request);
    const revoked = await sessions.revokeAllForUser(user.id);
    reply.clearCookie(config.SESSION_COOKIE_NAME, { path: "/" });
    return reply.send({ revoked });
  });

  // -------------------------------------------------------------------------
  // Single sign-on
  // -------------------------------------------------------------------------

  /**
   * Everything the callback needs to trust what comes back, kept in one short-lived cookie.
   *
   * A cookie rather than a database row: an abandoned sign-in is the common case -- somebody
   * clicks the button and closes the tab -- and a row would need a sweeper to clear what it
   * leaves behind. The cookie is signed with SESSION_SECRET, so a client cannot mint one, and
   * it is scoped to this path so it is not sent with every other request on the site.
   *
   * `sameSite: lax` is load-bearing and `strict` would break this outright: the request that
   * must carry this cookie is a top-level navigation *from the provider's domain*, and strict
   * withholds it on exactly that. The failure is a sign-in that always reports a bad state
   * parameter, which reads as an attack rather than a cookie policy.
   */
  const OIDC_TX_COOKIE = "sbom_oidc_tx";

  /** Ten minutes. Long enough to type a password and answer an MFA prompt; short enough that
   *  an abandoned attempt cannot be resumed from a shared machine an hour later. */
  const OIDC_TX_TTL_SECONDS = 600;

  /** Where a refusal lands. The code is short and fixed so it can go in a URL safely; the
   *  detail stays in the error log rather than being handed to the browser. */
  const signInFailure = (reply: FastifyReply, code: string): FastifyReply =>
    reply.redirect(`/login?sso=${encodeURIComponent(code)}`, 302);

  const redirectUri = (): string =>
    `${config.PUBLIC_URL.replace(/\/+$/, "")}${OIDC_CALLBACK_PATH}`;

  /**
   * Whether to offer the button, readable without a session.
   *
   * A boolean and nothing else. The sign-in page has to render before anybody is
   * authenticated, so this is necessarily anonymous -- which is why it says only that the
   * feature is on, never the issuer, the client id, or anything else an unauthenticated
   * caller could learn about the directory behind it.
   */
  fastify.get("/oidc/enabled", async (_request, reply) => {
    return reply.send({ enabled: await settings.oidcEnabled() });
  });

  fastify.get("/oidc/start", { config: { rateLimit: AUTH_RATE_LIMIT } }, async (request, reply) => {
    if (!(await settings.oidcEnabled())) return signInFailure(reply, "disabled");
    const clientConfig = await settings.oidcClientConfig();
    if (!clientConfig) return signInFailure(reply, "disabled");

    let metadata;
    try {
      metadata = await new OidcClient(clientConfig).discover();
    } catch (error) {
      /*
        Logged here, and the detail is still kept out of the URL -- the person signing in
        needs to know who to ask, not what the provider said about a redirect URI.

        But it has to be written down somewhere, and for a long time it was not. This refusal
        was the one failure on the whole sign-on path that left no trace at all: the browser
        showed "this server could not reach your organisation's sign-in service" and an
        administrator opening the error log found nothing, because nothing had been recorded.
        Diagnosing it meant reproducing it by hand from inside the container. The Authentication
        tab's test button produces a fuller account on demand; this is the line that says it
        happened to somebody, and when.
      */
      request.log.warn(
        { err: error, issuer: clientConfig.issuerUrl },
        "could not reach the sign-on provider to start a sign-in",
      );
      return signInFailure(reply, "provider_unreachable");
    }

    const state = randomBytes(32).toString("base64url");
    const nonce = randomBytes(32).toString("base64url");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    reply.setCookie(OIDC_TX_COOKIE, JSON.stringify({ state, nonce, verifier }), {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: "lax",
      signed: true,
      path: "/api/v1/auth/oidc",
      maxAge: OIDC_TX_TTL_SECONDS,
    });

    const authorize = new URL(metadata.authorizationEndpoint);
    authorize.searchParams.set("client_id", clientConfig.clientId);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("redirect_uri", redirectUri());
    authorize.searchParams.set("response_mode", "query");
    authorize.searchParams.set("scope", "openid profile email");
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("nonce", nonce);
    authorize.searchParams.set("code_challenge", challenge);
    authorize.searchParams.set("code_challenge_method", "S256");

    return reply.redirect(authorize.toString(), 302);
  });

  fastify.get("/oidc/callback", { config: { rateLimit: AUTH_RATE_LIMIT } }, async (request, reply) => {
    const query = (request.query ?? {}) as Record<string, unknown>;

    // The transaction is single-use whatever happens next, so it is cleared before anything
    // can fail and leave it replayable.
    const raw = request.cookies[OIDC_TX_COOKIE];
    reply.clearCookie(OIDC_TX_COOKIE, { path: "/api/v1/auth/oidc" });

    if (typeof query.error === "string") {
      request.log.warn({ oidcError: query.error }, "provider refused the sign-in");
      return signInFailure(reply, "provider_refused");
    }

    if (typeof raw !== "string") return signInFailure(reply, "expired");
    const unsigned = fastify.unsignCookie(raw);
    if (!unsigned.valid || unsigned.value === null) return signInFailure(reply, "expired");

    let tx: { state?: unknown; nonce?: unknown; verifier?: unknown };
    try {
      tx = JSON.parse(unsigned.value) as typeof tx;
    } catch {
      return signInFailure(reply, "expired");
    }
    if (
      typeof tx.state !== "string" ||
      typeof tx.nonce !== "string" ||
      typeof tx.verifier !== "string"
    ) {
      return signInFailure(reply, "expired");
    }

    /*
      The state check is what makes this redirect belong to the person holding this browser.
      Without it, an attacker completes a sign-in with their own authorization code in
      somebody else's session -- the victim ends up logged in as the attacker, and everything
      they then upload goes to the attacker's account.
    */
    if (typeof query.state !== "string" || !safeEquals(query.state, tx.state)) {
      request.log.warn("sign-in state did not match the browser's");
      return signInFailure(reply, "bad_state");
    }

    if (typeof query.code !== "string" || query.code === "") {
      return signInFailure(reply, "no_code");
    }

    const clientConfig = await settings.oidcClientConfig();
    if (!clientConfig || !(await settings.oidcEnabled())) {
      return signInFailure(reply, "disabled");
    }

    const client = new OidcClient(clientConfig);
    let idToken: string;
    try {
      const metadata = await client.discover();
      const response = await fetch(metadata.tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: query.code,
          redirect_uri: redirectUri(),
          client_id: clientConfig.clientId,
          client_secret: clientConfig.clientSecret,
          code_verifier: tx.verifier,
        }).toString(),
      });

      const payload = (await response.json().catch(() => null)) as
        | { id_token?: unknown; error?: unknown; error_description?: unknown }
        | null;

      if (!response.ok || typeof payload?.id_token !== "string") {
        /*
          Logged, never redirected. The provider's text here routinely names the redirect URI
          and the application, which belongs in the error log an administrator reads -- not in
          a query string the person signing in can see and screenshot.
        */
        request.log.warn(
          { status: response.status, oidcError: payload?.error },
          "the provider would not exchange the authorization code",
        );
        return signInFailure(reply, "exchange_failed");
      }
      idToken = payload.id_token;
    } catch (error) {
      // Same gap as in /oidc/start, and the more confusing half of it: discovery can succeed
      // from this server while the token endpoint is unreachable, which looks to the person
      // signing in like a provider that half works.
      request.log.warn(
        { err: error, issuer: clientConfig.issuerUrl },
        "could not reach the sign-on provider to exchange the authorization code",
      );
      return signInFailure(reply, "provider_unreachable");
    }

    const metadata = await client.discover();
    let identity;
    try {
      try {
        identity = verifyIdToken(idToken, {
          keys: await client.signingKeys(),
          issuer: metadata.issuer,
          clientId: clientConfig.clientId,
          nonce: tx.nonce,
        });
      } catch (error) {
        // One retry, and only for a key this platform has not seen. Providers publish new
        // signing keys continuously, and a cached set would otherwise turn a routine rotation
        // into an outage that clears itself hours later for no visible reason.
        if (error instanceof IdTokenError && error.reason === "unknown_key") {
          identity = verifyIdToken(idToken, {
            keys: await client.signingKeys(true),
            issuer: metadata.issuer,
            clientId: clientConfig.clientId,
            nonce: tx.nonce,
          });
        } else {
          throw error;
        }
      }
    } catch (error) {
      const reason = error instanceof IdTokenError ? error.reason : "unknown";
      request.log.warn({ reason }, "the provider's token was refused");
      return signInFailure(reply, "token_rejected");
    }

    const outcome = await auth.signInWithDirectory(identity, {
      ipAddress: request.ip,
      userAgent: request.headers["user-agent"],
    });

    if (!outcome.ok) {
      /*
        Two codes for one refusal, because they make different promises.

        A refused identity is normally queued for an administrator, and the sign-in page says
        so -- which is worth saying, since it turns "ask an administrator" into "somebody
        already knows". But the write can fail, and then that sentence would be false and the
        person would wait for a notification nobody received. So the stronger wording is used
        only when there is actually a request on the queue.
      */
      if (outcome.reason === "no_account") {
        return signInFailure(reply, outcome.requested ? "no_account_requested" : "no_account");
      }
      return signInFailure(reply, outcome.reason);
    }

    setSessionCookie(reply, outcome.session.token, outcome.session.expiresAt);
    return reply.redirect("/", 302);
  });
}

