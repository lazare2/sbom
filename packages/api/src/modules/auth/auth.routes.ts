import type { FastifyInstance, FastifyReply } from "fastify";
import { changePasswordRequestSchema, loginRequestSchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { toSessionUser } from "./auth.service.js";

/** Strict limits on the endpoints an anonymous caller can hammer. */
const AUTH_RATE_LIMIT = { max: 10, timeWindow: "1 minute" } as const;

export async function authRoutes(fastify: FastifyInstance): Promise<void> {
  const { auth, config, sessions } = fastify.ctx;

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
}
