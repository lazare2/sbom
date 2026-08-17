import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import fp from "fastify-plugin";
import type { UserRow } from "../db/schema.js";
import { sha256Hex } from "../lib/crypto.js";
import { AppError, ForbiddenError, UnauthorizedError } from "../lib/errors.js";

declare module "fastify" {
  interface FastifyInstance {
    /**
     * A valid session only. Does NOT enforce the forced-password-change gate,
     * so it is correct for exactly three routes: whoami, change-password, and
     * logout. Everything else wants `requireAuth`.
     */
    requireSession: preHandlerHookHandler;
    /** requireSession, plus a 403 until any admin-issued password has been changed. */
    requireAuth: preHandlerHookHandler;
    /** requireAuth, plus a 403 unless the user's role is `admin`. */
    requireAdmin: preHandlerHookHandler;
  }
  interface FastifyRequest {
    /** Set by requireAuth. Use `getUser(request)` in handlers for a checked read. */
    currentUser?: UserRow;
    /** Hash of the caller's own session token, so "revoke my other sessions" can skip it. */
    currentSessionTokenHash?: string;
  }
}

/**
 * Reads the authenticated user in a route handler.
 *
 * Throws rather than returning undefined: a handler registered behind
 * `requireAuth` that somehow runs without a user is a routing bug, and it must
 * fail closed instead of treating the request as anonymous.
 */
export function getUser(request: FastifyRequest): UserRow {
  if (!request.currentUser) throw new UnauthorizedError();
  return request.currentUser;
}

/**
 * Distinct code from a plain 403 so the SPA can react without string-matching
 * the message: on seeing it, the client routes to the change-password screen.
 */
export class PasswordChangeRequiredError extends AppError {
  constructor() {
    super({
      statusCode: 403,
      code: "password_change_required",
      message:
        "Your password was issued by an administrator and must be changed before you can continue.",
    });
  }
}

export const authPlugin = fp(
  async (fastify: FastifyInstance) => {
    const { sessions, config } = fastify.ctx;

    async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
      const token = request.cookies[config.SESSION_COOKIE_NAME];
      if (!token) throw new UnauthorizedError();

      const active = await sessions.validate(token);
      if (!active) {
        // Clear the stale cookie so the browser stops sending it on every
        // subsequent request.
        reply.clearCookie(config.SESSION_COOKIE_NAME, { path: "/" });
        throw new UnauthorizedError();
      }

      request.currentUser = active.user;
      request.currentSessionTokenHash = sha256Hex(token);
    }

    /**
     * Enforced server-side rather than only in the UI. An admin-issued password
     * has, by construction, been seen by someone other than its owner — often
     * pasted into a chat — so a session opened with it must not be able to read
     * the estate just by skipping past the client-side redirect.
     */
    async function requireChangedPassword(request: FastifyRequest, reply: FastifyReply): Promise<void> {
      await authenticate(request, reply);
      if (request.currentUser?.mustChangePassword) {
        throw new PasswordChangeRequiredError();
      }
    }

    fastify.decorate("requireSession", authenticate as preHandlerHookHandler);
    fastify.decorate("requireAuth", requireChangedPassword as preHandlerHookHandler);

    fastify.decorate("requireAdmin", (async (request: FastifyRequest, reply: FastifyReply) => {
      await requireChangedPassword(request, reply);
      if (request.currentUser?.role !== "admin") {
        throw new ForbiddenError("This action requires an administrator account.");
      }
    }) as preHandlerHookHandler);
  },
  { name: "auth", dependencies: ["app-context"] },
);
