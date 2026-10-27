import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import fp from "fastify-plugin";
import { API_TOKEN_PREFIX, type ApiTokenScope } from "@sbom/shared";
import type { UserRow } from "../db/schema.js";
import { sha256Hex } from "../lib/crypto.js";
import { AppError, ForbiddenError, UnauthorizedError } from "../lib/errors.js";
import { isReadOnlyRequest } from "../modules/auth/token-scope.js";

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
    /**
     * Set instead of `currentSessionTokenHash` when a personal API token authenticated this
     * request, rather than a browser session.
     *
     * Present so three things can tell the difference: the scope gate below, which refuses a
     * write to a read-only token; the audit trail, which records the token's name so a write
     * made by a leaked credential is distinguishable from one its owner made; and the session
     * routes, which have nothing to revoke for a token-authenticated caller.
     */
    apiToken?: { id: string; name: string; scope: ApiTokenScope };
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

/**
 * A read-only token tried to change something.
 *
 * Its own code so a client can tell it apart from an ordinary permission failure: the fix is a
 * different token, not different access, and "forbidden" alone sends people to an
 * administrator who cannot help them.
 */
export class TokenScopeError extends AppError {
  constructor() {
    super({
      statusCode: 403,
      code: "token_read_only",
      message:
        "This API token is read-only. Mint a token with write access from the API access page, " +
        "or use one you already have.",
    });
  }
}

export const authPlugin = fp(
  async (fastify: FastifyInstance) => {
    const { sessions, config, apiTokens } = fastify.ctx;

    /**
     * Authenticates a request by session cookie or by personal API token.
     *
     * The bearer header is tried first: a browser never sends one, so there is no ambiguity in
     * practice, and a client that sends one has done so deliberately. The CI ingest token is a
     * different credential checked inside its own route, and presenting one here simply fails
     * to match -- the two are not interchangeable on purpose, since an ingest token belongs to
     * an estate rather than to a person.
     */
    async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
      const header = request.headers.authorization;
      if (typeof header === "string" && header.startsWith(API_TOKEN_PREFIX)) {
        const authenticated = await apiTokens.authenticate(header.slice(API_TOKEN_PREFIX.length));
        if (!authenticated) throw new UnauthorizedError("Invalid, expired or revoked API token.");

        request.currentUser = authenticated.user;
        request.apiToken = {
          id: authenticated.tokenId,
          name: authenticated.tokenName,
          scope: authenticated.scope,
        };

        /*
          The scope ceiling, applied here rather than as a separate hook so that no route can
          be behind authentication without also being behind this. `routeOptions.url` is the
          router pattern -- `/api/v1/applications/:id` -- which is what the rule is written
          against; the resolved URL would make it depend on the uuid of the day.
        */
        if (
          authenticated.scope === "read" &&
          !isReadOnlyRequest(request.method, request.routeOptions.url ?? request.url)
        ) {
          throw new TokenScopeError();
        }
        return;
      }

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
     * has, by construction, been seen by someone other than its owner - often
     * pasted into a chat - so a session opened with it must not be able to read
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
