import type { FastifyRequest } from "fastify";
import type { EnvironmentAccess } from "@sbom/shared";
import { getUser } from "../../plugins/auth.plugin.js";
import type { EnvironmentScope } from "./environment.service.js";

/**
 * Turning a request into an estate.
 *
 * Every read of estate data goes through here, and there is deliberately no other way to
 * construct an `EnvironmentScope`. That is the whole defence: a service method that needs a
 * scope cannot be called without one, and the only supplier checks access first.
 *
 * Both results are memoised per request. A handler may ask several services for data and
 * each will want the scope; resolving it once keeps that from becoming a query per service,
 * and guarantees every service in one request agrees about which estate it is reading.
 */

declare module "fastify" {
  interface FastifyRequest {
    /** Memoised by `environmentAccess`. Never read directly — it is unset before the call. */
    resolvedAccess?: EnvironmentAccess;
    /** Memoised by `requireScope`. */
    resolvedScope?: EnvironmentScope;
  }
}

export async function environmentAccess(request: FastifyRequest): Promise<EnvironmentAccess> {
  if (request.resolvedAccess) return request.resolvedAccess;
  const access = await request.server.ctx.environments.accessFor(getUser(request));
  request.resolvedAccess = access;
  return access;
}

function requestedRef(request: FastifyRequest): string | null {
  const query = request.query as { environment?: unknown } | undefined;
  const raw = query?.environment;
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return trimmed === "" ? null : trimmed;
}

/**
 * The estate this request is about.
 *
 * An explicit `?environment=` wins and is checked against the caller's grants — an
 * environment they cannot reach reads as absent rather than as forbidden, so the response
 * does not confirm that an estate they are not allowed to know about exists.
 *
 * With nothing named, falls back to the caller's oldest environment. That path exists for
 * API clients written before environments existed: on every upgraded deployment the oldest
 * is the migrated `Production`, so those callers keep reading what they always read. The web
 * client never relies on it, because it carries the environment in the URL.
 */
export async function requireScope(request: FastifyRequest): Promise<EnvironmentScope> {
  if (request.resolvedScope) return request.resolvedScope;

  const { environments } = request.server.ctx;
  const access = await environmentAccess(request);
  const ref = requestedRef(request);

  const scope = ref
    ? await environments.resolve(ref, access)
    : await environments.requireDefault(access);

  request.resolvedScope = scope;
  return scope;
}

/**
 * Every estate the caller may read, for the searches that deliberately span them.
 *
 * Used by package search alone. It is the one place a single response mixes environments,
 * and it stays honest by labelling every row with the estate it came from and never summing
 * across them — see the note in `schemas/environment.ts`.
 */
export async function selectedScopes(
  request: FastifyRequest,
  refs: string[] | undefined,
): Promise<EnvironmentScope[]> {
  const access = await environmentAccess(request);
  return request.server.ctx.environments.scopesForSelection(refs, access);
}
