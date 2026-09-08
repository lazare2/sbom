import type { FastifyRequest } from "fastify";
import { getUser } from "../../plugins/auth.plugin.js";
import { readAccessOf, type ReadAccess, type ReadScope } from "./environment.service.js";

/**
 * Turning a request into what it is allowed to read.
 *
 * Every read of estate data goes through here, and there is deliberately no other way to
 * construct a `ReadScope` or a `ReadAccess`. That is the whole defence: a service method that
 * needs one cannot be called without it, and the only supplier checks access first.
 *
 * Two restrictions are resolved here, not one. Which estates the caller may reach, and which
 * applications within them — and they are combined into a single value before any service
 * sees them, so that no call site can apply one and forget the other.
 *
 * Both results are memoised per request. A handler may ask several services for data and
 * each will want the scope; resolving it once keeps that from becoming two queries per
 * service, and guarantees every service in one request agrees about what it may read.
 */

declare module "fastify" {
  interface FastifyRequest {
    /** Memoised by `readAccess`. Never read directly — it is unset before the call. */
    resolvedAccess?: ReadAccess;
    /** Memoised by `requireScope`. */
    resolvedScope?: ReadScope;
  }
}

/**
 * Everything this caller may read, across every estate they were granted.
 *
 * For fetching one named thing by its id. The two restrictions are resolved together and in
 * parallel: they are independent queries against different tables, and a restricted account
 * would otherwise pay two round trips before any handler did its own work.
 */
export async function readAccess(request: FastifyRequest): Promise<ReadAccess> {
  if (request.resolvedAccess) return request.resolvedAccess;

  const user = getUser(request);
  const { environments, applicationAccess } = request.server.ctx;
  const [inEnvironments, onApplications] = await Promise.all([
    environments.accessFor(user),
    applicationAccess.accessFor(user),
  ]);

  const access = readAccessOf(inEnvironments, onApplications);
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
 * The estate this request is about, and how much of it the caller may see.
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
export async function requireScope(request: FastifyRequest): Promise<ReadScope> {
  if (request.resolvedScope) return request.resolvedScope;

  const { environments } = request.server.ctx;
  const access = await readAccess(request);
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
 *
 * Each scope carries the caller's application visibility, so spanning estates never widens
 * what may be seen inside one. Without that, this would be the way to enumerate the names of
 * applications an account was deliberately not granted.
 */
export async function selectedScopes(
  request: FastifyRequest,
  refs: string[] | undefined,
): Promise<ReadScope[]> {
  const access = await readAccess(request);
  return request.server.ctx.environments.scopesForSelection(refs, access);
}
