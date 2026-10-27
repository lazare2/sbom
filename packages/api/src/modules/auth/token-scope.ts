/**
 * Whether a request changes anything, and therefore whether a read-only token may make it.
 *
 * One function, used by the hook that enforces it and by the OpenAPI document that describes
 * it. Two copies of this rule is how a spec comes to promise access the server refuses, and the
 * promise is the half people read.
 *
 * ## Why the method alone is not enough
 *
 * Almost every write is a POST, PATCH, PUT or DELETE and almost every read is a GET, but this
 * API has two POSTs that are searches. Refusing them to a read-only token would make such a
 * token nearly useless for the thing people actually want one for - querying the inventory
 * from a script - so they are named below rather than inferred.
 *
 * The converse does not arise: there is no GET in this API that changes anything, and if one is
 * ever added it is the route that is wrong, not this list.
 */

/**
 * POST routes that read.
 *
 * Matched against Fastify's *router* path, so the parameter placeholders are literal `:id`
 * segments rather than values. Matching the resolved URL would make the list depend on which
 * uuid happened to be in it.
 */
const READ_ONLY_POST_ROUTES: ReadonlySet<string> = new Set([
  /*
    Bulk package search. It does insert a `package_query` row -- that is what gives a pasted
    list a shareable address -- so it is not literally side-effect-free. It is allowed anyway:
    the row is bookkeeping about the question, not a change to the estate, and this endpoint is
    the main reason a developer wants a token at all. Refusing it would leave read tokens able
    to list applications but not to answer "where is log4j", which is the question.
  */
  "/api/v1/components/bulk-search",
  /*
    Scores a candidate grant set without saving it. A POST only because the candidate is too
    structured for a query string.
  */
  "/api/v1/admin/users/:id/application-access/preview",
]);

/** Methods that never change anything, whatever the route. */
const READ_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * True when a read-only token is permitted to make this request.
 *
 * Takes the router path rather than the URL for the reason given above, and falls back to
 * refusing: an unrecognised POST is treated as a write, so adding a route cannot accidentally
 * widen what a read token can do. The failure direction is the safe one - a new read-only POST
 * is refused until somebody adds it here, which is a bug report rather than a breach.
 */
export function isReadOnlyRequest(method: string, routerPath: string): boolean {
  if (READ_METHODS.has(method.toUpperCase())) return true;
  if (method.toUpperCase() !== "POST") return false;
  return READ_ONLY_POST_ROUTES.has(routerPath);
}

/** Exposed so the OpenAPI document can mark each operation, and so a test can assert on it. */
export function readOnlyPostRoutes(): string[] {
  return [...READ_ONLY_POST_ROUTES].sort();
}
