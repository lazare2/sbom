import { zodToJsonSchema } from "zod-to-json-schema";
import { API_TOKEN_SECRET_PREFIX } from "@sbom/shared";
import { isReadOnlyRequest } from "../auth/token-scope.js";
import { ROUTE_CATALOG, type RouteAuth, type RouteMeta } from "./route-catalog.js";
import { RouteCollector, type CollectedRoute } from "./route-collector.js";

/**
 * Builds the OpenAPI document from the server's own route table.
 *
 * Nothing here is a list of endpoints. The paths come from Fastify, the request bodies from the
 * Zod schemas the server validates with, and the read/write marking from the same function the
 * authorisation hook calls. The only hand-written part is the prose in the catalog - so the
 * document can be wrong about what an endpoint is *for*, but not about whether it exists, what
 * it accepts, or who may call it.
 *
 * ## Responses
 *
 * Documented as status codes and their meanings rather than as body schemas. The response types
 * are TypeScript interfaces, so there is nothing to convert; hand-writing a hundred JSON
 * Schemas would be a second description of the same shapes, free to drift from the first. The
 * types in `@sbom/shared` are the description, and the UI is compiled against them.
 */

/** Routes that exist but are not API operations. */
function isDocumentable(route: CollectedRoute): boolean {
  // The CORS preflight wildcard. Not an endpoint anybody calls deliberately.
  return route.url !== "*";
}

/** `/api/v1/applications/:id` -> `/api/v1/applications/{id}`, and the parameter names. */
function toTemplate(url: string): { path: string; params: string[] } {
  const params: string[] = [];
  const path = url
    .split("/")
    .map((segment) => {
      if (!segment.startsWith(":")) return segment;
      /*
        `:id.pdf` is one segment carrying a parameter and a literal suffix. Splitting on the
        dot keeps the suffix outside the braces, because `{id.pdf}` would name a parameter
        that does not exist and make the document invalid.
      */
      const dot = segment.indexOf(".");
      const name = (dot === -1 ? segment.slice(1) : segment.slice(1, dot)).trim();
      params.push(name);
      return dot === -1 ? `{${name}}` : `{${name}}${segment.slice(dot)}`;
    })
    .join("/");
  return { path, params };
}

const AUTH_DESCRIPTION: Record<RouteAuth, string> = {
  public: "No credential required.",
  session:
    "A signed-in account. Reachable while a forced password change is pending, unlike the rest " +
    "of the API.",
  user: "Any signed-in account, by session cookie or personal API token.",
  admin: "An account whose role is `admin`.",
  ingest:
    "A CI ingest token, which is a different credential from a personal API token: it belongs " +
    "to an environment rather than a person, and may only submit scans.",
};

/** The responses every operation can produce, by who may call it. */
function responsesFor(meta: RouteMeta, method: string): Record<string, { description: string }> {
  const responses: Record<string, { description: string }> = {};

  responses[method === "POST" ? "201" : "200"] =
    method === "POST"
      ? { description: "Created. See the types in `@sbom/shared` for the body." }
      : { description: "Success. See the types in `@sbom/shared` for the body." };
  if (method === "DELETE") {
    delete responses["200"];
    responses["204"] = { description: "Deleted. No body." };
  }

  responses["400"] = { description: "The request was malformed. Retrying will not help." };
  if (meta.auth !== "public") {
    responses["401"] = { description: "Missing, invalid, expired or revoked credential." };
  }
  if (meta.auth === "admin") {
    responses["403"] = { description: "The account is not an administrator." };
  }
  if (!isReadOnlyRequest(method, "")) {
    responses["403"] = {
      description:
        meta.auth === "admin"
          ? "The account is not an administrator, or the API token is read-only " +
            "(`token_read_only`)."
          : "The API token is read-only (`token_read_only`).",
    };
  }
  responses["429"] = { description: "Rate limited. The response says when to retry." };
  return responses;
}

export interface OpenApiOptions {
  baseUrl: string;
  version: string;
}

export function buildOpenApiDocument(
  routes: readonly CollectedRoute[],
  options: OpenApiOptions,
): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  const tags = new Set<string>();

  for (const route of routes) {
    if (!isDocumentable(route)) continue;

    const key = RouteCollector.keyOf(route);
    const meta = ROUTE_CATALOG[key];
    /*
      A route with no catalog entry is skipped here and *fails a test*. Emitting a placeholder
      instead would make the document look complete while describing an endpoint nobody has
      explained -- and the test is what makes the omission loud rather than cosmetic.
    */
    if (!meta) continue;

    const { path, params } = toTemplate(route.url);
    tags.add(meta.tag);

    const readOnly = isReadOnlyRequest(route.method, route.url);
    const operation: Record<string, unknown> = {
      summary: meta.summary,
      tags: [meta.tag],
      description: [
        meta.notes ?? "",
        "",
        `**Access.** ${AUTH_DESCRIPTION[meta.auth]}`,
        meta.auth === "public" || meta.auth === "ingest"
          ? ""
          : `**Token scope.** ${
              readOnly
                ? "Callable with a read-only token."
                : "Requires a token with `write` scope."
            }`,
      ]
        .filter((line) => line !== "")
        .join("\n\n"),
      operationId: `${route.method.toLowerCase()}${path
        .replace(/[^a-zA-Z0-9]+(.)/g, (_m, c: string) => c.toUpperCase())
        .replace(/[^a-zA-Z0-9]/g, "")}`,
      security: meta.auth === "public" ? [] : [{ bearerAuth: [] }],
      responses: responsesFor(meta, route.method),
    };

    if (params.length > 0) {
      operation.parameters = params.map((name) => ({
        name,
        in: "path",
        required: true,
        schema: { type: "string" },
      }));
    }

    if (meta.body) {
      operation.requestBody = {
        required: true,
        content: {
          "application/json": {
            /*
              Generated from the same Zod the route validates with, so the document cannot
              promise a field the server rejects. `$refStrategy: none` inlines definitions:
              a reader looking at one operation should not have to resolve a pointer to learn
              what a field is.
            */
            schema: zodToJsonSchema(meta.body, { target: "openApi3", $refStrategy: "none" }),
          },
        },
      };
    }

    paths[path] ??= {};
    paths[path][route.method.toLowerCase()] = operation;
  }

  return {
    openapi: "3.0.3",
    info: {
      title: "SBOM Platform API",
      version: options.version,
      description: [
        "The API this platform's own web interface is built on. Every screen is drawn by",
        "calling these endpoints, so a token reaches exactly what the UI reaches - no more,",
        "and no less.",
        "",
        "## Authenticating",
        "",
        "Send a personal API token as a bearer credential on every request:",
        "",
        "```",
        `Authorization: Bearer ${API_TOKEN_SECRET_PREFIX}…`,
        "```",
        "",
        "Mint one on the **API access** page. A token acts as the account that created it, and",
        "its permissions are resolved per request - narrowing an account's access, or disabling",
        "it, applies to its tokens immediately.",
        "",
        "## Read and write",
        "",
        "Tokens carry a scope. A `read` token may call any GET, plus the two POSTs that are",
        "searches rather than changes; everything else needs `write`. A refusal on scope",
        "returns 403 with the code `token_read_only`, which is distinct from an ordinary",
        "permission failure because the fix is a different token rather than different access.",
        "",
        "## Environments",
        "",
        "Estates are a hard partition. An application name is unique per environment, so the",
        "same service in two estates is two independent records with separate scans and",
        "separate findings. Nothing is ever summed across them.",
        "",
        "## Absent data is never zero",
        "",
        "Where the platform has not measured something it says so, rather than reporting zero.",
        "Vulnerability figures come back `null` when scanning is off, and the base-image half",
        "comes back `null` when the active scanner holds no data for operating-system",
        "packages. A zero means it looked and found nothing.",
      ].join("\n"),
    },
    servers: [{ url: options.baseUrl, description: "This deployment" }],
    tags: [...tags].sort().map((name) => ({ name })),
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description:
            "A personal API token from the API access page. CI ingest tokens are also bearer " +
            "credentials but are accepted only by POST /api/v1/scans.",
        },
      },
    },
    security: [{ bearerAuth: [] }],
    paths,
  };
}

/**
 * Routes with no catalog entry.
 *
 * Exported for the test that asserts this is empty. Keeping the check outside the builder is
 * what lets the server start with an incomplete document while a test still refuses to let one
 * be committed.
 */
export function undocumentedRoutes(routes: readonly CollectedRoute[]): string[] {
  return routes
    .filter(isDocumentable)
    .map((route) => RouteCollector.keyOf(route))
    .filter((key) => !(key in ROUTE_CATALOG))
    .sort();
}

/** Catalog entries describing a route that no longer exists. */
export function staleCatalogEntries(routes: readonly CollectedRoute[]): string[] {
  const live = new Set(routes.map((route) => RouteCollector.keyOf(route)));
  return Object.keys(ROUTE_CATALOG)
    .filter((key) => !live.has(key))
    .sort();
}
