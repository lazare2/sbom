/**
 * Every route the server actually registered.
 *
 * Collected from Fastify's own `onRoute` hook rather than listed by hand, which is the one
 * thing that makes "the document describes the whole API" true by construction instead of by
 * diligence. A hand-maintained list drifts the first time somebody adds an endpoint and does
 * not think of the spec - and the spec is the half people read.
 *
 * The companion guarantee is in the catalog: a route collected here with no entry there fails
 * a test. Between them, an endpoint cannot exist undocumented and cannot be documented without
 * existing.
 */

export interface CollectedRoute {
  /** Upper-case HTTP method. One entry per method, even where a route declared several. */
  method: string;
  /**
   * The router pattern, with `:param` placeholders intact.
   *
   * Not the resolved URL: the pattern is what the scope rule is written against and what an
   * OpenAPI path template needs, and a resolved URL would make both depend on whichever uuid
   * happened to be in the request.
   */
  url: string;
}

/**
 * Collects routes as they register, de-duplicated.
 *
 * Fastify fires `onRoute` once per route declaration, and a declaration may carry several
 * methods; HEAD is also synthesised for every GET. Both are flattened here so the document has
 * one operation per method-and-path, which is what OpenAPI expects.
 */
export class RouteCollector {
  private readonly seen = new Set<string>();

  add(route: { method: string | string[]; url: string }): void {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const method of methods) {
      /*
        HEAD is dropped. Fastify adds one for every GET automatically, and documenting a
        parallel HEAD for all seventy-nine reads would double the document to say nothing a
        reader did not already know from the GET.
      */
      if (method.toUpperCase() === "HEAD") continue;
      this.seen.add(`${method.toUpperCase()} ${route.url}`);
    }
  }

  /** Sorted, so the generated document is byte-stable between restarts. */
  list(): CollectedRoute[] {
    return [...this.seen]
      .sort()
      .map((key) => {
        const space = key.indexOf(" ");
        return { method: key.slice(0, space), url: key.slice(space + 1) };
      });
  }

  /** `METHOD /path`, the key the catalog is indexed by. */
  static keyOf(route: CollectedRoute): string {
    return `${route.method} ${route.url}`;
  }
}

declare module "fastify" {
  interface FastifyInstance {
    /** Every route this server registered. Populated by an `onRoute` hook in `buildApp`. */
    routeTable: RouteCollector;
  }
}
