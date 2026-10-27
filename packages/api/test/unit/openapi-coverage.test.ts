import { describe, expect, it } from "vitest";
import { buildApp } from "../../src/app.js";
import {
  buildOpenApiDocument,
  staleCatalogEntries,
  undocumentedRoutes,
} from "../../src/modules/openapi/openapi.service.js";
import { isReadOnlyRequest, readOnlyPostRoutes } from "../../src/modules/auth/token-scope.js";
import { loadConfig } from "../../src/config.js";
import type { FastifyInstance } from "fastify";

/**
 * The guarantee that the API document describes the API.
 *
 * A specification is read far more often than it is checked, so the failure that matters is
 * not a malformed document - anything will catch that - but a document that is confidently
 * wrong: it promises an endpoint that was removed, or omits one that was added, and a
 * developer builds against it and blames their own code.
 *
 * Two assertions prevent both directions, and they are only possible because the route list is
 * taken from Fastify's own table rather than written by hand. Neither can be satisfied by
 * editing the document; they are satisfied by the document and the server agreeing.
 *
 * The app is built for real here. That is slower than a fixture and it is the point: a fixture
 * would be a third list of routes, free to disagree with both of the others.
 */

/**
 * Config supplied explicitly rather than read from the environment.
 *
 * `buildApp` validates its configuration at construction, and a unit suite has no `.env`. The
 * values are inert: the pool is created but never queried, because the route table is assembled
 * during registration and nothing here invokes a handler.
 */
const config = loadConfig({
  NODE_ENV: "test",
  LOG_LEVEL: "silent",
  DATABASE_URL: "postgres://sbom:sbom@127.0.0.1:5432/sbom_test",
  SESSION_SECRET: "t".repeat(48),
  PUBLIC_URL: "http://localhost:5173",
});

let app: FastifyInstance | undefined;

async function routes() {
  // Built once and reused across the file.
  app ??= await buildApp({ config });
  await app.ready();
  return app.routeTable.list();
}

describe("the OpenAPI document covers the API", () => {
  it("documents every route the server registers", async () => {
    /*
      The direction that matters most. An endpoint added without a catalog entry is invisible
      to everybody who reads the document rather than the source, and nothing else would ever
      point it out.
    */
    const missing = undocumentedRoutes(await routes());
    expect(
      missing,
      `these routes have no entry in route-catalog.ts:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });

  it("describes no route that no longer exists", async () => {
    // The other direction: a stale entry is a promise the server will not keep, and a 404
    // against a documented endpoint reads as a deployment fault rather than a dead document.
    const stale = staleCatalogEntries(await routes());
    expect(
      stale,
      `route-catalog.ts describes routes that are not registered:\n  ${stale.join("\n  ")}`,
    ).toEqual([]);
  });
});

describe("the document itself", () => {
  it("is a well-formed OpenAPI 3 document with every operation reachable", async () => {
    const doc = buildOpenApiDocument(await routes(), {
      baseUrl: "https://sbom.example.com/api/v1",
      version: "test",
    });

    expect(doc.openapi).toBe("3.0.3");
    const paths = doc.paths as Record<string, Record<string, unknown>>;
    const operations = Object.values(paths).flatMap((methods) => Object.values(methods));

    // Non-empty, and every operation carries the three things a reader needs.
    expect(operations.length).toBeGreaterThan(100);
    for (const op of operations as Record<string, unknown>[]) {
      expect(op.summary, JSON.stringify(op).slice(0, 120)).toBeTruthy();
      expect(op.tags).toBeTruthy();
      expect(op.responses).toBeTruthy();
    }
  });

  it("turns Fastify parameters into OpenAPI templates, suffixes included", async () => {
    const doc = buildOpenApiDocument(await routes(), { baseUrl: "https://x/api/v1", version: "t" });
    const paths = Object.keys(doc.paths as object);

    // No colon form survives, or the document is invalid.
    expect(paths.filter((p) => p.includes(":"))).toEqual([]);
    expect(paths).toContain("/api/v1/applications/{id}");
    /*
      `:id.pdf` is one segment holding a parameter and a literal extension. Braces around the
      whole thing would declare a parameter named `id.pdf`, which no operation defines -- an
      invalid document that most validators accept and most generators then break on.
    */
    expect(paths).toContain("/api/v1/admin/reports/{id}.pdf");
  });

  it("declares a path parameter for every template it emits", async () => {
    const doc = buildOpenApiDocument(await routes(), { baseUrl: "https://x/api/v1", version: "t" });
    const problems: string[] = [];

    for (const [path, methods] of Object.entries(doc.paths as Record<string, object>)) {
      const expected = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      for (const [method, op] of Object.entries(methods as Record<string, Record<string, unknown>>)) {
        const declared = ((op.parameters as { name: string }[] | undefined) ?? []).map(
          (p) => p.name,
        );
        for (const name of expected) {
          if (!declared.includes(name)) problems.push(`${method.toUpperCase()} ${path} -> ${name}`);
        }
      }
    }
    expect(problems, `templated parameters with no declaration:\n  ${problems.join("\n  ")}`).toEqual(
      [],
    );
  });

  it("marks each operation with the credential and scope it needs", async () => {
    const doc = buildOpenApiDocument(await routes(), { baseUrl: "https://x/api/v1", version: "t" });
    const paths = doc.paths as Record<string, Record<string, Record<string, unknown>>>;

    // A write names the scope it needs; a read says it can be called with a read-only token.
    const write = paths["/api/v1/admin/groups"]?.post;
    expect(String(write?.description)).toContain("`write` scope");

    const read = paths["/api/v1/applications"]?.get;
    expect(String(read?.description)).toContain("read-only token");

    // The sign-in endpoint is public and must not demand a credential, or a client generated
    // from this document cannot authenticate at all.
    expect(paths["/api/v1/auth/login"]?.post?.security).toEqual([]);
  });

  it("generates request bodies from the schemas the server validates with", async () => {
    const doc = buildOpenApiDocument(await routes(), { baseUrl: "https://x/api/v1", version: "t" });
    const paths = doc.paths as Record<string, Record<string, Record<string, unknown>>>;

    const body = paths["/api/v1/auth/api-tokens"]?.post?.requestBody as {
      content: { "application/json": { schema: { properties: Record<string, unknown> } } };
    };
    const schema = body.content["application/json"].schema;

    /*
      Asserted against the real field names rather than merely "a schema exists". The value of
      generating from Zod is that the document cannot promise a field the server rejects, and
      only reading the fields back proves the conversion happened at all.
    */
    expect(Object.keys(schema.properties)).toEqual(
      expect.arrayContaining(["name", "scope", "expiresInDays"]),
    );
  });
});

describe("the read-only scope rule", () => {
  it("permits every GET and refuses every other method by default", () => {
    expect(isReadOnlyRequest("GET", "/api/v1/applications")).toBe(true);
    expect(isReadOnlyRequest("HEAD", "/api/v1/applications")).toBe(true);
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(isReadOnlyRequest(method, "/api/v1/admin/groups"), method).toBe(false);
    }
  });

  it("permits the two POSTs that are searches rather than changes", () => {
    for (const path of readOnlyPostRoutes()) {
      expect(isReadOnlyRequest("POST", path), path).toBe(true);
    }
    // And the list is the two it is meant to be -- a third appearing silently would widen
    // what every read-only token on the platform can do.
    expect(readOnlyPostRoutes()).toEqual([
      "/api/v1/admin/users/:id/application-access/preview",
      "/api/v1/components/bulk-search",
    ]);
  });

  it("refuses an unrecognised POST rather than allowing it", () => {
    /*
      The failure direction that matters. A route added tomorrow is treated as a write until
      somebody adds it to the allowlist, so forgetting produces a refusal somebody reports --
      not a read-only token quietly gaining the ability to change things.
    */
    expect(isReadOnlyRequest("POST", "/api/v1/something/added/later")).toBe(false);
  });
});
