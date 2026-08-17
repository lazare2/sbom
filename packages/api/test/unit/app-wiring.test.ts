import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import type { BlobStore } from "../../src/services/blob-store/index.js";
import type { VulnerabilityScanner } from "../../src/services/scanner/index.js";

/**
 * Wiring smoke tests: builds the real Fastify app and drives it with
 * `inject()`, no network and no database.
 *
 * These cover the failure modes that only appear once everything is assembled —
 * a plugin registered in the wrong order, a route mounted under the wrong
 * prefix, an error that bypasses the handler and leaks a stack trace. The
 * endpoints exercised here (health, and the pre-database rejection paths of the
 * ingest route) never reach Postgres.
 */

class FakeBlobStore implements BlobStore {
  readonly name = "fake";
  readonly puts: Array<{ key: string; size: number }> = [];
  async put(key: string, data: Buffer) {
    this.puts.push({ key, size: data.length });
    return { key, storedBytes: data.length, deduplicated: false };
  }
  async get(): Promise<Buffer> {
    throw new Error("not used");
  }
  async exists(): Promise<boolean> {
    return false;
  }
  async delete(): Promise<void> {}
  async verify(): Promise<void> {}
}

/**
 * Scanner stub.
 *
 * The real one spawns a subprocess and reads a 1.9 GB database directory. These tests build
 * the whole app, so without a substitute every run would shell out to grype — and would
 * behave differently on a machine that happens to have it installed.
 */
class FakeScanner implements VulnerabilityScanner {
  readonly name = "fake";
  async availability() {
    return { available: false, version: null, path: null, resolvedBy: null, supportedDbSchema: null, attempts: [] };
  }
  async dbStatus() {
    return { present: false, builtAt: null, schemaVersion: null, valid: false, error: "no database", path: null };
  }
  async listingUrl() {
    return "https://example.invalid/databases/v6/latest.json";
  }
  async checkReachable() {
    return { reachable: false, url: "https://example.invalid/databases/v6/latest.json", message: "offline" };
  }
  async updateDb() {
    return { outcome: "unreachable" as const, message: "offline", builtBefore: null, builtAfter: null, schemaVersion: null, sourceUrl: null };
  }
  async importDb() {
    return { outcome: "failed" as const, message: "not used", builtBefore: null, builtAfter: null, schemaVersion: null, sourceUrl: null };
  }
  async match() {
    return { findings: [], grypeVersion: null, dbBuiltAt: null, unmappedFindings: 0, submittedComponentIds: [] };
  }
}

const config = loadConfig({
  NODE_ENV: "test",
  LOG_LEVEL: "silent",
  DATABASE_URL: "postgres://sbom:sbom@127.0.0.1:5432/sbom_test",
  SESSION_SECRET: "t".repeat(48),
  INGEST_TOKENS: "test-ci:super-secret-ci-token",
  PUBLIC_URL: "http://localhost:5173",
});

describe("app wiring", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp({ config, blobStore: new FakeBlobStore(), scanner: new FakeScanner() });
    await app.ready();
  });

  afterAll(async () => {
    // Guarded: if beforeAll threw, `app` is undefined and the teardown error
    // would mask the real failure.
    if (app) await app.close();
  });

  it("assembles every plugin and route without error", () => {
    expect(app.ctx).toBeDefined();
    expect(app.ctx.blobStore.name).toBe("fake");
    // The registry reflects AUTH_PROVIDERS; only `local` exists in this phase.
    expect(app.ctx.providers.all().map((p) => p.name)).toEqual(["local"]);
  });

  it("guards every admin route behind requireAdmin", async () => {
    // Anonymous, so each must stop at the scope-wide hook rather than reaching a
    // handler. This is the check that catches a route added to admin.routes.ts
    // under a prefix that accidentally escapes the guarded scope.
    for (const url of [
      "/api/v1/admin/users",
      "/api/v1/admin/audit-log",
      "/api/v1/admin/ingest-tokens",
    ]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode, url).toBe(401);
    }

    const post = await app.inject({
      method: "POST",
      url: "/api/v1/admin/applications",
      payload: { name: "should-not-be-created" },
    });
    expect(post.statusCode).toBe(401);
  });

  it("guards the bulk package search behind a session", async () => {
    /*
     * Worth its own check because this is the one read-scope route that *writes*:
     * submitting a list persists it so the results have a shareable URL. An
     * anonymous caller must not be able to create rows, and the export must not
     * hand out estate contents.
     */
    const post = await app.inject({
      method: "POST",
      url: "/api/v1/components/bulk-search",
      payload: { input: "express" },
    });
    expect(post.statusCode).toBe(401);

    for (const url of [
      "/api/v1/components/bulk-search",
      "/api/v1/components/bulk-search/00000000-0000-4000-8000-000000000000",
      "/api/v1/components/bulk-search/00000000-0000-4000-8000-000000000000/export.xlsx",
    ]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode, url).toBe(401);
    }
  });

  it("guards the manual SBOM upload behind a session, not the ingest token", async () => {
    /*
     * The single most important guard added by the manual upload feature. This
     * endpoint writes scan history and moves an application's current-build
     * pointer, so it must be unreachable without a session.
     *
     * The second assertion is the one that would catch a real mistake: a CI ingest
     * token must NOT open this route. The two auth mechanisms live in separate
     * plugin scopes precisely so they cannot cross over, and a token that could
     * post to an arbitrary application id — bypassing app_name resolution, aliases
     * and auto-creation — would defeat that separation.
     */
    const appId = "00000000-0000-4000-8000-000000000000";

    const anonymous = await app.inject({
      method: "POST",
      url: `/api/v1/applications/${appId}/scans`,
    });
    expect(anonymous.statusCode).toBe(401);

    const withIngestToken = await app.inject({
      method: "POST",
      url: `/api/v1/applications/${appId}/scans`,
      headers: { authorization: "Bearer super-secret-ci-token" },
    });
    expect(withIngestToken.statusCode).toBe(401);
  });

  it("guards every vulnerability route, admin and read alike", async () => {
    /*
     * Two distinct boundaries, both asserted here because they are easy to get wrong in
     * opposite directions.
     *
     * The admin routes control whether scanning runs at all and can install a database, so
     * they must sit behind requireAdmin. The read routes expose estate contents, so they
     * must sit behind requireAuth. Neither may be reachable anonymously, and a route added
     * to either file later inherits its scope's hook rather than needing its own.
     */
    for (const url of [
      "/api/v1/admin/vuln/status",
      "/api/v1/admin/vuln/history",
      "/api/v1/admin/vuln/suppressions",
    ]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode, url).toBe(401);
    }

    for (const url of [
      "/api/v1/admin/vuln/update",
      "/api/v1/admin/vuln/sweep",
      "/api/v1/admin/vuln/import",
    ]) {
      const res = await app.inject({ method: "POST", url });
      expect(res.statusCode, url).toBe(401);
    }

    const patch = await app.inject({
      method: "PATCH",
      url: "/api/v1/admin/vuln/settings",
      payload: { enabled: true },
    });
    expect(patch.statusCode).toBe(401);

    for (const url of [
      "/api/v1/vulnerabilities",
      "/api/v1/vulnerabilities/CVE-2021-44228",
      "/api/v1/vuln-status",
      "/api/v1/applications/00000000-0000-4000-8000-000000000000/vulnerabilities",
      "/api/v1/scans/00000000-0000-4000-8000-000000000000/vulnerabilities",
    ]) {
      const res = await app.inject({ method: "GET", url });
      expect(res.statusCode, url).toBe(401);
    }
  });

  it("does not let a CI ingest token reach vulnerability data", async () => {
    // The ingest token authenticates a pipeline posting SBOMs. It must not double as a
    // read credential for the estate's vulnerability posture.
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/vulnerabilities",
      headers: { authorization: "Bearer super-secret-ci-token" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("serves liveness without touching the database", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ status: "ok" });
  });

  it("returns the standard error envelope for an unknown route", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/does-not-exist" });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ error: { code: "route_not_found" } });
  });

  it("mounts the ingest endpoint under /api/v1", async () => {
    // No auth header, so this must be rejected before any DB or blob access.
    const res = await app.inject({ method: "POST", url: "/api/v1/scans" });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: { code: "unauthorized" } });
    // The message has to tell a pipeline author what to fix.
    expect(res.json().error.message).toMatch(/Authorization: Bearer/);
  });

  it("fails closed rather than falsely rejecting when the token store is unreachable", async () => {
    // An unrecognised token is not in the env list, so verification falls
    // through to the `ingest_token` table — unreachable here, since these tests
    // run without Postgres.
    //
    // A 5xx is the correct outcome: we cannot prove the token is invalid, so the
    // pipeline should retry rather than be told its credential is bad. Asserting
    // this pins the behaviour, because the alternative — a 401 on a database
    // blip — would send CI owners hunting for a credential problem that does not
    // exist. The genuine invalid-token 401 is covered by integration tests.
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: "Bearer not-the-right-token" },
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(500);
    expect(res.json()).toEqual({ error: { code: "internal_error", message: "Internal server error" } });
  });

  it("accepts the configured env token but rejects a non-multipart body", async () => {
    // Getting to 415 proves the token verified: an invalid token would have
    // returned 401 first.
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: "Bearer super-secret-ci-token", "content-type": "application/json" },
      payload: { app_name: "x" },
    });
    expect(res.statusCode).toBe(415);
    expect(res.json().error.code).toBe("unsupported_media_type");
    expect(res.json().error.message).toMatch(/multipart\/form-data/);
  });

  it("requires authentication on the session-protected routes", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/auth/me" });
    expect(res.statusCode).toBe(401);
  });

  it("treats logout as idempotent when there is no session", async () => {
    const res = await app.inject({ method: "POST", url: "/api/v1/auth/logout" });
    expect(res.statusCode).toBe(204);
  });

  it("validates the login body before hitting an auth provider", async () => {
    // `email` is a login identifier, not a mailbox, so it is deliberately not
    // RFC-validated — `not-an-email` is an acceptable username. What is still
    // rejected is an identifier with whitespace in it, which is always a paste
    // accident, and an empty password.
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { email: "has a space", password: "" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
    expect(Object.keys(res.json().error.details)).toContain("email");
    expect(Object.keys(res.json().error.details)).toContain("password");
  });

  it("never leaks an internal message on a 500", async () => {
    // A separate instance, because routes cannot be added after ready(). Built
    // with the real error handler so this exercises the production path.
    const boomApp = await buildApp({ config, blobStore: new FakeBlobStore(), scanner: new FakeScanner() });
    boomApp.get("/__boom", async () => {
      throw new Error("secret internal detail: connection string was postgres://user:pw@host/db");
    });
    await boomApp.ready();

    try {
      const res = await boomApp.inject({ method: "GET", url: "/__boom" });
      expect(res.statusCode).toBe(500);
      expect(res.body).not.toContain("secret internal detail");
      expect(res.body).not.toContain("postgres://");
      expect(res.json()).toEqual({ error: { code: "internal_error", message: "Internal server error" } });
    } finally {
      await boomApp.close();
    }
  });
});
