import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config.js";

const base = {
  DATABASE_URL: "postgres://sbom:sbom@localhost:5432/sbom",
  SESSION_SECRET: "a".repeat(48),
};

describe("loadConfig", () => {
  it("applies defaults for everything optional", () => {
    const config = loadConfig({ ...base });
    expect(config.NODE_ENV).toBe("development");
    expect(config.API_PORT).toBe(3000);
    expect(config.BLOB_STORE_DRIVER).toBe("fs");
    expect(config.AUTH_PROVIDERS).toEqual(["local"]);
    expect(config.INGEST_MAX_SBOM_BYTES).toBe(64 * 1024 * 1024);
  });

  it("fails when DATABASE_URL is missing, rather than at first query", () => {
    expect(() => loadConfig({ SESSION_SECRET: "a".repeat(48) })).toThrowError(/DATABASE_URL/);
  });

  it("rejects a session secret short enough to brute-force", () => {
    expect(() => loadConfig({ ...base, SESSION_SECRET: "short" })).toThrowError(/at least 32/);
  });

  it("refuses to start in production with the example session secret", () => {
    expect(() =>
      loadConfig({
        ...base,
        NODE_ENV: "production",
        SESSION_SECRET: "change-me-to-a-long-random-string-at-least-32-chars",
      }),
    ).toThrowError(/must not use the example value/);
  });

  it("allows the example secret outside production, so local dev just works", () => {
    const config = loadConfig({
      ...base,
      SESSION_SECRET: "change-me-to-a-long-random-string-at-least-32-chars",
    });
    expect(config.NODE_ENV).toBe("development");
  });

  it("parses named ingest tokens", () => {
    const config = loadConfig({
      ...base,
      INGEST_TOKENS: "jenkins:tok-one, gitlab:tok-two",
    });
    expect(config.INGEST_TOKENS).toEqual([
      { name: "jenkins", token: "tok-one" },
      { name: "gitlab", token: "tok-two" },
    ]);
  });

  it("accepts a bare token and gives it a positional name", () => {
    const config = loadConfig({ ...base, INGEST_TOKENS: "just-a-token" });
    expect(config.INGEST_TOKENS).toEqual([{ name: "env-1", token: "just-a-token" }]);
  });

  it("ignores empty entries from a trailing comma in CI config", () => {
    const config = loadConfig({ ...base, INGEST_TOKENS: "a:1,,b:2," });
    expect(config.INGEST_TOKENS).toHaveLength(2);
  });

  it("treats a token value containing a colon as part of the token", () => {
    const config = loadConfig({ ...base, INGEST_TOKENS: "ci:abc:def" });
    expect(config.INGEST_TOKENS).toEqual([{ name: "ci", token: "abc:def" }]);
  });

  it("requires a bucket when the s3 blob driver is selected", () => {
    expect(() => loadConfig({ ...base, BLOB_STORE_DRIVER: "s3" })).toThrowError(
      /BLOB_STORE_S3_BUCKET/,
    );
  });

  it("accepts a bootstrap admin identifier that is not a deliverable address", () => {
    // Regression guard. This used to be `z.string().email()`, which refused
    // `admin@localhost` and `svc-ci` outright — a startup failure for an
    // identifier that is perfectly valid now that nothing is ever mailed.
    for (const email of ["admin@localhost", "svc-ci", "admin@sbom.local"]) {
      expect(loadConfig({ ...base, BOOTSTRAP_ADMIN_EMAIL: email }).BOOTSTRAP_ADMIN_EMAIL).toBe(email);
    }
  });

  it("still rejects a bootstrap admin identifier containing whitespace", () => {
    expect(() => loadConfig({ ...base, BOOTSTRAP_ADMIN_EMAIL: "two words" })).toThrowError(
      /BOOTSTRAP_ADMIN_EMAIL/,
    );
  });

  it("rejects an auth provider that is not implemented yet", () => {
    expect(() => loadConfig({ ...base, AUTH_PROVIDERS: "local,ldap" })).toThrowError(
      /only "local" is implemented/,
    );
  });

  it("marks the session cookie Secure only when the public URL is https", () => {
    expect(loadConfig({ ...base, PUBLIC_URL: "http://localhost:5173" }).cookieSecure).toBe(false);
    expect(loadConfig({ ...base, PUBLIC_URL: "https://sbom.internal.example.com" }).cookieSecure).toBe(true);
  });

  it("reports every problem at once instead of one per restart", () => {
    let message = "";
    try {
      loadConfig({ SESSION_SECRET: "short", API_PORT: "not-a-number" });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toMatch(/DATABASE_URL/);
    expect(message).toMatch(/SESSION_SECRET/);
    expect(message).toMatch(/API_PORT/);
  });
});
