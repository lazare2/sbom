/*
  What is allowed to reach the error log table.

  The log exists so an administrator can read why a request failed without developer tools.
  That means it is durable, and readable by every administrator — which makes it the worst
  possible place for a credential to land. The guarantee is enforced here rather than at the
  call sites, because the call site is a single generic error handler that cannot know which
  of a hundred schemas produced the failure it is recording.

  Today no schema in this repository quotes a submitted value for a secret field, so nothing
  in these tests is currently reachable through the API. That is the point: this is what
  stops a schema written next year from quietly turning the error log into a list of tokens,
  in a place nobody would think to look for one.

  The other half is that redaction must not destroy the log's usefulness. A field *name* is
  safe and is the whole reason the row is worth keeping, so the tests below pin what survives
  as carefully as what does not.
*/
import { describe, expect, it } from "vitest";
import { redactDetails, redactPath } from "../../src/modules/admin/api-error.service.js";

describe("redacting validation details", () => {
  it("keeps the field name and the reason for an ordinary field", () => {
    // The case this whole feature was built for: a rejected Xray URL that said nothing.
    expect(redactDetails({ baseUrl: ["Must be a full URL including http:// or https://."] })).toEqual({
      baseUrl: ["Must be a full URL including http:// or https://."],
    });
  });

  it("withholds the reason for a field whose name says it holds a secret", () => {
    /*
      The name is kept and the message is replaced. Knowing that the token was rejected is
      exactly what the reader needs; knowing what they typed is what must not be stored.
    */
    const out = redactDetails({ token: ["Expected at least 1 character, received \"hunter2\""] });
    expect(out?.token).toHaveLength(1);
    expect(out?.token?.[0]).not.toContain("hunter2");
    expect(out?.token?.[0]).toMatch(/withheld/i);
  });

  it("catches secret fields whatever the naming convention", () => {
    // camelCase, snake_case, SCREAMING_CASE and nested paths all arrive here in practice.
    for (const field of [
      "apiToken",
      "smtpPassword",
      "SECRETS_KEY",
      "xray.token",
      "connection.apiKey",
      "credentials",
      "authorization",
    ]) {
      const out = redactDetails({ [field]: ["something quoting a value"] });
      expect(out?.[field]?.[0], `${field} was not redacted`).toMatch(/withheld/i);
    }
  });

  it("redacts only the secret field, leaving its siblings readable", () => {
    // A form usually fails on more than one field at once, and the useful ones must survive.
    const out = redactDetails({
      baseUrl: ["Must be a full URL."],
      token: ["quoted secret"],
      username: ["required"],
    });
    expect(out).toEqual({
      baseUrl: ["Must be a full URL."],
      token: [expect.stringMatching(/withheld/i)],
      username: ["required"],
    });
  });

  it("returns null rather than an empty object when there is nothing to record", () => {
    // `details` is nullable in the column, and an empty object would render as an empty
    // bullet list under the message — a visual claim that there was more to say.
    expect(redactDetails(undefined)).toBeNull();
    expect(redactDetails(null)).toBeNull();
    expect(redactDetails({})).toBeNull();
    expect(redactDetails({ field: [] })).toBeNull();
  });

  it("keeps a structured payload that is not a validation failure", () => {
    /*
      Validation is not the only producer. The duplicate-SBOM refusal is a `ConflictError`
      carrying the existing scan's identity, and it is one of the more useful rows in the log
      — "this build was rejected because you already sent it, here is the one you already
      have" is the whole answer to the question the reader arrived with.
    */
    expect(
      redactDetails({
        existingScanId: "f0d7985f-0f3c-4f3c-9473-811e2ef80f40",
        existingScanCreatedAt: "2026-09-10T10:30:01.053Z",
        existingBuildNumber: "manual-1",
        existingIsLatest: true,
      }),
    ).toEqual({
      existingScanId: ["f0d7985f-0f3c-4f3c-9473-811e2ef80f40"],
      existingScanCreatedAt: ["2026-09-10T10:30:01.053Z"],
      existingBuildNumber: ["manual-1"],
      existingIsLatest: ["true"],
    });
  });

  it("keeps scalars rather than dropping them", () => {
    /*
      This was a real defect, found by reading the rendered page rather than the code: the
      boolean above was silently absent from every duplicate-refusal row, because the first
      version kept strings only. A field that quietly disappears is worse than one that is
      obviously missing — the row looks complete and is not.
    */
    expect(redactDetails({ attempts: 3, wasRetried: false })).toEqual({
      attempts: ["3"],
      wasRetried: ["false"],
    });
  });

  it("refuses shapes it does not understand instead of storing them verbatim", () => {
    /*
      `details` is typed `unknown` at the boundary and reaches this function straight from a
      thrown error, so a value of any shape can arrive. A nested object is dropped: storing
      one would be storing something whose contents were never reasoned about, and it is
      exactly where a credential would hide.
    */
    expect(redactDetails("a string")).toBeNull();
    expect(redactDetails(["an", "array"])).toBeNull();
    expect(redactDetails(42)).toBeNull();
    expect(redactDetails({ nested: { deep: "object" } })).toBeNull();
    expect(redactDetails({ nested: { token: "secret" }, good: "kept" })).toEqual({ good: ["kept"] });
  });

  it("accepts a bare string message as well as a list", () => {
    expect(redactDetails({ baseUrl: "required" })).toEqual({ baseUrl: ["required"] });
  });
});

describe("redacting the request path", () => {
  it("leaves an ordinary path and its query untouched", () => {
    // The query is usually the diagnostic half — which filter, which page, which sort.
    expect(redactPath("/api/v1/applications?page=2&sortBy=name")).toBe(
      "/api/v1/applications?page=2&sortBy=name",
    );
  });

  it("blanks a query parameter named like a credential", () => {
    const out = redactPath("/api/v1/scans?token=abc123&app=web");
    expect(out).not.toContain("abc123");
    expect(out).toContain("token=REDACTED");
    // The rest of the query still has to survive, or the redaction costs more than it saves.
    expect(out).toContain("app=web");
  });

  it("caps the stored length so one absurd URL cannot dominate the table", () => {
    expect(redactPath(`/api/v1/search?q=${"x".repeat(5000)}`).length).toBeLessThanOrEqual(500);
  });

  it("handles a path with no query at all", () => {
    expect(redactPath("/api/v1/vuln-status")).toBe("/api/v1/vuln-status");
  });
});
