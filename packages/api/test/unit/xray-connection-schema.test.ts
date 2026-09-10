/*
  What the platform will accept as the address of a JFrog Xray.

  This value is handed to an HTTP client with a credential attached, so the schema is the
  place where anything that could redirect that credential has to be stopped. But it is also
  the gate every administrator meets before the feature works at all, and the failure that
  motivated this file was the gate itself: `http` was refused for any non-loopback host, and
  the one server the provider was written for is an Artifactory published on port 80.

  The refusal protected nothing -- there was no https listener to fall back to -- and arrived
  in the browser as "Body validation failed" with no field named, so the cause was invisible.

  Both halves are pinned here: that a plaintext URL is accepted, and that the narrowing which
  genuinely matters still rejects. The messages are asserted too, because an unreadable
  rejection is the same defect wearing a different hat.
*/
import { describe, expect, it } from "vitest";
import { xrayBaseUrlSchema, xrayUrlIsPlaintext } from "@sbom/shared";

/** The field-level messages, as `parseOrThrow` would collect them for the client. */
function reject(value: string): string[] {
  const result = xrayBaseUrlSchema.safeParse(value);
  expect(result.success, `expected ${value} to be rejected`).toBe(false);
  return result.success ? [] : result.error.issues.map((i) => i.message);
}

function accept(value: string): string {
  const result = xrayBaseUrlSchema.safeParse(value);
  expect(result.success, `expected ${value} to be accepted`).toBe(true);
  return result.success ? result.data : "";
}

describe("the Xray base URL", () => {
  it("accepts a plain http host, because that is how Artifactory is often published", () => {
    // The regression guard. This exact shape is what a corporate Artifactory looks like.
    accept("http://repository.example.com");
  });

  it("accepts http on an explicit port", () => {
    accept("http://artifactory.internal:8081");
  });

  it("accepts https, with and without a port", () => {
    accept("https://artifactory.example.org");
    accept("https://artifactory.example.org:8443");
  });

  it("accepts a path, since Artifactory is often mounted under one", () => {
    accept("https://artifactory.example.org/artifactory");
  });

  it("trims surrounding whitespace rather than rejecting a pasted value", () => {
    // Pasting from a wiki or a ticket routinely brings a trailing space with it, and
    // failing on that would be a rejection nobody can see.
    expect(accept("  https://artifactory.example.org  ")).toBe("https://artifactory.example.org");
  });

  it("rejects a bare hostname, and says a scheme is what is missing", () => {
    const messages = reject("artifactory.example.org");
    expect(messages.join(" ")).toMatch(/http:\/\/ or https:\/\//);
  });

  it("rejects a URL carrying its own credentials", () => {
    /*
      Two identities in one request is never what was meant, and the one in the URL would
      travel somewhere the token fields never chose. The message sends the reader to the
      fields below rather than just refusing.
    */
    const messages = reject("https://someone:secret@artifactory.example.org");
    expect(messages.join(" ")).toMatch(/Credentials go in the fields below/);
  });

  it("rejects a scheme that is not http or https", () => {
    // `file:` and `ftp:` parse as valid URLs, so this cannot be left to the URL constructor.
    expect(reject("ftp://artifactory.example.org").join(" ")).toMatch(/not supported/);
    expect(reject("file:///etc/passwd").join(" ")).toMatch(/not supported/);
  });

  it("rejects an empty value", () => {
    reject("");
    reject("   ");
  });
});

describe("whether a URL exposes the token", () => {
  /*
    What the screen warns from. The warning has to be accurate in both directions: a missing
    warning understates a real exposure, and a warning on loopback is noise that teaches
    people to ignore the one that matters.
  */

  it("is true for plain http to another machine", () => {
    expect(xrayUrlIsPlaintext("http://repository.example.com")).toBe(true);
    expect(xrayUrlIsPlaintext("http://artifactory.internal:8081")).toBe(true);
  });

  it("is false for https", () => {
    expect(xrayUrlIsPlaintext("https://artifactory.example.org")).toBe(false);
  });

  it("is false for loopback, where the traffic never reaches an interface", () => {
    expect(xrayUrlIsPlaintext("http://localhost:8081")).toBe(false);
    expect(xrayUrlIsPlaintext("http://127.0.0.1:8081")).toBe(false);
  });

  it("is false for a value that is not a URL at all", () => {
    // Called on every keystroke while a URL is being typed, so a half-typed value must not
    // throw -- and must not claim an exposure it cannot know about.
    expect(xrayUrlIsPlaintext("http:/")).toBe(false);
    expect(xrayUrlIsPlaintext("")).toBe(false);
  });
});
