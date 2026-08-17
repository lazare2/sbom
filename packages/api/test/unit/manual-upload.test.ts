import { describe, expect, it } from "vitest";
import { manualUploadFieldsSchema } from "@sbom/shared";

/**
 * The metadata contract for `POST /api/v1/applications/:id/scans`.
 *
 * Small surface, but two of these behaviours are load-bearing and silently
 * reversible: the duplicate guard defaults to on, and a CI-style empty form field
 * must read as absent rather than as an empty string. Both would break without
 * failing anything visible.
 */
describe("manualUploadFieldsSchema", () => {
  it("defaults allow_duplicate to false", () => {
    // The safety default. If this ever flips, a double-clicked upload button
    // silently records two identical builds instead of returning a 409, and
    // nothing else in the system would complain.
    const parsed = manualUploadFieldsSchema.parse({});
    expect(parsed.allow_duplicate).toBe(false);
  });

  it("accepts an explicit opt-in to duplicates", () => {
    expect(manualUploadFieldsSchema.parse({ allow_duplicate: "true" }).allow_duplicate).toBe(true);
    expect(manualUploadFieldsSchema.parse({ allow_duplicate: "false" }).allow_duplicate).toBe(false);
  });

  it("rejects a value it cannot interpret rather than guessing", () => {
    // `1`, `yes` and `TRUE` all mean true to a human, and all of them would be
    // read as false by a looser `=== "true"` check — an opt-in that silently does
    // not opt in. A 400 tells the caller instead.
    for (const value of ["1", "yes", "TRUE", "on"]) {
      expect(manualUploadFieldsSchema.safeParse({ allow_duplicate: value }).success, value).toBe(false);
    }
  });

  it("treats an empty form field as absent", () => {
    // Browsers and CI templates both submit unset text inputs as empty strings.
    // Storing "" would put an empty commit sha and branch on the scan row, which
    // reads as "known to be empty" rather than "not supplied".
    const parsed = manualUploadFieldsSchema.parse({
      commit_sha: "",
      build_number: "",
      branch: "",
      image_ref: "",
      note: "",
    });
    expect(parsed.commit_sha).toBeUndefined();
    expect(parsed.build_number).toBeUndefined();
    expect(parsed.branch).toBeUndefined();
    expect(parsed.image_ref).toBeUndefined();
    expect(parsed.note).toBeUndefined();
  });

  it("trims surrounding whitespace", () => {
    const parsed = manualUploadFieldsSchema.parse({ build_number: "  402  ", branch: " main " });
    expect(parsed.build_number).toBe("402");
    expect(parsed.branch).toBe("main");
  });

  it("caps the note so it cannot be used as free storage", () => {
    expect(manualUploadFieldsSchema.safeParse({ note: "x".repeat(500) }).success).toBe(true);
    expect(manualUploadFieldsSchema.safeParse({ note: "x".repeat(501) }).success).toBe(false);
  });

  it("does not accept an app_name", () => {
    /*
     * The target application comes from the URL. A stray `app_name` field must not
     * become a second, competing way to choose it — that would reintroduce the CI
     * path's name resolution (aliases, auto-creation) on a route whose whole point
     * is that the user already picked the application.
     *
     * Zod strips unknown keys by default, so this asserts the absence of a
     * passthrough rather than a rejection.
     */
    const parsed = manualUploadFieldsSchema.parse({ app_name: "some-other-app" });
    expect(parsed).not.toHaveProperty("app_name");
  });
});
