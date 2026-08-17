import { describe, expect, it } from "vitest";
import { BULK_SEARCH_MAX_ENTRIES } from "@sbom/shared";
import { parseBulkInput } from "../../src/modules/components/bulk-parse.js";

/** Parses one line and returns the single entry, failing loudly if it was rejected. */
function one(line: string) {
  const { entries, summary } = parseBulkInput(line);
  expect(summary.problems, `unexpected problem for "${line}"`).toEqual([]);
  expect(entries).toHaveLength(1);
  return entries[0]!;
}

function rejected(line: string) {
  const { entries, summary } = parseBulkInput(line);
  expect(entries).toEqual([]);
  expect(summary.problems).toHaveLength(1);
  return summary.problems[0]!;
}

describe("parseBulkInput — the documented format", () => {
  it("reads the exact list from the feature request", () => {
    const { entries, summary } = parseBulkInput(
      ["logaas", "@wb-track/shared-front", "cnapp-ui", "keyv@6.0.0"].join("\n"),
    );

    expect(summary.problems).toEqual([]);
    expect(summary.lines).toBe(4);
    expect(summary.entries).toBe(4);
    expect(entries.map((e) => [e.name, e.version, e.versionKind])).toEqual([
      ["logaas", null, "any"],
      // The trap: a leading @ is an npm scope, not a version separator.
      ["@wb-track/shared-front", null, "any"],
      ["cnapp-ui", null, "any"],
      ["keyv", "6.0.0", "exact"],
    ]);
  });

  it("splits a scoped name that also carries a version", () => {
    // Two @ signs: the first is the scope, the last is the separator. A
    // `split("@")` gets this wrong in both directions.
    expect(one("@wb-track/shared-front@2.1.0")).toMatchObject({
      name: "@wb-track/shared-front",
      version: "2.1.0",
      versionKind: "exact",
    });
  });

  it("keeps a bare name as a match on every version", () => {
    expect(one("express")).toMatchObject({ name: "express", version: null, versionKind: "any" });
  });

  it("ignores blank lines and comments without counting them", () => {
    const { entries, summary } = parseBulkInput(
      ["# from CVE-2024-1234", "", "express@4.19.2", "   ", "// noise", "lodash"].join("\n"),
    );
    expect(summary.lines).toBe(2);
    expect(entries.map((e) => e.name)).toEqual(["express", "lodash"]);
  });

  it("reports the line number of each entry, for pointing at problems", () => {
    const { entries } = parseBulkInput(["", "# note", "express", "", "lodash"].join("\n"));
    expect(entries.map((e) => e.line)).toEqual([3, 5]);
  });

  it("handles CRLF and bare CR line endings", () => {
    expect(parseBulkInput("express\r\nlodash\rkeyv").entries.map((e) => e.name)).toEqual([
      "express",
      "lodash",
      "keyv",
    ]);
  });

  it("strips trailing commas and semicolons left by copying out of code", () => {
    const { entries } = parseBulkInput(["'express',", '"lodash";'].join("\n"));
    expect(entries.map((e) => e.name)).toEqual(["'express'", '"lodash"']);
  });
});

describe("parseBulkInput — ecosystem-native formats", () => {
  it("reads a pip pin as an exact version", () => {
    expect(one("django==4.2.1")).toMatchObject({
      name: "django",
      version: "4.2.1",
      versionKind: "exact",
    });
    expect(one("django===4.2.1")).toMatchObject({ version: "4.2.1", versionKind: "exact" });
  });

  it("reads a pip pin written with spaces", () => {
    // `requirements.txt` in the wild is not consistently unspaced.
    expect(one("django >= 4.2")).toMatchObject({ name: "django", versionKind: "version-ignored" });
    expect(one("django == 4.2.1")).toMatchObject({
      name: "django",
      version: "4.2.1",
      versionKind: "exact",
    });
  });

  it("reads whitespace-, tab- and comma-separated columns", () => {
    for (const line of ["express 4.19.2", "express\t4.19.2", "express,4.19.2"]) {
      expect(one(line), line).toMatchObject({
        name: "express",
        version: "4.19.2",
        versionKind: "exact",
      });
    }
  });

  it("reads a purl, and takes the ecosystem from it", () => {
    expect(one("pkg:npm/keyv@6.0.0")).toMatchObject({
      name: "keyv",
      version: "6.0.0",
      ecosystem: "npm",
      versionKind: "exact",
    });
    // A scoped name inside a purl keeps its @.
    expect(one("pkg:npm/@wb-track/shared-front@2.1.0")).toMatchObject({
      name: "@wb-track/shared-front",
      version: "2.1.0",
      ecosystem: "npm",
    });
    // Qualifiers describe the artifact, not the identity being matched here.
    expect(one("pkg:deb/debian/openssl@3.0.14-1?arch=amd64")).toMatchObject({
      version: "3.0.14-1",
      ecosystem: "deb",
    });
  });

  it("reads a maven coordinate under its artifact id", () => {
    // Syft catalogues maven components by artifact, which is what `component` holds.
    //
    // The ecosystem must be `maven`, the purl type — not `java-archive`, which is
    // Syft's package-type property and matches no `component.ecosystem` value.
    // Getting this wrong made every maven coordinate silently return nothing.
    expect(one("com.fasterxml.jackson.core:jackson-databind:2.17.2")).toMatchObject({
      name: "jackson-databind",
      version: "2.17.2",
      ecosystem: "maven",
      versionKind: "exact",
    });
  });

  it("does not guess at a two-part colon form", () => {
    // `a:b` cannot be told apart from a package name containing a colon, so it
    // stays a name rather than being split on a guess.
    expect(one("group:artifact")).toMatchObject({ name: "group:artifact", version: null });
  });

  it("treats a colon-heavy name without a group-like prefix as a name", () => {
    expect(one("no-dots:artifact:1.0.0")).toMatchObject({ name: "no-dots:artifact:1.0.0" });
  });
});

describe("parseBulkInput — version specifiers that are not a version", () => {
  it("drops a range and matches the name across all versions", () => {
    // The safe direction: matching 4.2 exactly would be silently wrong, and
    // dropping the line would hide a real hit.
    for (const line of ["django>=4.2", "express@^1.2.3", "requests~=2.31", "left-pad<1.3.0"]) {
      const entry = one(line);
      expect(entry.versionKind, line).toBe("version-ignored");
      expect(entry.version, line).not.toBeNull();
    }
  });

  it("parses the @ separator before an operator", () => {
    // `express@^1.2.3`: reading the ^ as the separator would leave the name as
    // "express@", which matches nothing and looks like a data problem.
    expect(one("express@^1.2.3")).toMatchObject({ name: "express", version: "1.2.3" });
    expect(one("@scope/pkg@>=2.0.0")).toMatchObject({ name: "@scope/pkg", version: "2.0.0" });
  });

  it("drops a wildcard pin", () => {
    expect(one("django==4.2.*")).toMatchObject({ version: "4.2", versionKind: "version-ignored" });
  });

  it("drops a negation rather than inverting it", () => {
    expect(one("django!=4.2.1")).toMatchObject({ versionKind: "version-ignored" });
  });

  it("shows a dist-tag but does not match on it", () => {
    // `express@latest` must not report express as absent just because no version
    // is literally called "latest".
    expect(one("express@latest")).toMatchObject({
      name: "express",
      version: "latest",
      versionKind: "version-ignored",
    });
  });

  it("normalises a leading v, which no ecosystem puts in a version field", () => {
    expect(one("express@v4.19.2")).toMatchObject({ version: "4.19.2", versionKind: "exact" });
  });

  it("counts the entries whose specifier was dropped", () => {
    const { summary } = parseBulkInput(["express@^1", "lodash@4.17.21", "keyv@latest"].join("\n"));
    expect(summary.constraintsDropped).toBe(2);
  });

  it("treats a trailing @ as a typo, not a version", () => {
    expect(one("express@")).toMatchObject({ name: "express", version: null, versionKind: "any" });
  });

  it("accepts distro version forms unchanged", () => {
    expect(one("zlib1g@1:1.2.13.dfsg-1")).toMatchObject({ version: "1:1.2.13.dfsg-1" });
    expect(one("openssl@3.0.14-1~deb12u2")).toMatchObject({ version: "3.0.14-1~deb12u2" });
    expect(one("guava@33.3.1-jre")).toMatchObject({ version: "33.3.1-jre" });
  });
});

describe("parseBulkInput — rejections", () => {
  it("rejects a line with more than two fields", () => {
    expect(rejected("express 4.19.2 extra").reason).toContain("one package on each line");
  });

  it("rejects a second field that is not a version", () => {
    // Two words is far more likely a sentence than a package and a version.
    expect(rejected("my package").reason).toContain("does not look like a version");
  });

  it("rejects a URL", () => {
    expect(rejected("https://registry.npmjs.org/express").reason).toContain("URL");
  });

  it("rejects two versions on one line", () => {
    expect(rejected("express@1.0.0 2.0.0").reason).toContain("two versions");
  });

  it("keeps parsing the rest of the list after a bad line", () => {
    // One malformed line must not cost the other 199.
    const { entries, summary } = parseBulkInput(
      ["express", "this is not a package at all", "lodash"].join("\n"),
    );
    expect(entries.map((e) => e.name)).toEqual(["express", "lodash"]);
    expect(summary.problems).toHaveLength(1);
    expect(summary.problems[0]!.line).toBe(2);
    expect(summary.problems[0]!.raw).toBe("this is not a package at all");
  });
});

describe("parseBulkInput — deduplication", () => {
  it("collapses case-insensitive duplicates", () => {
    // Matching is case-insensitive, so running both would produce two identical
    // rows.
    const { entries, summary } = parseBulkInput(["express", "Express", "EXPRESS"].join("\n"));
    expect(entries).toHaveLength(1);
    expect(summary.duplicatesCollapsed).toBe(2);
  });

  it("keeps two different versions of the same package apart", () => {
    const { entries } = parseBulkInput(["express@4.19.2", "express@4.18.0"].join("\n"));
    expect(entries.map((e) => e.version)).toEqual(["4.19.2", "4.18.0"]);
  });

  it("collapses a dropped-specifier entry into the bare name", () => {
    // Both ask the database the same question — every version of express — so
    // keeping both would duplicate a row for no reason.
    const { entries, summary } = parseBulkInput(["express", "express@^4"].join("\n"));
    expect(entries).toHaveLength(1);
    expect(summary.duplicatesCollapsed).toBe(1);
  });

  it("does not collapse the same name in different ecosystems", () => {
    const { entries } = parseBulkInput(["pkg:npm/keyv@6.0.0", "pkg:pypi/keyv@6.0.0"].join("\n"));
    expect(entries).toHaveLength(2);
  });
});

describe("parseBulkInput — limits", () => {
  it("caps the list and says so", () => {
    const input = Array.from({ length: BULK_SEARCH_MAX_ENTRIES + 50 }, (_v, i) => `pkg-${i}`).join("\n");
    const { entries, summary } = parseBulkInput(input);
    expect(entries).toHaveLength(BULK_SEARCH_MAX_ENTRIES);
    expect(summary.entries).toBe(BULK_SEARCH_MAX_ENTRIES);
    expect(summary.truncated).toBe(true);
  });

  it("does not report truncation for a list that fits", () => {
    const { summary } = parseBulkInput(["express", "lodash"].join("\n"));
    expect(summary.truncated).toBe(false);
  });

  it("returns nothing for empty input rather than throwing", () => {
    const { entries, summary } = parseBulkInput("\n\n#only a comment\n");
    expect(entries).toEqual([]);
    expect(summary.lines).toBe(0);
    expect(summary.entries).toBe(0);
  });
});
