import { describe, expect, it } from "vitest";
import type { ComponentRef } from "@sbom/shared";
import { pairVersionChanges } from "../../src/modules/diff/diff.service.js";

let nextId = 1;
function comp(name: string, version: string | null, ecosystem = "npm"): ComponentRef {
  return { id: String(nextId++), name, version, ecosystem, purl: `pkg:${ecosystem}/${name}@${version}` };
}

describe("pairVersionChanges", () => {
  it("folds a matching add and remove into one version change", () => {
    const result = pairVersionChanges([comp("log4j-core", "2.24.1")], [comp("log4j-core", "2.14.1")]);

    expect(result.changed).toEqual([
      expect.objectContaining({ name: "log4j-core", fromVersion: "2.14.1", toVersion: "2.24.1" }),
    ]);
    // Crucially, the raw rows are consumed rather than duplicated — otherwise a
    // routine upgrade would be reported three times.
    expect(result.added).toEqual([]);
    expect(result.removed).toEqual([]);
  });

  it("leaves a genuinely new package in `added`", () => {
    const result = pairVersionChanges([comp("left-pad", "1.3.0")], []);
    expect(result.added).toHaveLength(1);
    expect(result.changed).toEqual([]);
  });

  it("leaves a genuinely dropped package in `removed`", () => {
    const result = pairVersionChanges([], [comp("request", "2.88.2")]);
    expect(result.removed).toHaveLength(1);
    expect(result.changed).toEqual([]);
  });

  it("matches package names case-insensitively", () => {
    const result = pairVersionChanges([comp("Log4J-Core", "2.24.1")], [comp("log4j-core", "2.14.1")]);
    expect(result.changed).toHaveLength(1);
  });

  it("does not pair packages of the same name in different ecosystems", () => {
    // `pkg:npm/redis` and `pkg:deb/redis` are unrelated software that happen to
    // share a name. Reporting one as an upgrade of the other would be a lie.
    const result = pairVersionChanges([comp("redis", "4.6.0", "npm")], [comp("redis", "6.0.16", "deb")]);
    expect(result.changed).toEqual([]);
    expect(result.added).toHaveLength(1);
    expect(result.removed).toHaveLength(1);
  });

  it("refuses to guess when the pairing is ambiguous", () => {
    // Two versions added and one removed: which of the two is "the upgrade" has
    // no defensible answer, so all three stay in the raw lists rather than
    // being paired arbitrarily.
    const result = pairVersionChanges(
      [comp("openssl", "3.0.14", "deb"), comp("openssl", "1.1.1w", "deb")],
      [comp("openssl", "3.0.11", "deb")],
    );
    expect(result.changed).toEqual([]);
    expect(result.added).toHaveLength(2);
    expect(result.removed).toHaveLength(1);
  });

  it("carries both component ids so each side stays linkable", () => {
    const to = comp("axios", "1.7.9");
    const from = comp("axios", "1.6.0");
    const result = pairVersionChanges([to], [from]);

    expect(result.changed[0]?.fromComponentId).toBe(from.id);
    expect(result.changed[0]?.toComponentId).toBe(to.id);
  });

  it("handles a package whose version is unknown on one side", () => {
    // CycloneDX permits a component with no resolvable version; it must not
    // crash the pairing or vanish from the diff.
    const result = pairVersionChanges([comp("mystery", null)], [comp("mystery", "1.0.0")]);
    expect(result.changed).toEqual([
      expect.objectContaining({ fromVersion: "1.0.0", toVersion: null }),
    ]);
  });

  it("sorts version changes by name so the list is stable between builds", () => {
    const result = pairVersionChanges(
      [comp("zod", "3.24.1"), comp("axios", "1.7.9")],
      [comp("zod", "3.23.0"), comp("axios", "1.6.0")],
    );
    expect(result.changed.map((c) => c.name)).toEqual(["axios", "zod"]);
  });

  it("returns everything untouched when nothing matches", () => {
    const result = pairVersionChanges([comp("a", "1")], [comp("b", "1")]);
    expect(result.added).toHaveLength(1);
    expect(result.removed).toHaveLength(1);
    expect(result.changed).toEqual([]);
  });
});
