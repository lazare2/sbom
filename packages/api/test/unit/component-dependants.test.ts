import { describe, expect, it } from "vitest";
import { COMPONENT_DEPENDANT_CAP, formatDependant } from "@sbom/shared";
import { parseCycloneDx } from "../../src/modules/ingestion/cyclonedx.js";

/**
 * What pulled a package in.
 *
 * A finding against a package nobody installed is unactionable on its own. Nothing names
 * `@fastify/error` in any manifest, so the developer looking at that row has nothing to
 * change; knowing that `fastify` and `avvio` depend on it names the thing to upgrade. This is
 * the whole value of the feature, and every guarantee below protects some part of it.
 *
 * ## The two failures worth pinning
 *
 * **Silently losing an edge.** Refs are not identities. Syft emits the same package twice when
 * it finds it in two layers, and the parser collapses those into one row — but the dependency
 * graph may still refer to the collapsed copy by its own bom-ref. Resolving refs only for
 * kept entries would drop exactly those edges, and nothing downstream would look wrong: the
 * dependants shown would be real, just not all of them.
 *
 * **Claiming an edge that is not there.** The opposite, and worse. A self-reference rendered
 * as "lodash is pulled in by lodash", or a dangling ref resolved to whatever happened to be
 * nearby, is a statement about somebody's dependency tree that they will act on.
 *
 * ## What this deliberately does not attempt
 *
 * Direct-versus-transitive. The document's root component carries no dependency entry — three
 * real SBOMs were checked and none had one — so nothing here can distinguish "you asked for
 * this" from "something else did". These are the immediate dependants and the contract says
 * only that.
 */

function component(over: {
  name: string;
  version?: string | null;
  ref?: string;
  purl?: string;
}) {
  return {
    type: "library",
    "bom-ref": over.ref ?? `ref-${over.name}`,
    name: over.name,
    ...(over.version === null ? {} : { version: over.version ?? "1.0.0" }),
    purl: over.purl ?? `pkg:npm/${over.name}@${over.version ?? "1.0.0"}`,
  };
}

function doc(components: unknown[], dependencies?: unknown) {
  return Buffer.from(
    JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components,
      ...(dependencies === undefined ? {} : { dependencies }),
    }),
    "utf8",
  );
}

function byName(parsed: ReturnType<typeof parseCycloneDx>, name: string) {
  const found = parsed.components.find((c) => c.name === name);
  expect(found, `component ${name} missing from parse`).toBeDefined();
  return found!;
}

describe("reading the dependency graph backwards", () => {
  it("names the packages that depend on a component", () => {
    const parsed = parseCycloneDx(
      doc(
        [component({ name: "fastify" }), component({ name: "avvio" }), component({ name: "error" })],
        [
          { ref: "ref-fastify", dependsOn: ["ref-error"] },
          { ref: "ref-avvio", dependsOn: ["ref-error"] },
        ],
      ),
    );

    expect(byName(parsed, "error").pulledInBy).toEqual(["avvio@1.0.0", "fastify@1.0.0"]);
    expect(byName(parsed, "error").pulledInByCount).toBe(2);
  });

  it("leaves a component with no incoming edge null, not empty", () => {
    /*
     * The distinction the whole null-versus-empty rule rests on. An empty array would be a
     * claim — "nothing depends on this" — and the renderer would be right to display it.
     * Null means no edge was recorded, which on a container image is true of every npm
     * package in the build because the lockfile the graph comes from is not in the image.
     */
    const parsed = parseCycloneDx(
      doc([component({ name: "fastify" }), component({ name: "error" })], [
        { ref: "ref-fastify", dependsOn: ["ref-error"] },
      ]),
    );

    expect(byName(parsed, "fastify").pulledInBy).toBeNull();
    expect(byName(parsed, "fastify").pulledInByCount).toBeNull();
  });

  it("records nothing at all when the document has no dependencies array", () => {
    // A hand-written SBOM, or any tool that does not emit the graph. Must not throw.
    const parsed = parseCycloneDx(doc([component({ name: "lodash" })]));
    expect(byName(parsed, "lodash").pulledInBy).toBeNull();
  });

  it("survives a malformed dependencies array rather than failing the whole ingest", () => {
    /*
     * An unparseable graph must cost the graph, never the scan. Losing the inventory of a
     * build because one entry was the wrong shape would be a far worse outcome than losing
     * the dependants, and ingest is called by CI with `curl -f`.
     */
    const parsed = parseCycloneDx(
      doc([component({ name: "lodash" })], [
        null,
        "nonsense",
        { ref: 42, dependsOn: ["ref-lodash"] },
        { ref: "ref-lodash" },
        { ref: "ref-lodash", dependsOn: "not-an-array" },
        { dependsOn: ["ref-lodash"] },
      ]),
    );
    expect(parsed.components).toHaveLength(1);
    expect(byName(parsed, "lodash").pulledInBy).toBeNull();
  });
});

describe("resolving refs to packages", () => {
  it("keeps an edge that names a duplicate entry collapsed into another", () => {
    /*
     * The silent-loss failure. Both entries are the same package by identity hash, so the
     * second is collapsed away — but the graph refers to it by its own ref. If refs were
     * recorded only for kept entries, this edge would vanish and `victim` would look as
     * though nothing depended on it.
     */
    const parsed = parseCycloneDx(
      doc(
        [
          component({ name: "fastify", ref: "fastify-layer-1" }),
          component({ name: "fastify", ref: "fastify-layer-2" }),
          component({ name: "victim" }),
        ],
        [{ ref: "fastify-layer-2", dependsOn: ["ref-victim"] }],
      ),
    );

    expect(parsed.duplicatesCollapsed).toBe(1);
    expect(byName(parsed, "victim").pulledInBy).toEqual(["fastify@1.0.0"]);
  });

  it("counts two refs for one package as a single dependant", () => {
    // The other half of the same fact: the duplicate must not be counted twice just because
    // it was listed twice. "Pulled in by fastify, fastify" is visibly wrong.
    const parsed = parseCycloneDx(
      doc(
        [
          component({ name: "fastify", ref: "fastify-a" }),
          component({ name: "fastify", ref: "fastify-b" }),
          component({ name: "victim" }),
        ],
        [
          { ref: "fastify-a", dependsOn: ["ref-victim"] },
          { ref: "fastify-b", dependsOn: ["ref-victim"] },
        ],
      ),
    );

    expect(byName(parsed, "victim").pulledInBy).toEqual(["fastify@1.0.0"]);
    expect(byName(parsed, "victim").pulledInByCount).toBe(1);
  });

  it("drops an edge whose parent is not a component we kept", () => {
    /*
     * The root component is the case that actually occurs: it has a bom-ref, it is not in the
     * components array, and in real Syft output it has no dependency entry either. Excluded
     * `file` entries are the same shape of problem. Resolving these to anything would be an
     * invented relationship.
     */
    const parsed = parseCycloneDx(
      doc([component({ name: "lodash" })], [
        { ref: "the-root-component", dependsOn: ["ref-lodash"] },
      ]),
    );
    expect(byName(parsed, "lodash").pulledInBy).toBeNull();
  });

  it("drops an edge pointing at a package that is not in the document", () => {
    const parsed = parseCycloneDx(
      doc([component({ name: "fastify" })], [
        { ref: "ref-fastify", dependsOn: ["ref-something-not-here"] },
      ]),
    );
    expect(parsed.components).toHaveLength(1);
    expect(byName(parsed, "fastify").pulledInBy).toBeNull();
  });

  it("never lists a package as its own dependant", () => {
    /*
     * Produced by real documents: two bom-refs for one package, one listed as depending on
     * the other. Both resolve to the same identity, and "lodash is pulled in by lodash" reads
     * as a bug in the platform rather than a quirk of the SBOM.
     */
    const parsed = parseCycloneDx(
      doc(
        [component({ name: "lodash", ref: "lodash-a" }), component({ name: "lodash", ref: "lodash-b" })],
        [{ ref: "lodash-a", dependsOn: ["lodash-b"] }],
      ),
    );
    expect(byName(parsed, "lodash").pulledInBy).toBeNull();
  });
});

describe("what gets stored", () => {
  it("caps the list and keeps the true total", () => {
    // Measured maximum on a real package was 71 dependants. A list that does not admit it is
    // truncated is read as complete, and removing the five shown looks sufficient when it is not.
    const parents = Array.from({ length: COMPONENT_DEPENDANT_CAP + 4 }, (_, i) =>
      component({ name: `parent-${i}` }),
    );
    const parsed = parseCycloneDx(
      doc(
        [...parents, component({ name: "victim" })],
        parents.map((p) => ({ ref: p["bom-ref"], dependsOn: ["ref-victim"] })),
      ),
    );

    const victim = byName(parsed, "victim");
    expect(victim.pulledInBy).toHaveLength(COMPONENT_DEPENDANT_CAP);
    expect(victim.pulledInByCount).toBe(COMPONENT_DEPENDANT_CAP + 4);
  });

  it("stores the same subset every time the same document is parsed", () => {
    /*
     * Sorting is what makes the cap deterministic. Without it the kept five would follow
     * document order, and re-ingesting an unchanged build would look like its dependency tree
     * had changed — the same reason the path list is sorted before it is capped.
     */
    const parents = Array.from({ length: 9 }, (_, i) => component({ name: `p${i}` }));
    const bytes = doc(
      [...parents, component({ name: "victim" })],
      parents.map((p) => ({ ref: p["bom-ref"], dependsOn: ["ref-victim"] })),
    );

    const first = byName(parseCycloneDx(bytes), "victim").pulledInBy;
    const second = byName(parseCycloneDx(bytes), "victim").pulledInBy;
    expect(first).toEqual(second);
    expect(first).toEqual([...first!].sort());
  });

  it("deduplicates a parent listed twice under one entry", () => {
    // Real Syft output does this — one document listed @types/node twice under a single parent.
    const parsed = parseCycloneDx(
      doc([component({ name: "fastify" }), component({ name: "victim" })], [
        { ref: "ref-fastify", dependsOn: ["ref-victim", "ref-victim"] },
      ]),
    );
    expect(byName(parsed, "victim").pulledInBy).toEqual(["fastify@1.0.0"]);
  });

  it("keeps OS-package edges, unlike locations", () => {
    /*
     * Locations are dropped for deb and apk because they point at the package manager's
     * database and locate nothing. A dependency edge from apt to adduser is a real
     * relationship and the same reasoning does not apply, so nothing filters by ecosystem here.
     */
    const parsed = parseCycloneDx(
      doc(
        [
          { type: "library", "bom-ref": "apt", name: "apt", version: "3.0.3", purl: "pkg:deb/debian/apt@3.0.3" },
          { type: "library", "bom-ref": "adduser", name: "adduser", version: "3.152", purl: "pkg:deb/debian/adduser@3.152" },
        ],
        [{ ref: "apt", dependsOn: ["adduser"] }],
      ),
    );
    expect(byName(parsed, "adduser").pulledInBy).toEqual(["apt@3.0.3"]);
  });

  it("names a versionless package by name alone rather than trailing an empty version", () => {
    // CycloneDX permits a component with no version. "thing@" would look like corrupt data.
    expect(formatDependant("thing", null)).toBe("thing");
    const parsed = parseCycloneDx(
      doc(
        [
          { type: "library", "bom-ref": "p", name: "parent", purl: "pkg:npm/parent" },
          component({ name: "child" }),
        ],
        [{ ref: "p", dependsOn: ["ref-child"] }],
      ),
    );
    expect(byName(parsed, "child").pulledInBy).toEqual(["parent"]);
  });
});
