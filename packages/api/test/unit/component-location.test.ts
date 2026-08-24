import { describe, expect, it } from "vitest";
import {
  classifyComponentOrigin,
  ecosystemHasMeaningfulPaths,
  normalizeLocationPath,
  COMPONENT_LOCATION_PATH_CAP,
} from "@sbom/shared";
import { parseCycloneDx } from "../../src/modules/ingestion/cyclonedx.js";

/**
 * Where a package is, and whether it belongs to the application or to the image underneath it.
 *
 * Two separate guarantees are pinned here, and they fail in different ways.
 *
 * The **origin classifier** decides which of those two answers a reader is given. It is the
 * only heuristic in the feature, and the failure it must not have is the quiet one: telling
 * somebody a package they installed came from the base image sends them to argue with the
 * platform team about a Dockerfile they do not own. The guard against that is not accuracy
 * alone — it is that the path is always rendered next to the label, so a wrong answer is
 * visibly wrong. What is pinned here is the classification of the prefixes that actually occur.
 *
 * The **parser** decides whether there is a location to show at all, and its dangerous failure
 * is silent loss. Syft emits the same package more than once when it finds it in two layers or
 * via two catalogers, and those duplicate entries are exactly the ones carrying a location the
 * first entry did not have. Collapsing duplicates without merging their locations — which is
 * what the parser did before this feature — discards multi-location data on precisely the
 * packages installed in more than one place. Nothing about that failure is visible downstream:
 * the path shown is real, it is just not the only one.
 */

// ---------------------------------------------------------------------------
// Origin classification
// ---------------------------------------------------------------------------

describe("classifyComponentOrigin", () => {
  it("calls an OS-ecosystem package base image without consulting any path", () => {
    // deb and apk record the package manager's database, not the package. Every apk package in
    // an image reports the identical `/lib/apk/db/installed`, so a path-based answer here would
    // be derived from a value that distinguishes nothing.
    expect(classifyComponentOrigin({ ecosystem: "deb", paths: null })).toBe("os_package");
    expect(classifyComponentOrigin({ ecosystem: "apk", paths: ["/lib/apk/db/installed"] })).toBe(
      "os_package",
    );
    expect(classifyComponentOrigin({ ecosystem: "rpm", paths: null })).toBe("os_package");
  });

  it("calls the distro marker a base-image package despite its unknown ecosystem", () => {
    // The `alpine` / `debian` operating-system component is stored with ecosystem `unknown`
    // and carries no path. Without the `kind` short-circuit it would land in `unknown`, which
    // is technically true and useless: it is the one component whose origin is never in doubt.
    expect(classifyComponentOrigin({ ecosystem: "unknown", paths: null, kind: "os" })).toBe(
      "os_package",
    );
  });

  it("puts a language runtime's global packages in the image, not the application", () => {
    // This is the case that motivated abandoning the layer-based rule. In node:20-alpine these
    // 203 npm packages sit in a layer containing no distro packages at all, so "the layer with
    // apk in it is the base image" labels them application dependencies — wrong for anyone
    // whose Dockerfile says FROM node:20-alpine.
    expect(
      classifyComponentOrigin({
        ecosystem: "npm",
        paths: ["/usr/local/lib/node_modules/npm/node_modules/@isaacs/cliui/package.json"],
      }),
    ).toBe("image");

    expect(
      classifyComponentOrigin({
        ecosystem: "pypi",
        paths: ["/usr/local/lib/python3.12/site-packages/pip/_vendor/distlib/t64.exe"],
      }),
    ).toBe("image");

    expect(classifyComponentOrigin({ ecosystem: "npm", paths: ["/opt/yarn-v1.22.22/package.json"] })).toBe(
      "image",
    );
  });

  it("treats the common application WORKDIRs as application, including /usr/src/app", () => {
    // `/usr/src/app` is the trap. A bare `/usr/` prefix in the image list would misfile every
    // dependency of every application using it — and it is one of the most common WORKDIRs
    // there is, so the mistake would land hardest on ordinary deployments.
    for (const path of [
      "/app/node_modules/left-pad/package.json",
      "/usr/src/app/node_modules/left-pad/package.json",
      "/home/node/app/node_modules/left-pad/package.json",
      "/srv/app/vendor/bundle/left-pad.gemspec",
      "/workspace/requirements.txt",
    ]) {
      expect(classifyComponentOrigin({ ecosystem: "npm", paths: [path] })).toBe("application");
    }
  });

  it("resolves a disagreement between paths in favour of the application", () => {
    // A package present in both places is a dependency this application has, whatever else in
    // the image also carries a copy. Answering "image" here would hide the copy the reader can
    // actually do something about.
    expect(
      classifyComponentOrigin({
        ecosystem: "npm",
        paths: ["/usr/local/lib/node_modules/lodash/package.json", "/app/node_modules/lodash/package.json"],
      }),
    ).toBe("application");
  });

  it("says unknown rather than guessing when no path was recorded", () => {
    // The whole point of the fourth value. A non-Syft SBOM carries no locations, and answering
    // either "application" or "image" there would be an invention rather than a reading.
    expect(classifyComponentOrigin({ ecosystem: "npm", paths: null })).toBe("unknown");
    expect(classifyComponentOrigin({ ecosystem: "npm", paths: [] })).toBe("unknown");
  });

  it("treats a bare relative path from a directory scan as application", () => {
    // A directory scan has no image to be part of, so everything it finds is the application.
    // Syft on Windows reports `\package-lock.json`, which must not fall through to unknown.
    expect(classifyComponentOrigin({ ecosystem: "npm", paths: ["\\package-lock.json"] })).toBe(
      "application",
    );
    expect(classifyComponentOrigin({ ecosystem: "npm", paths: ["package-lock.json"] })).toBe(
      "application",
    );
  });
});

describe("ecosystemHasMeaningfulPaths", () => {
  it("excludes OS package managers and keeps language ecosystems", () => {
    for (const eco of ["deb", "rpm", "apk", "alpm", "portage", "nix"]) {
      expect(ecosystemHasMeaningfulPaths(eco)).toBe(false);
    }
    for (const eco of ["npm", "pypi", "gem", "maven", "golang", "generic"]) {
      expect(ecosystemHasMeaningfulPaths(eco)).toBe(true);
    }
  });

  it("does not exclude runtimes, whose path is a real location", () => {
    // `/usr/local/bin/node` locates the binary. Folding runtimes in with OS packages — which
    // `isBaseImagePackage` does, for a different and correct purpose — would throw it away.
    expect(ecosystemHasMeaningfulPaths("generic")).toBe(true);
    expect(classifyComponentOrigin({ ecosystem: "generic", paths: ["/usr/local/bin/node"], kind: "runtime" })).toBe(
      "image",
    );
  });
});

describe("normalizeLocationPath", () => {
  it("folds backslashes and anchors a relative path", () => {
    expect(normalizeLocationPath("\\package-lock.json")).toBe("/package-lock.json");
    expect(normalizeLocationPath("app\\node_modules\\x")).toBe("/app/node_modules/x");
    expect(normalizeLocationPath("/already/absolute")).toBe("/already/absolute");
  });

  it("rejects an empty or whitespace-only value rather than returning a bare slash", () => {
    expect(normalizeLocationPath("")).toBeNull();
    expect(normalizeLocationPath("   ")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Parser extraction
// ---------------------------------------------------------------------------

/** A CycloneDX component carrying Syft's location properties. */
function component(over: {
  name: string;
  purl?: string;
  type?: string;
  syftType?: string;
  locations?: Array<{ path: string; layerID?: string }>;
}) {
  const properties: Array<{ name: string; value: string }> = [];
  if (over.syftType) properties.push({ name: "syft:package:type", value: over.syftType });
  (over.locations ?? []).forEach((loc, i) => {
    properties.push({ name: `syft:location:${i}:path`, value: loc.path });
    if (loc.layerID) properties.push({ name: `syft:location:${i}:layerID`, value: loc.layerID });
  });
  return {
    type: over.type ?? "library",
    name: over.name,
    version: "1.0.0",
    purl: over.purl ?? `pkg:npm/${over.name}@1.0.0`,
    properties,
  };
}

function doc(components: unknown[]) {
  return Buffer.from(
    JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components }),
    "utf8",
  );
}

describe("parseCycloneDx location extraction", () => {
  it("records the path and layer of a located component", () => {
    const parsed = parseCycloneDx(
      doc([
        component({
          name: "left-pad",
          syftType: "npm",
          locations: [{ path: "/app/node_modules/left-pad/package.json", layerID: "sha256:aaa" }],
        }),
      ]),
    );

    expect(parsed.components).toHaveLength(1);
    expect(parsed.components[0]!.paths).toEqual(["/app/node_modules/left-pad/package.json"]);
    expect(parsed.components[0]!.pathCount).toBe(1);
    expect(parsed.components[0]!.layerId).toBe("sha256:aaa");
  });

  it("merges locations from duplicate entries instead of discarding them", () => {
    // The regression this whole test file exists for. Both entries are the same package by
    // identity hash, so the second collapses into the first — and it is the second that
    // carries the /app copy. Before the merge, that path was silently lost.
    const parsed = parseCycloneDx(
      doc([
        component({
          name: "left-pad",
          syftType: "npm",
          locations: [{ path: "/usr/local/lib/node_modules/left-pad/package.json", layerID: "sha256:base" }],
        }),
        component({
          name: "left-pad",
          syftType: "npm",
          locations: [{ path: "/app/node_modules/left-pad/package.json", layerID: "sha256:app" }],
        }),
      ]),
    );

    expect(parsed.components).toHaveLength(1);
    expect(parsed.duplicatesCollapsed).toBe(1);
    expect(parsed.components[0]!.paths).toEqual([
      "/app/node_modules/left-pad/package.json",
      "/usr/local/lib/node_modules/left-pad/package.json",
    ]);
    expect(parsed.components[0]!.pathCount).toBe(2);

    // And the merge changes the answer, which is the reason it matters: on the first entry
    // alone this package reads as inherited from the base image.
    expect(
      classifyComponentOrigin({
        ecosystem: parsed.components[0]!.ecosystem,
        paths: parsed.components[0]!.paths,
      }),
    ).toBe("application");
  });

  it("caps the stored paths but reports the true total", () => {
    const many = Array.from({ length: 9 }, (_, i) => ({ path: `/app/copy-${i}/package.json` }));
    const parsed = parseCycloneDx(doc([component({ name: "sprawl", syftType: "npm", locations: many })]));

    expect(parsed.components[0]!.paths).toHaveLength(COMPONENT_LOCATION_PATH_CAP);
    // "3 of 9", not "3" — a truncated list that does not say so implies it is complete.
    expect(parsed.components[0]!.pathCount).toBe(9);
  });

  it("stores paths in a deterministic order so a re-ingest is not read as a move", () => {
    const forwards = parseCycloneDx(
      doc([
        component({
          name: "order",
          syftType: "npm",
          locations: [{ path: "/app/b/package.json" }, { path: "/app/a/package.json" }],
        }),
      ]),
    );
    const backwards = parseCycloneDx(
      doc([
        component({
          name: "order",
          syftType: "npm",
          locations: [{ path: "/app/a/package.json" }, { path: "/app/b/package.json" }],
        }),
      ]),
    );

    expect(forwards.components[0]!.paths).toEqual(backwards.components[0]!.paths);
    expect(forwards.components[0]!.paths).toEqual(["/app/a/package.json", "/app/b/package.json"]);
  });

  it("deduplicates a path reported by two catalogers", () => {
    const parsed = parseCycloneDx(
      doc([
        component({ name: "twice", syftType: "npm", locations: [{ path: "/app/x/package.json" }] }),
        component({ name: "twice", syftType: "npm", locations: [{ path: "/app/x/package.json" }] }),
      ]),
    );

    expect(parsed.components[0]!.paths).toEqual(["/app/x/package.json"]);
    // Not 2. The count is of distinct locations, so it cannot be inflated by a package being
    // catalogued twice in the same place.
    expect(parsed.components[0]!.pathCount).toBe(1);
  });

  it("stores no path for an OS package even though the SBOM carries one", () => {
    // `/var/lib/dpkg/status` is where dpkg keeps its records, not where libc lives. Storing it
    // would put a path on screen that sends the reader to the wrong file.
    const parsed = parseCycloneDx(
      doc([
        {
          type: "library",
          name: "libc6",
          version: "2.36-9",
          purl: "pkg:deb/debian/libc6@2.36-9?arch=amd64",
          properties: [
            { name: "syft:package:type", value: "deb" },
            { name: "syft:location:0:path", value: "/var/lib/dpkg/status" },
            { name: "syft:location:1:path", value: "/var/lib/dpkg/info/libc6.list" },
          ],
        },
      ]),
    );

    expect(parsed.components[0]!.ecosystem).toBe("deb");
    expect(parsed.components[0]!.paths).toBeNull();
    // Null, not 0. Zero would say "this package is nowhere", which is a claim about the image
    // rather than about what the SBOM records.
    expect(parsed.components[0]!.pathCount).toBeNull();
  });

  it("leaves paths null for an SBOM that carries no locations at all", () => {
    const parsed = parseCycloneDx(
      doc([{ type: "library", name: "plain", version: "1.0.0", purl: "pkg:npm/plain@1.0.0" }]),
    );

    expect(parsed.components[0]!.paths).toBeNull();
    expect(parsed.components[0]!.pathCount).toBeNull();
    expect(parsed.components[0]!.layerId).toBeNull();
  });

  it("reads location indices that are out of order or non-contiguous", () => {
    // Nothing in CycloneDX promises the properties array is ordered, and a missed location is
    // a place the reader will not think to look.
    const parsed = parseCycloneDx(
      doc([
        {
          type: "library",
          name: "scattered",
          version: "1.0.0",
          purl: "pkg:npm/scattered@1.0.0",
          properties: [
            { name: "syft:location:7:path", value: "/app/seven/package.json" },
            { name: "syft:package:type", value: "npm" },
            { name: "syft:location:2:path", value: "/app/two/package.json" },
            { name: "syft:location:2:layerID", value: "sha256:two" },
          ],
        },
      ]),
    );

    expect(parsed.components[0]!.paths).toEqual([
      "/app/seven/package.json",
      "/app/two/package.json",
    ]);
    expect(parsed.components[0]!.pathCount).toBe(2);
  });
});
