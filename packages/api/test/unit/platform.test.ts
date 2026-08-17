import { describe, expect, it } from "vitest";
import {
  compareVersions,
  detectPlatform,
  osLabel,
  platformSummary,
  type PlatformCandidate,
} from "../../src/modules/ingestion/platform.js";
import { parseCycloneDx } from "../../src/modules/ingestion/cyclonedx.js";

function candidate(overrides: Partial<PlatformCandidate> & { name: string }): PlatformCandidate {
  return {
    version: null,
    cdxType: "library",
    purl: null,
    syftType: null,
    ...overrides,
  };
}

/** An OS component the way Syft emits it. */
function osComponent(id: string, version: string, pretty: string): PlatformCandidate {
  return candidate({
    name: id,
    version,
    cdxType: "operating-system",
    distroId: id,
    distroVersionId: version,
    distroPrettyName: pretty,
  });
}

/** A runtime the way Syft's binary classifier emits it. */
function binary(name: string, version: string): PlatformCandidate {
  return candidate({
    name,
    version,
    cdxType: "application",
    purl: `pkg:generic/${name}@${version}`,
    syftType: "binary",
  });
}

describe("detectPlatform", () => {
  it("reads the distro from the operating-system component", () => {
    const result = detectPlatform([osComponent("alpine", "3.20.3", "Alpine Linux v3.20")]);
    expect(result).toMatchObject({
      osName: "alpine",
      osVersion: "3.20.3",
      osPretty: "Alpine Linux v3.20",
    });
  });

  it("prefers the syft:distro properties over the component's own fields", () => {
    // The properties come straight from /etc/os-release; the component fields
    // are a rendering of them and can be less precise.
    const result = detectPlatform([
      candidate({
        name: "Alpine Linux",
        version: "3.20",
        cdxType: "operating-system",
        distroId: "alpine",
        distroVersionId: "3.20.3",
        distroPrettyName: "Alpine Linux v3.20",
      }),
    ]);
    expect(result.osName).toBe("alpine");
    expect(result.osVersion).toBe("3.20.3");
  });

  it("falls back to the component fields for SBOMs from other tools", () => {
    const result = detectPlatform([
      candidate({ name: "debian", version: "12", cdxType: "operating-system" }),
    ]);
    expect(result).toMatchObject({ osName: "debian", osVersion: "12", osPretty: null });
  });

  it("detects language runtimes from binary-cataloged components", () => {
    const result = detectPlatform([binary("node", "22.11.0"), binary("python3", "3.12.7")]);
    expect(result.runtimes).toEqual([
      { name: "node", version: "22.11.0" },
      { name: "python", version: "3.12.7" },
    ]);
  });

  it("collapses aliases so counts do not fragment", () => {
    // python3/python and the JDK spellings must not produce two dashboard rows
    // for one runtime.
    expect(detectPlatform([binary("python3", "3.12.7")]).runtimes[0]?.name).toBe("python");
    expect(detectPlatform([binary("openjdk", "21.0.5")]).runtimes[0]?.name).toBe("java");
    expect(detectPlatform([binary("nodejs", "22.11.0")]).runtimes[0]?.name).toBe("node");
  });

  it("ignores a LIBRARY named like a runtime", () => {
    // An npm package literally called "node" is a dependency in someone's tree,
    // not the interpreter. Treating it as the runtime would report a Java
    // service as running Node.
    const result = detectPlatform([
      candidate({ name: "node", version: "1.0.0", purl: "pkg:npm/node@1.0.0", syftType: "npm" }),
    ]);
    expect(result.runtimes).toEqual([]);
  });

  it("ignores binaries that are not runtimes", () => {
    // A container has dozens of binaries. Listing busybox and openssl as "the
    // runtime" would bury the one fact this feature exists to surface.
    const result = detectPlatform([
      binary("busybox", "1.36.1"),
      binary("openssl", "3.3.2"),
      binary("bash", "5.2.15"),
      binary("node", "22.11.0"),
    ]);
    expect(result.runtimes).toEqual([{ name: "node", version: "22.11.0" }]);
  });

  it("keeps the highest version when an image carries two of the same runtime", () => {
    // A JDK plus a JRE. Reporting the lower one would understate what is installed.
    const result = detectPlatform([binary("jre", "17.0.13"), binary("jdk", "21.0.5")]);
    expect(result.runtimes).toEqual([{ name: "java", version: "21.0.5" }]);
  });

  it("returns all-null for a scratch image", () => {
    // Meaningful rather than missing: a distroless image genuinely has no
    // os-release file and no runtime binary.
    const result = detectPlatform([]);
    expect(result).toEqual({ osName: null, osVersion: null, osPretty: null, runtimes: [] });
    expect(platformSummary(result)).toBeNull();
  });

  it("sorts runtimes so an unchanged image stores an identical array", () => {
    const a = detectPlatform([binary("node", "22.11.0"), binary("nginx", "1.27.3")]);
    const b = detectPlatform([binary("nginx", "1.27.3"), binary("node", "22.11.0")]);
    expect(a.runtimes).toEqual(b.runtimes);
    expect(a.runtimes.map((r) => r.name)).toEqual(["nginx", "node"]);
  });
});

describe("platformSummary", () => {
  it("renders OS then runtimes", () => {
    const result = detectPlatform([
      osComponent("alpine", "3.20.3", "Alpine Linux v3.20"),
      binary("node", "22.11.0"),
    ]);
    expect(platformSummary(result)).toBe("Alpine 3.20.3 · Node.js 22.11.0");
  });

  it("renders an OS with no runtime", () => {
    expect(platformSummary(detectPlatform([osComponent("debian", "12", "Debian 12")]))).toBe("Debian 12");
  });

  it("renders a runtime with no OS", () => {
    expect(platformSummary(detectPlatform([binary("go", "1.23.4")]))).toBe("Go 1.23.4");
  });

  it("keeps an unrecognised distro id readable rather than hiding it", () => {
    expect(osLabel("someneworg")).toBe("someneworg");
  });
});

describe("compareVersions", () => {
  it("orders numerically, not lexically", () => {
    // The one wrong answer that would actually mislead: string compare ranks
    // "9.0" above "10.0".
    expect(compareVersions("10.0", "9.0")).toBeGreaterThan(0);
    expect(compareVersions("3.9.2", "3.12.7")).toBeLessThan(0);
  });

  it("treats a missing version as lowest", () => {
    expect(compareVersions(null, "1.0")).toBeLessThan(0);
    expect(compareVersions("1.0", null)).toBeGreaterThan(0);
    expect(compareVersions(null, null)).toBe(0);
  });

  it("handles distro-style versions without crashing", () => {
    expect(compareVersions("3.0.14-1~deb12u2", "3.0.15-1~deb12u1")).toBeLessThan(0);
  });
});

describe("parseCycloneDx platform integration", () => {
  it("extracts the platform from a Syft-shaped document", () => {
    const doc = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [
        {
          type: "operating-system",
          name: "alpine",
          version: "3.20.3",
          properties: [
            { name: "syft:distro:id", value: "alpine" },
            { name: "syft:distro:versionID", value: "3.20.3" },
            { name: "syft:distro:prettyName", value: "Alpine Linux v3.20" },
          ],
        },
        {
          type: "application",
          name: "node",
          version: "22.11.0",
          purl: "pkg:generic/node@22.11.0",
          properties: [{ name: "syft:package:type", value: "binary" }],
        },
        { type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" },
      ],
    };

    const parsed = parseCycloneDx(Buffer.from(JSON.stringify(doc)));

    expect(parsed.platform.osName).toBe("alpine");
    expect(parsed.platform.runtimes).toEqual([{ name: "node", version: "22.11.0" }]);
    // The OS and runtime entries are still stored as components too — the
    // platform columns are a denormalised summary, not a replacement.
    expect(parsed.components.map((c) => c.name).sort()).toEqual(["alpine", "express", "node"]);
  });

  it("labels each component so aggregates can exclude the platform", () => {
    // Without this the dashboard's "most widely deployed packages" ranks the
    // base OS alongside real dependencies, which makes a blast-radius list
    // nobody should act on.
    const doc = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [
        {
          type: "operating-system",
          name: "alpine",
          version: "3.20.3",
          properties: [{ name: "syft:distro:id", value: "alpine" }],
        },
        {
          type: "application",
          name: "node",
          version: "22.11.0",
          purl: "pkg:generic/node@22.11.0",
          properties: [{ name: "syft:package:type", value: "binary" }],
        },
        {
          // A binary that is not a runtime stays an ordinary component: it is a
          // real thing shipped in the image and someone may need to search it.
          type: "application",
          name: "busybox",
          version: "1.36.1",
          purl: "pkg:generic/busybox@1.36.1",
          properties: [{ name: "syft:package:type", value: "binary" }],
        },
        { type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" },
      ],
    };

    const byName = new Map(
      parseCycloneDx(Buffer.from(JSON.stringify(doc))).components.map((c) => [c.name, c.kind]),
    );

    expect(byName.get("alpine")).toBe("os");
    expect(byName.get("node")).toBe("runtime");
    expect(byName.get("busybox")).toBe("library");
    expect(byName.get("express")).toBe("library");
  });

  it("does not label an npm package named like a runtime as a runtime", () => {
    const doc = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [
        {
          type: "library",
          name: "node",
          version: "1.0.0",
          purl: "pkg:npm/node@1.0.0",
          properties: [{ name: "syft:package:type", value: "npm" }],
        },
      ],
    };
    expect(parseCycloneDx(Buffer.from(JSON.stringify(doc))).components[0]?.kind).toBe("library");
  });

  it("yields an empty platform for an SBOM with no OS or runtime", () => {
    const doc = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [{ type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" }],
    };
    const parsed = parseCycloneDx(Buffer.from(JSON.stringify(doc)));
    expect(platformSummary(parsed.platform)).toBeNull();
  });
});
