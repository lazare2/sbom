import { describe, expect, it } from "vitest";
import { computeIdentityHash, parseCycloneDx } from "../../src/modules/ingestion/cyclonedx.js";
import { AppError } from "../../src/lib/errors.js";
import { syftCycloneDx14Sbom, syftCycloneDxSbom } from "../fixtures/syft-cyclonedx.js";

function parse(doc: unknown) {
  return parseCycloneDx(Buffer.from(JSON.stringify(doc), "utf8"));
}

describe("parseCycloneDx — document metadata", () => {
  it("reads spec version, serial number, and the CycloneDX 1.5 tools shape", () => {
    const result = parse(syftCycloneDxSbom);
    expect(result.specVersion).toBe("1.5");
    expect(result.serialNumber).toBe("urn:uuid:5f2b8c3a-1d4e-4f6a-9b8c-7d6e5f4a3b2c");
    expect(result.toolName).toBe("syft");
    expect(result.toolVersion).toBe("1.18.1");
  });

  it("reads the CycloneDX 1.4 tools array shape too", () => {
    const result = parse(syftCycloneDx14Sbom);
    expect(result.toolName).toBe("syft");
    expect(result.toolVersion).toBe("0.105.1");
  });

  it("captures the image the SBOM describes, for use when CI omits image_ref", () => {
    const result = parse(syftCycloneDxSbom);
    expect(result.subjectName).toBe("registry.internal.example.com/payments/api:1.42.0");
  });
});

describe("parseCycloneDx — component extraction", () => {
  it("collapses duplicates rather than letting them break the scan_component insert", () => {
    const result = parse(syftCycloneDxSbom);

    // express appears twice from two catalogers; libc6 twice with reordered
    // purl qualifiers. Both must collapse to one entry each.
    expect(result.duplicatesCollapsed).toBe(2);

    const names = result.components.map((c) => c.name);
    expect(names.filter((n) => n === "express")).toHaveLength(1);
    expect(names.filter((n) => n === "libc6")).toHaveLength(1);

    // Every identity hash in the output is unique — this is the invariant that
    // the (scan_id, component_id) primary key depends on.
    const hashes = result.components.map((c) => c.identityHash);
    expect(new Set(hashes).size).toBe(hashes.length);
  });

  it("derives the ecosystem from the purl in preference to the syft property", () => {
    const result = parse(syftCycloneDxSbom);
    const byName = new Map(result.components.map((c) => [c.name, c]));

    expect(byName.get("libc6")?.ecosystem).toBe("deb");
    expect(byName.get("express")?.ecosystem).toBe("npm");
    // purl says `pypi` while the syft property says `python`; purl wins.
    expect(byName.get("requests")?.ecosystem).toBe("pypi");
  });

  it("falls back to the syft package type when there is no purl", () => {
    const result = parse(syftCycloneDxSbom);
    const lib = result.components.find((c) => c.name === "internal-shared-lib");
    expect(lib).toBeDefined();
    // `java-archive` maps onto the canonical maven ecosystem.
    expect(lib?.ecosystem).toBe("maven");
    expect(lib?.purl).toBeNull();
  });

  it("keeps versionless components", () => {
    const result = parse(syftCycloneDxSbom);
    const mystery = result.components.find((c) => c.name === "mystery-binary");
    expect(mystery).toBeDefined();
    expect(mystery?.version).toBeNull();
  });

  it("keeps the operating-system component but excludes file entries", () => {
    const result = parse(syftCycloneDxSbom);
    expect(result.components.some((c) => c.name === "debian")).toBe(true);
    expect(result.components.some((c) => c.name.includes("libcrypto.so"))).toBe(false);
    expect(result.skipped.some((s) => s.reason === "excluded_type")).toBe(true);
  });

  it("skips a nameless component without failing the whole upload", () => {
    const result = parse(syftCycloneDxSbom);
    expect(result.skipped.some((s) => s.reason === "missing_name")).toBe(true);
    // The rest of the document still came through.
    expect(result.components.length).toBeGreaterThan(4);
  });

  it("normalises the stored purl", () => {
    const result = parse(syftCycloneDxSbom);
    const libc = result.components.find((c) => c.name === "libc6");
    expect(libc?.purl).toBe("pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12");
  });

  it("captures the CPE for a future vulnerability-matching phase", () => {
    const result = parse(syftCycloneDxSbom);
    const libc = result.components.find((c) => c.name === "libc6");
    expect(libc?.cpe).toContain("cpe:2.3:a:libc6");
  });

  it("reads a cpes array when there is no scalar cpe field", () => {
    const result = parse({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [
        { type: "library", name: "x", version: "1", cpes: ["cpe:2.3:a:x:x:1:*:*:*:*:*:*:*"] },
      ],
    });
    expect(result.components[0]?.cpe).toBe("cpe:2.3:a:x:x:1:*:*:*:*:*:*:*");
  });

  it("skips non-object entries in the components array", () => {
    const result = parse({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: ["oops", null, 42, { type: "library", name: "real", version: "1" }],
    });
    expect(result.components).toHaveLength(1);
    expect(result.skipped.filter((s) => s.reason === "not_an_object")).toHaveLength(3);
  });
});

describe("parseCycloneDx — empty and edge-case documents", () => {
  it("accepts an SBOM with no components (a scratch or distroless image)", () => {
    const result = parse({ bomFormat: "CycloneDX", specVersion: "1.5", components: [] });
    expect(result.components).toHaveLength(0);
    expect(result.skipped).toHaveLength(0);
  });

  it("accepts an SBOM with the components key missing entirely", () => {
    const result = parse({ bomFormat: "CycloneDX", specVersion: "1.5" });
    expect(result.components).toHaveLength(0);
  });

  it("accepts a document identified only by specVersion", () => {
    // Some toolchains post-process SBOMs and drop bomFormat. Losing real data
    // over a cosmetic field would be the wrong trade.
    const result = parse({ specVersion: "1.5", components: [{ type: "library", name: "a", version: "1" }] });
    expect(result.components).toHaveLength(1);
  });
});

describe("parseCycloneDx — character encodings", () => {
  const doc = { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "a", version: "1" }] };

  it("ignores a UTF-8 BOM instead of failing the upload", () => {
    // RFC 8259 permits ignoring a BOM, and anything post-processing an SBOM on
    // Windows can add one — PowerShell's `Set-Content -Encoding utf8` does.
    const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(doc), "utf8")]);
    const result = parseCycloneDx(withBom);
    expect(result.components).toHaveLength(1);
    expect(result.specVersion).toBe("1.5");
  });

  it("decodes UTF-16 LE", () => {
    const result = parseCycloneDx(Buffer.from(`﻿${JSON.stringify(doc)}`, "utf16le"));
    expect(result.components).toHaveLength(1);
  });

  it("decodes UTF-16 BE", () => {
    const le = Buffer.from(`﻿${JSON.stringify(doc)}`, "utf16le");
    const be = Buffer.from(le);
    be.swap16();
    const result = parseCycloneDx(be);
    expect(result.components).toHaveLength(1);
  });

  it("strips a leading U+FEFF from a string input", () => {
    const result = parseCycloneDx(`﻿${JSON.stringify(doc)}`);
    expect(result.components).toHaveLength(1);
  });

  it("still parses plain UTF-8 with no BOM", () => {
    const result = parseCycloneDx(Buffer.from(JSON.stringify(doc), "utf8"));
    expect(result.components).toHaveLength(1);
  });

  it("handles non-ASCII package names", () => {
    const result = parseCycloneDx(
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [{ type: "library", name: "café-lib", version: "1.0" }],
      }),
    );
    expect(result.components[0]?.name).toBe("café-lib");
  });
});

describe("parseCycloneDx — rejections", () => {
  it("rejects invalid JSON as 422", () => {
    try {
      parseCycloneDx(Buffer.from("{not json", "utf8"));
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      expect((err as AppError).statusCode).toBe(422);
    }
  });

  it("rejects a JSON array", () => {
    expect(() => parseCycloneDx(JSON.stringify([1, 2, 3]))).toThrowError(/must be a JSON object/i);
  });

  it("rejects a non-CycloneDX SBOM format such as SPDX", () => {
    expect(() =>
      parse({ bomFormat: "SPDX", specVersion: "2.3", components: [] }),
    ).toThrowError(/only cyclonedx/i);
  });

  it("rejects a JSON object with no CycloneDX markers at all", () => {
    expect(() => parse({ hello: "world" })).toThrowError(/does not look like CycloneDX/i);
  });
});

describe("computeIdentityHash", () => {
  it("is stable for the same purl", () => {
    const a = computeIdentityHash({ purl: "pkg:npm/express@4.19.2", ecosystem: "npm", name: "express", version: "4.19.2" });
    const b = computeIdentityHash({ purl: "pkg:npm/express@4.19.2", ecosystem: "npm", name: "express", version: "4.19.2" });
    expect(a).toBe(b);
  });

  it("distinguishes OS packages that differ only by purl qualifier", () => {
    // Same name and version, different architecture — genuinely different
    // artifacts, and the reason identity is purl-based rather than a triple.
    const amd64 = computeIdentityHash({
      purl: "pkg:deb/debian/libc6@2.36?arch=amd64",
      ecosystem: "deb",
      name: "libc6",
      version: "2.36",
    });
    const arm64 = computeIdentityHash({
      purl: "pkg:deb/debian/libc6@2.36?arch=arm64",
      ecosystem: "deb",
      name: "libc6",
      version: "2.36",
    });
    expect(amd64).not.toBe(arm64);
  });

  it("falls back to ecosystem/name/version when there is no purl", () => {
    const a = computeIdentityHash({ purl: null, ecosystem: "maven", name: "lib", version: "1.0" });
    const b = computeIdentityHash({ purl: null, ecosystem: "maven", name: "lib", version: "1.0" });
    const c = computeIdentityHash({ purl: null, ecosystem: "maven", name: "lib", version: "2.0" });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  it("does not collide a purl-derived identity with a triple-derived one", () => {
    const withPurl = computeIdentityHash({ purl: "pkg:npm/x@1", ecosystem: "npm", name: "x", version: "1" });
    const withoutPurl = computeIdentityHash({ purl: null, ecosystem: "npm", name: "x", version: "1" });
    expect(withPurl).not.toBe(withoutPurl);
  });

  it("cannot be confused by names containing the field separator", () => {
    // The prefixed, space-separated encoding must not let a crafted name
    // impersonate a different package.
    const a = computeIdentityHash({ purl: null, ecosystem: "npm", name: "a b", version: "1" });
    const b = computeIdentityHash({ purl: null, ecosystem: "npm", name: "a", version: "b 1" });
    expect(a).not.toBe(b);
  });
});
