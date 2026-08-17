/**
 * Representative Syft `-o cyclonedx-json` output.
 *
 * Trimmed to a handful of components but structurally faithful to the real thing,
 * including the parts that actually cause trouble: the 1.5-style
 * `metadata.tools.components` shape, purl qualifiers on OS packages, a component
 * with no version, a duplicate emitted by two catalogers, and a `file` entry.
 */
export const syftCycloneDxSbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:5f2b8c3a-1d4e-4f6a-9b8c-7d6e5f4a3b2c",
  version: 1,
  metadata: {
    timestamp: "2026-08-11T09:14:22Z",
    tools: {
      components: [
        {
          type: "application",
          author: "anchore",
          name: "syft",
          version: "1.18.1",
        },
      ],
    },
    component: {
      "bom-ref": "1a2b3c4d5e6f",
      type: "container",
      name: "registry.internal.example.com/payments/api:1.42.0",
      version: "sha256:9c1f2e3d4b5a6978c0d1e2f3a4b5c6d7e8f90112233445566778899aabbccddee",
    },
  },
  components: [
    {
      "bom-ref": "pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64",
      type: "library",
      publisher: "GNU Libc Maintainers",
      name: "libc6",
      version: "2.36-9+deb12u7",
      cpe: "cpe:2.3:a:libc6:libc6:2.36-9\\+deb12u7:*:*:*:*:*:*:*",
      purl: "pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?distro=debian-12&arch=amd64",
      properties: [
        { name: "syft:package:type", value: "deb" },
        { name: "syft:package:foundBy", value: "dpkgdb-cataloger" },
      ],
    },
    {
      "bom-ref": "pkg:npm/express@4.19.2",
      type: "library",
      name: "express",
      version: "4.19.2",
      purl: "pkg:npm/express@4.19.2",
      properties: [{ name: "syft:package:type", value: "npm" }],
    },
    {
      // Same package, second cataloger. Must collapse: scan_component is keyed
      // on (scan_id, component_id) and would otherwise abort the insert.
      "bom-ref": "pkg:npm/express@4.19.2-dup",
      type: "library",
      name: "express",
      version: "4.19.2",
      purl: "pkg:npm/express@4.19.2",
      properties: [{ name: "syft:package:type", value: "npm" }],
    },
    {
      // Same purl, qualifiers in a different order — normalisation must make
      // this identical to the libc6 entry above rather than a second package.
      "bom-ref": "pkg:deb/debian/libc6@2.36-reordered",
      type: "library",
      name: "libc6",
      version: "2.36-9+deb12u7",
      purl: "pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12",
      properties: [{ name: "syft:package:type", value: "deb" }],
    },
    {
      "bom-ref": "pkg:pypi/requests@2.32.3",
      type: "library",
      name: "requests",
      version: "2.32.3",
      purl: "pkg:pypi/requests@2.32.3",
      properties: [{ name: "syft:package:type", value: "python" }],
    },
    {
      // No purl at all: ecosystem has to come from the syft property.
      "bom-ref": "no-purl-jar",
      type: "library",
      name: "internal-shared-lib",
      version: "3.1.0",
      properties: [{ name: "syft:package:type", value: "java-archive" }],
    },
    {
      // Versionless component — legal in CycloneDX, must be kept.
      "bom-ref": "versionless",
      type: "library",
      name: "mystery-binary",
      properties: [{ name: "syft:package:type", value: "binary" }],
    },
    {
      // The base OS. Kept: it answers "which base image is this app on".
      "bom-ref": "os-debian",
      type: "operating-system",
      name: "debian",
      version: "12",
      properties: [{ name: "syft:distro:id", value: "debian" }],
    },
    {
      // File entries are excluded — they are not dependencies and would add
      // thousands of rows per scan.
      "bom-ref": "file-entry",
      type: "file",
      name: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    },
    {
      // Malformed: no usable name. Recorded as skipped, must not fail the upload.
      "bom-ref": "broken",
      type: "library",
      name: "   ",
      version: "1.0.0",
    },
  ],
  dependencies: [],
};

/** CycloneDX 1.4 shape, where `metadata.tools` is a bare array. */
export const syftCycloneDx14Sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  serialNumber: "urn:uuid:11111111-2222-3333-4444-555555555555",
  version: 1,
  metadata: {
    tools: [{ vendor: "anchore", name: "syft", version: "0.105.1" }],
    component: { type: "container", name: "legacy/app:0.9", version: "sha256:abc" },
  },
  components: [
    {
      type: "library",
      name: "openssl",
      version: "3.0.11",
      purl: "pkg:apk/alpine/openssl@3.0.11?arch=x86_64",
      properties: [{ name: "syft:package:type", value: "apk" }],
    },
  ],
};
