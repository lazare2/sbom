import { describe, expect, it } from "vitest";
import {
  exportFilename,
  exportQuerySchema,
  supportsFlavour,
  CYCLONEDX_SPEC_VERSION,
  SPDX_SPEC_VERSION,
  type ExportFlavour,
} from "@sbom/shared";
import { renderCycloneDx } from "../../src/modules/exports/cyclonedx.render.js";
import { renderSpdx } from "../../src/modules/exports/spdx.render.js";
import type { ExportComponent, ExportDocument } from "../../src/modules/exports/export.types.js";

/**
 * What the two export formats actually say.
 *
 * An export leaves the building. Everything else this platform renders is read on a screen by
 * someone who can click through to the evidence behind it; a downloaded file is read months
 * later by someone who cannot, possibly at another company, and acted on as a statement of
 * fact. So the failures that matter here are all the same failure in different clothing:
 * the document asserting something nobody asserted.
 *
 * Three specific ones are pinned below, because each is a plausible thing for a later edit
 * to break silently:
 *
 *   - an inventory export growing an empty `vulnerabilities: []`, which reads as "we looked
 *     and the estate is clean" on a document that never looked
 *   - an enriched export produced while a feed was switched off, losing the declaration that
 *     says so
 *   - a malicious-package entry acquiring a severity rating that nobody upstream assigned
 *
 * The renderers are pure functions over an assembled document, which is what makes all of
 * this checkable here rather than only through a browser against a live database.
 */

function component(over: Partial<ExportComponent> = {}): ExportComponent {
  return {
    identityHash: "aaaa1111",
    name: "lodash",
    version: "4.17.20",
    ecosystem: "npm",
    kind: "library",
    purl: "pkg:npm/lodash@4.17.20",
    cpe: null,
    origin: "application",
    paths: ["/app/node_modules/lodash/package.json"],
    pathCount: 1,
    vulnerabilities: [],
    malicious: [],
    ...over,
  };
}

function harness(
  over: {
    flavour?: ExportFlavour;
    components?: ExportComponent[];
    assessment?: Partial<ExportDocument["assessment"]>;
    sources?: ExportDocument["subject"]["sources"];
  } = {},
): ExportDocument {
  return {
    subject: {
      kind: "application",
      id: "11111111-1111-1111-1111-111111111111",
      name: "payments-api",
      sources: over.sources ?? [
        {
          scanId: "22222222-2222-2222-2222-222222222222",
          applicationId: "11111111-1111-1111-1111-111111111111",
          applicationName: "payments-api",
          createdAt: "2026-08-01T09:30:00.000Z",
          imageRef: "registry.example/payments-api:1.4.0",
          commitSha: "abc123",
          buildNumber: "480",
          branch: "main",
          toolName: "syft",
          toolVersion: "1.20.0",
        },
      ],
    },
    flavour: over.flavour ?? "inventory",
    // Carries milliseconds on purpose: SPDX must strip them and CycloneDX must not.
    generatedAt: "2026-08-25T12:00:00.456Z",
    components: over.components ?? [component()],
    assessment: {
      vulnerabilityScanning: true,
      maliciousDetection: true,
      ...over.assessment,
    },
  };
}

function props(entry: unknown): Record<string, string> {
  const list = (entry as { properties?: Array<{ name: string; value: string }> }).properties ?? [];
  return Object.fromEntries(list.map((p) => [p.name, p.value]));
}

// ---------------------------------------------------------------------------

describe("CycloneDX: findings are present only when they were looked for", () => {
  it("omits the vulnerabilities key entirely on an inventory export", () => {
    /*
     * The whole point of the two flavours. An empty array here would be indistinguishable
     * from a clean estate, and an inventory export is precisely the document handed to
     * people outside the organisation who have no other way to check.
     */
    const bom = renderCycloneDx(harness({ flavour: "inventory" }));
    expect(bom).not.toHaveProperty("vulnerabilities");
  });

  it("emits the vulnerabilities key on an enriched export even when nothing was found", () => {
    // Here an empty array IS the answer: the feeds ran and matched nothing.
    const bom = renderCycloneDx(harness({ flavour: "enriched" }));
    expect(bom.vulnerabilities).toEqual([]);
  });

  it("declares a switched-off feed rather than letting silence imply a clean result", () => {
    const bom = renderCycloneDx(
      harness({
        flavour: "enriched",
        assessment: { vulnerabilityScanning: false, maliciousDetection: false },
      }),
    );
    const meta = props(bom.metadata);
    expect(meta["sbom:assessment:vulnerability-scanning"]).toBe("disabled");
    expect(meta["sbom:assessment:malicious-detection"]).toBe("disabled");
  });

  it("does not put assessment claims on an inventory export", () => {
    // An inventory document makes no claim either way, so it must not carry one.
    const meta = props(renderCycloneDx(harness({ flavour: "inventory" })).metadata);
    expect(meta["sbom:assessment:vulnerability-scanning"]).toBeUndefined();
  });
});

describe("CycloneDX: the shape of a finding", () => {
  const vuln = {
    id: "CVE-2021-23337",
    severity: "high" as const,
    cvssBaseScore: 7.2,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    epssScore: 0.0042,
    knownExploited: true,
    description: "Command injection.",
    fixState: "fixed",
    fixVersions: ["4.17.21"],
    urls: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    dataSource: "github:language:javascript",
  };

  it("lists one entry per advisory with every affected component under it", () => {
    /*
     * One entry per (component, advisory) pair is legal CycloneDX and produces a document
     * where a single widely-shipped CVE appears hundreds of times. Anyone counting entries
     * to answer "how many advisories affect us" would get the wrong number by two orders of
     * magnitude.
     */
    const bom = renderCycloneDx(
      harness({
        flavour: "enriched",
        components: [
          component({ identityHash: "aaaa1111", vulnerabilities: [vuln] }),
          component({ identityHash: "bbbb2222", name: "lodash-es", vulnerabilities: [vuln] }),
        ],
      }),
    );
    const entries = bom.vulnerabilities as Array<Record<string, unknown>>;
    expect(entries).toHaveLength(1);
    expect(entries[0]!.affects).toEqual([{ ref: "aaaa1111" }, { ref: "bbbb2222" }]);
  });

  it("names the CVSS version from the vector instead of assuming one", () => {
    const bom = renderCycloneDx(
      harness({ flavour: "enriched", components: [component({ vulnerabilities: [vuln] })] }),
    );
    const rating = (bom.vulnerabilities as Array<{ ratings: Array<Record<string, unknown>> }>)[0]!
      .ratings[0]!;
    expect(rating.method).toBe("CVSSv31");
    expect(rating.score).toBe(7.2);
  });

  it("reports an unversioned vector as an unknown method rather than guessing", () => {
    const bom = renderCycloneDx(
      harness({
        flavour: "enriched",
        components: [
          component({ vulnerabilities: [{ ...vuln, cvssVector: "something/else" }] }),
        ],
      }),
    );
    const rating = (bom.vulnerabilities as Array<{ ratings: Array<Record<string, unknown>> }>)[0]!
      .ratings[0]!;
    expect(rating.method).toBe("other");
  });

  it("maps negligible to info, not to none", () => {
    /*
     * CycloneDX `none` means the advisory carries no severity at all. Using it for a
     * negligible finding would turn a real low-grade result into an unrated one, and those
     * are two different facts.
     */
    const bom = renderCycloneDx(
      harness({
        flavour: "enriched",
        components: [
          component({ vulnerabilities: [{ ...vuln, severity: "negligible", cvssBaseScore: null }] }),
        ],
      }),
    );
    const rating = (bom.vulnerabilities as Array<{ ratings: Array<Record<string, unknown>> }>)[0]!
      .ratings[0]!;
    expect(rating.severity).toBe("info");
  });

  it("flags known-exploited only when it is true", () => {
    // A `false` on every entry would bury the handful that justify waking somebody up.
    const enriched = harness({
      flavour: "enriched",
      components: [component({ vulnerabilities: [{ ...vuln, knownExploited: false }] })],
    });
    const entry = (renderCycloneDx(enriched).vulnerabilities as unknown[])[0];
    expect(props(entry)["sbom:known-exploited"]).toBeUndefined();
  });

  it("sorts advisories by id so an unchanged estate exports identically twice", () => {
    const bom = renderCycloneDx(
      harness({
        flavour: "enriched",
        components: [
          component({ identityHash: "a", vulnerabilities: [{ ...vuln, id: "CVE-2024-9999" }] }),
          component({ identityHash: "b", vulnerabilities: [{ ...vuln, id: "CVE-2020-1111" }] }),
        ],
      }),
    );
    const ids = (bom.vulnerabilities as Array<{ id: string }>).map((v) => v.id);
    expect(ids).toEqual(["CVE-2020-1111", "CVE-2024-9999"]);
  });
});

describe("CycloneDX: malicious packages", () => {
  const mal = {
    id: "MAL-2024-1677",
    packageName: "evil-lib",
    sources: ["ghsa-malware", "amazon-inspector"],
    matchMode: "name_version",
  };

  it("invents no severity rating", () => {
    /*
     * A package that is malware is not a borderline call, and CycloneDX would accept
     * `critical` without complaint. It is still a number nobody upstream assigned, and this
     * platform refuses to mint those -- the same reason it will not fold severity, CVSS and
     * EPSS into a single score. The evidence goes in the document; the conclusion is the
     * reader's.
     */
    const bom = renderCycloneDx(
      harness({ flavour: "enriched", components: [component({ malicious: [mal] })] }),
    );
    const entry = (bom.vulnerabilities as Array<Record<string, unknown>>)[0]!;
    expect(entry.id).toBe("MAL-2024-1677");
    expect(entry).not.toHaveProperty("ratings");
  });

  it("carries the reporters through", () => {
    const bom = renderCycloneDx(
      harness({ flavour: "enriched", components: [component({ malicious: [mal] })] }),
    );
    const entry = (bom.vulnerabilities as unknown[])[0];
    expect(props(entry)["sbom:malicious:reporters"]).toBe("ghsa-malware, amazon-inspector");
  });

  it("says so explicitly when upstream recorded no reporter", () => {
    /*
     * 16.9% of the live feed. An absent property would read as "the exporter dropped it";
     * the wording has to distinguish upstream's gap from ours.
     */
    const bom = renderCycloneDx(
      harness({
        flavour: "enriched",
        components: [component({ malicious: [{ ...mal, sources: [] }] })],
      }),
    );
    const entry = (bom.vulnerabilities as unknown[])[0];
    expect(props(entry)["sbom:malicious:reporters"]).toBe("none recorded upstream");
  });
});

describe("CycloneDX: components", () => {
  it("omits version rather than asserting an empty one", () => {
    // CycloneDX permits a component with no resolvable version; `""` would claim one.
    const bom = renderCycloneDx(harness({ components: [component({ version: null })] }));
    expect((bom.components as unknown[])[0]).not.toHaveProperty("version");
  });

  it("states the true total only when the stored path list was capped", () => {
    const capped = renderCycloneDx(
      harness({ components: [component({ paths: ["/a", "/b", "/c"], pathCount: 81 })] }),
    );
    expect(props((capped.components as unknown[])[0])["sbom:location:total"]).toBe("81");

    const complete = renderCycloneDx(harness({ components: [component({ pathCount: 1 })] }));
    expect(props((complete.components as unknown[])[0])["sbom:location:total"]).toBeUndefined();
  });

  it("maps an OS component to operating-system and a runtime to application", () => {
    // CycloneDX has no `runtime`. Leaving either as `library` would file the base distribution
    // as a dependency, which is the split the whole platform is built around.
    const bom = renderCycloneDx(
      harness({
        components: [
          component({ identityHash: "os1", kind: "os", name: "debian" }),
          component({ identityHash: "rt1", kind: "runtime", name: "python" }),
        ],
      }),
    );
    const types = (bom.components as Array<{ type: string }>).map((c) => c.type);
    expect(types).toEqual(["operating-system", "application"]);
  });

  it("records the build behind the document", () => {
    // An SBOM whose reader cannot tell which build it describes cannot be checked against
    // anything, which makes it unfalsifiable rather than merely incomplete.
    const meta = props(renderCycloneDx(harness()).metadata);
    expect(meta["sbom:build:0:image"]).toBe("registry.example/payments-api:1.4.0");
    expect(meta["sbom:build:0:commit"]).toBe("abc123");
    expect(meta["sbom:export:builds"]).toBe("1");
  });

  it("stays a valid document for an application that has never been built", () => {
    /*
     * Not a 404. The application exists; it has no scans. An error here would claim the
     * application does not exist, which is a different and wrong statement.
     */
    const bom = renderCycloneDx(harness({ components: [], sources: [] }));
    expect(bom.specVersion).toBe(CYCLONEDX_SPEC_VERSION);
    expect(bom.components).toEqual([]);
    expect(props(bom.metadata)["sbom:export:builds"]).toBe("0");
  });
});

// ---------------------------------------------------------------------------

describe("SPDX", () => {
  it("uses second precision, which the spec requires and a JS ISO string violates", () => {
    /*
     * `2026-08-25T12:00:00.456Z` is rejected by strict SPDX validators. Truncating rather
     * than rounding: a document must not claim to have been created in the future.
     */
    const doc = renderSpdx(harness()) as { creationInfo: { created: string } };
    expect(doc.creationInfo.created).toBe("2026-08-25T12:00:00Z");
  });

  it("declares the spec version and the fixed document licence", () => {
    const doc = renderSpdx(harness()) as Record<string, unknown>;
    expect(doc.spdxVersion).toBe(SPDX_SPEC_VERSION);
    // Fixed by the spec — it licenses the document, not the software it describes.
    expect(doc.dataLicense).toBe("CC0-1.0");
  });

  it("never emits findings, because SPDX 2.3 has nowhere to put them", () => {
    const doc = renderSpdx(harness({ flavour: "enriched" })) as Record<string, unknown>;
    expect(doc).not.toHaveProperty("vulnerabilities");
  });

  it("constrains identifiers to the characters the spec allows", () => {
    /*
     * Identity hashes are hex today and already conform. The substitution is unconditional
     * because nothing guarantees that forever, and one stray character produces a document
     * that fails validation with no indication of which package caused it.
     */
    const doc = renderSpdx(
      harness({ components: [component({ identityHash: "ab/cd+ef=" })] }),
    ) as { packages: Array<{ SPDXID: string }> };
    const ids = doc.packages.map((p) => p.SPDXID);
    expect(ids).toContain("SPDXRef-Package-ab-cd-ef-");
    for (const id of ids) expect(id).toMatch(/^SPDXRef-[a-zA-Z0-9.-]+$/);
  });

  it("says NOASSERTION for licences rather than inventing one", () => {
    // The platform does not record licences yet. NOASSERTION means "no claim is made", which
    // is exactly true; any other value would be an assertion nobody made.
    const doc = renderSpdx(harness()) as { packages: Array<Record<string, unknown>> };
    const pkg = doc.packages.find((p) => p.name === "lodash")!;
    expect(pkg.licenseConcluded).toBe("NOASSERTION");
    expect(pkg.licenseDeclared).toBe("NOASSERTION");
  });

  it("carries purl and cpe as external references", () => {
    const doc = renderSpdx(
      harness({ components: [component({ cpe: "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*" })] }),
    ) as { packages: Array<{ name: string; externalRefs?: Array<Record<string, string>> }> };
    const refs = doc.packages.find((p) => p.name === "lodash")!.externalRefs!;
    expect(refs.map((r) => r.referenceType)).toEqual(["purl", "cpe23Type"]);
  });

  it("keeps the provenance a human can read, since SPDX has no properties list", () => {
    const doc = renderSpdx(harness()) as { creationInfo: { comment: string } };
    expect(doc.creationInfo.comment).toContain("payments-api");
    expect(doc.creationInfo.comment).toContain("22222222-2222-2222-2222-222222222222");
  });

  it("states plainly that a never-built application has no packages", () => {
    const doc = renderSpdx(harness({ components: [], sources: [] })) as {
      creationInfo: { comment: string };
      packages: unknown[];
    };
    expect(doc.creationInfo.comment).toContain("No build has been ingested");
    // The subject package itself remains, so the document still describes something.
    expect(doc.packages).toHaveLength(1);
  });

  it("relates every package to the subject so the document is a graph, not a bag", () => {
    const doc = renderSpdx(
      harness({
        components: [component({ identityHash: "a" }), component({ identityHash: "b" })],
      }),
    ) as { relationships: Array<{ relationshipType: string }> };
    const types = doc.relationships.map((r) => r.relationshipType);
    expect(types.filter((t) => t === "DESCRIBES")).toHaveLength(1);
    expect(types.filter((t) => t === "CONTAINS")).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------

describe("the export request contract", () => {
  it("refuses enriched SPDX instead of quietly serving the inventory", () => {
    /*
     * The dangerous downgrade. A caller who asked for findings and received a package list
     * cannot tell the difference between "this format cannot carry them" and "there are
     * none", and the second is what it looks like.
     */
    expect(supportsFlavour("spdx", "enriched")).toBe(false);
    expect(supportsFlavour("spdx", "inventory")).toBe(true);
    expect(supportsFlavour("cyclonedx", "enriched")).toBe(true);
  });

  it("defaults to the safe combination", () => {
    // Inventory CycloneDX: the widest-supported format, and the flavour that discloses least.
    const parsed = exportQuerySchema.parse({});
    expect(parsed.format).toBe("cyclonedx");
    expect(parsed.flavour).toBe("inventory");
  });

  it("rejects a format it does not implement", () => {
    expect(() => exportQuerySchema.parse({ format: "spdx3" })).toThrow();
  });

  it("builds a filename that says what the file is", () => {
    expect(exportFilename({ subject: "payments-api", format: "spdx", flavour: "inventory" })).toBe(
      "payments-api-spdx.json",
    );
    expect(
      exportFilename({ subject: "payments-api", format: "cyclonedx", flavour: "enriched" }),
    ).toBe("payments-api-cyclonedx-findings.json");
  });

  it("strips characters that would break a Content-Disposition header", () => {
    /*
     * Application names are free text. A quote or a newline in the filename is a header
     * injection, and a slash makes the browser write outside the download directory on some
     * clients.
     */
    const name = exportFilename({
      subject: 'we"ird/name here\n',
      format: "cyclonedx",
      flavour: "inventory",
    });
    expect(name).toBe("we-ird-name-here-cyclonedx.json");
    expect(name).not.toMatch(/["\n/\\]/);
  });

  it("falls back rather than producing a nameless file", () => {
    expect(exportFilename({ subject: "***", format: "cyclonedx", flavour: "inventory" })).toBe(
      "export-cyclonedx.json",
    );
  });
});
