import { randomUUID } from "node:crypto";
import {
  CYCLONEDX_SPEC_VERSION,
  COMPONENT_LOCATION_PATH_CAP,
  type VulnSeverity,
} from "@sbom/shared";
import type { ExportComponent, ExportDocument } from "./export.types.js";

/**
 * Renders the export document as CycloneDX 1.6 JSON.
 *
 * A pure function over the assembled document: no database, no clock, no configuration. That
 * is what lets the shape of the output be pinned by unit tests rather than only by a browser
 * drive, and it is why the generated timestamp is carried on the document rather than read
 * here.
 *
 * ## What this deliberately does not emit
 *
 * A rating for a malicious-package match. CycloneDX would happily take
 * `severity: "critical"`, and a package that is malware is not a borderline call -- but this
 * platform does not mint risk figures it was not given, which is the same reason it refuses
 * to fold severity, CVSS and EPSS into a single score. The finding is emitted with its OSV
 * id, its description and its reporters, and a consumer can draw the obvious conclusion from
 * evidence rather than from a number invented here.
 */

const TOOL_NAME = "sbom-platform";

/** CycloneDX has no `runtime`; an interpreter or app server is an `application` to it. */
const COMPONENT_TYPES: Record<ExportComponent["kind"], string> = {
  library: "library",
  os: "operating-system",
  runtime: "application",
};

/**
 * CycloneDX 1.6 rating severities. Its vocabulary is not ours.
 *
 * `negligible` becomes `info` -- the closest honest equivalent, and specifically not `none`,
 * which in CycloneDX means the advisory carries no severity at all rather than a very low
 * one. Collapsing the two would turn a real low-grade finding into an unrated one.
 */
const SEVERITIES: Record<VulnSeverity, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  negligible: "info",
  unknown: "unknown",
};

export function renderCycloneDx(doc: ExportDocument): Record<string, unknown> {
  const bom: Record<string, unknown> = {
    bomFormat: "CycloneDX",
    specVersion: CYCLONEDX_SPEC_VERSION,
    /*
      A fresh identifier per export, which is what the spec asks for: the serial number
      identifies this document, not the estate it describes. Two exports of the same
      application are two documents, and a consumer diffing them needs to be able to say so.
    */
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: metadata(doc),
    components: doc.components.map(component),
  };

  if (doc.flavour === "enriched") {
    const vulnerabilities = vulnerabilityEntries(doc);
    /*
      The key is present even when empty, and only ever on an enriched document where the
      assessment properties in `metadata` say whether the feeds had actually run. On an
      inventory export it is absent entirely, so an empty findings list can never be read as
      a clean bill of health for a document that never claimed to look.
    */
    bom.vulnerabilities = vulnerabilities;
  }

  return bom;
}

function metadata(doc: ExportDocument): Record<string, unknown> {
  return {
    timestamp: doc.generatedAt,
    tools: {
      components: [{ type: "application", name: TOOL_NAME, version: platformVersion() }],
    },
    component: {
      "bom-ref": `${doc.subject.kind}:${doc.subject.id}`,
      /*
        Always `application`, including for a group. CycloneDX has no type for "a collection of
        deliverables", and the nearest alternatives all say something false -- `container`
        claims an image, `library` claims a dependency. What the subject actually is travels
        in sbom:subject:kind below, where it can be read without being guessed at.
      */
      type: "application",
      name: doc.subject.name,
    },
    properties: metadataProperties(doc),
  };
}

/**
 * The self-describing part of the document.
 *
 * A file outlives the request that produced it. Somebody opens this in six months with no
 * access to the platform and needs to know what it covers and what had actually been
 * checked -- so the subject, the builds behind it, and the state of each assessment are all
 * written into the document rather than being implied by its absence.
 */
function metadataProperties(doc: ExportDocument): Array<{ name: string; value: string }> {
  const props: Array<{ name: string; value: string }> = [
    { name: "sbom:subject:kind", value: doc.subject.kind },
    { name: "sbom:subject:id", value: doc.subject.id },
    { name: "sbom:export:flavour", value: doc.flavour },
    { name: "sbom:export:builds", value: String(doc.subject.sources.length) },
  ];

  if (doc.flavour === "enriched") {
    props.push({
      name: "sbom:assessment:vulnerability-scanning",
      value: doc.assessment.vulnerabilityScanning ? "enabled" : "disabled",
    });
    props.push({
      name: "sbom:assessment:malicious-detection",
      value: doc.assessment.maliciousDetection ? "enabled" : "disabled",
    });
  }

  for (const [index, source] of doc.subject.sources.entries()) {
    props.push({ name: `sbom:build:${index}:application`, value: source.applicationName });
    props.push({ name: `sbom:build:${index}:scan-id`, value: source.scanId });
    props.push({ name: `sbom:build:${index}:scanned-at`, value: source.createdAt });
    if (source.imageRef) props.push({ name: `sbom:build:${index}:image`, value: source.imageRef });
    if (source.commitSha) props.push({ name: `sbom:build:${index}:commit`, value: source.commitSha });
    if (source.buildNumber) props.push({ name: `sbom:build:${index}:build`, value: source.buildNumber });
  }

  return props;
}

function component(c: ExportComponent): Record<string, unknown> {
  const entry: Record<string, unknown> = {
    "bom-ref": c.identityHash,
    type: COMPONENT_TYPES[c.kind],
    name: c.name,
  };
  // Omitted rather than emitted empty: CycloneDX permits a component with no resolvable
  // version, and `"version": ""` would assert one that is the empty string.
  if (c.version) entry.version = c.version;
  if (c.purl) entry.purl = c.purl;
  if (c.cpe) entry.cpe = c.cpe;

  const props: Array<{ name: string; value: string }> = [
    { name: "sbom:ecosystem", value: c.ecosystem },
    { name: "sbom:origin", value: c.origin },
  ];

  for (const [index, path] of (c.paths ?? []).entries()) {
    props.push({ name: `syft:location:${index}:path`, value: path });
  }
  /*
    The true total, when the stored list was capped. Without it a reader sees three paths and
    has no way to know there were eighty-one -- the same reason the column exists on the join
    row rather than the list being silently truncated on screen.
  */
  if (c.pathCount !== null && c.pathCount > COMPONENT_LOCATION_PATH_CAP) {
    props.push({ name: "sbom:location:total", value: String(c.pathCount) });
  }

  entry.properties = props;
  return entry;
}

function vulnerabilityEntries(doc: ExportDocument): Array<Record<string, unknown>> {
  /*
    One entry per advisory, with every affected component listed under `affects`. The
    alternative -- one entry per (component, advisory) pair -- is legal but produces a
    document where a single CVE appears four hundred times, and a consumer counting entries
    gets four hundred rather than one.
  */
  const byId = new Map<string, { entry: Record<string, unknown>; affects: Set<string> }>();

  for (const c of doc.components) {
    for (const v of c.vulnerabilities) {
      const existing = byId.get(v.id);
      if (existing) {
        existing.affects.add(c.identityHash);
        continue;
      }

      const ratings: Array<Record<string, unknown>> = [];
      if (v.severity !== "unknown" || v.cvssBaseScore !== null) {
        const rating: Record<string, unknown> = { severity: SEVERITIES[v.severity] };
        if (v.cvssBaseScore !== null) {
          rating.score = v.cvssBaseScore;
          // `method` describes where the score came from. Claiming a CVSS version we were not
          // told would be a fabricated provenance, so an unversioned vector is reported as other.
          rating.method = cvssMethod(v.cvssVector);
          if (v.cvssVector) rating.vector = v.cvssVector;
        }
        if (v.dataSource) rating.source = { name: v.dataSource };
        ratings.push(rating);
      }

      const entry: Record<string, unknown> = { "bom-ref": v.id, id: v.id };
      if (v.dataSource) entry.source = { name: v.dataSource };
      if (ratings.length > 0) entry.ratings = ratings;
      if (v.description) entry.description = v.description;
      if (v.urls.length > 0) entry.advisories = v.urls.map((url) => ({ url }));

      const props: Array<{ name: string; value: string }> = [
        { name: "sbom:fix-state", value: v.fixState },
      ];
      if (v.fixVersions.length > 0) {
        props.push({ name: "sbom:fix-versions", value: v.fixVersions.join(", ") });
      }
      // Emitted only when true. A `false` on every entry would bury the handful that matter.
      if (v.knownExploited) props.push({ name: "sbom:known-exploited", value: "true" });
      if (v.epssScore !== null) props.push({ name: "sbom:epss", value: String(v.epssScore) });
      entry.properties = props;

      byId.set(v.id, { entry, affects: new Set([c.identityHash]) });
    }

    for (const m of c.malicious) {
      const existing = byId.get(m.id);
      if (existing) {
        existing.affects.add(c.identityHash);
        continue;
      }
      const entry: Record<string, unknown> = {
        "bom-ref": m.id,
        id: m.id,
        source: { name: "osv-malicious-packages" },
        description: `${m.packageName} is reported as a malicious package.`,
        properties: [
          { name: "sbom:malicious", value: "true" },
          { name: "sbom:malicious:match-mode", value: m.matchMode },
          {
            name: "sbom:malicious:reporters",
            // Named reporters, or an explicit statement that upstream recorded none. An
            // absent property would read as "we did not carry that across".
            value: m.sources.length > 0 ? m.sources.join(", ") : "none recorded upstream",
          },
        ],
      };
      byId.set(m.id, { entry, affects: new Set([c.identityHash]) });
    }
  }

  const entries: Array<Record<string, unknown>> = [...byId.values()].map(({ entry, affects }) => ({
    ...entry,
    affects: [...affects].sort().map((ref) => ({ ref })),
  }));
  // Sorted by advisory id so two exports of an unchanged estate are byte-identical. Without
  // it the order follows Map insertion, which follows component order, and a diff of two
  // exports would show movement where nothing moved.
  return entries.sort((a, b) => String(a.id).localeCompare(String(b.id)));
}

function cvssMethod(vector: string | null): string {
  if (!vector) return "other";
  if (vector.startsWith("CVSS:4")) return "CVSSv4";
  if (vector.startsWith("CVSS:3.1")) return "CVSSv31";
  if (vector.startsWith("CVSS:3")) return "CVSSv3";
  if (vector.startsWith("AV:")) return "CVSSv2";
  return "other";
}

/**
 * Read from the package manifest rather than hardcoded, so an export names the build that
 * produced it. Falls back rather than throwing: failing an export because a version string
 * could not be read would trade the whole feature for a cosmetic field.
 */
function platformVersion(): string {
  return process.env.npm_package_version ?? "0.1.0";
}
