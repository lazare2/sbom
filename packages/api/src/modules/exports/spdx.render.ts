import { randomUUID } from "node:crypto";
import { SPDX_SPEC_VERSION, COMPONENT_LOCATION_PATH_CAP } from "@sbom/shared";
import type { ExportComponent, ExportDocument } from "./export.types.js";

/**
 * Renders the export document as SPDX 2.3 JSON.
 *
 * SPDX exists here for one reason: it is what a large part of the world asks for, and Syft
 * emitted CycloneDX. Once a build has gone, re-running the tool in another format is not an
 * option, so the conversion has to happen from what was stored.
 *
 * ## Where the two formats deliberately differ
 *
 * Findings are not emitted. SPDX 2.3 has no vulnerability structure -- that arrived in 3.0,
 * which almost nothing consumes yet -- and the alternative would be to invent an annotation
 * convention that no SPDX reader understands, producing a file that looks like it carries
 * findings while being silently ignored by every consumer of it. The route refuses the
 * combination rather than quietly downgrading it, so a caller who asked for findings is told
 * they are not there instead of receiving a document that appears clean.
 *
 * Locations and origin *are* carried, as package annotations. Annotations are a real part of
 * 2.3 and are ignored gracefully by readers that do not care, which makes them the right
 * place for something extra rather than something load-bearing.
 */

const NOASSERTION = "NOASSERTION";

export function renderSpdx(doc: ExportDocument): Record<string, unknown> {
  /*
    SPDX requires second precision and rejects the milliseconds a JS ISO string carries.
    Truncating rather than rounding: this is a "when was it written" stamp, and a document
    that claims to have been created a fraction of a second in the future is worse than one
    that is a fraction of a second stale.
  */
  const created = `${doc.generatedAt.slice(0, 19)}Z`;
  const rootId = "SPDXRef-Subject";

  const packages = doc.components.map((c) => spdxPackage(c, created));

  return {
    spdxVersion: SPDX_SPEC_VERSION,
    /*
      Fixed by the specification: it licenses the SBOM document itself, not the software it
      describes. Every conformant SPDX document carries exactly this value.
    */
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: doc.subject.name,
    /*
      Must be unique per document, per the spec, which is why it carries a fresh uuid rather
      than being derived from the subject. Two exports of one application are two documents;
      a namespace that collided would make them indistinguishable to a consumer storing both.
    */
    documentNamespace: `https://sbom.invalid/spdx/${doc.subject.kind}/${doc.subject.id}/${randomUUID()}`,
    creationInfo: {
      created,
      creators: ["Tool: sbom-platform"],
      comment: creationComment(doc),
    },
    packages: [rootPackage(doc, rootId, created), ...packages],
    relationships: [
      { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: rootId },
      ...doc.components.map((c) => ({
        spdxElementId: rootId,
        relationshipType: "CONTAINS",
        relatedSpdxElement: spdxId(c.identityHash),
      })),
    ],
  };
}

/**
 * What this document covers and which builds it came from, in prose.
 *
 * SPDX has no properties list, so the provenance that CycloneDX carries as structured
 * metadata has to go somewhere a human will find it. Dropping it was the alternative, and an
 * SBOM whose reader cannot tell which build it describes cannot be checked against anything.
 */
function creationComment(doc: ExportDocument): string {
  const builds = doc.subject.sources;
  if (builds.length === 0) {
    return `Export of ${doc.subject.kind} "${doc.subject.name}". No build has been ingested for it yet, so this document lists no packages.`;
  }
  const listed = builds
    .slice(0, 20)
    .map((b) => `${b.applicationName} (scan ${b.scanId}, ${b.createdAt})`)
    .join("; ");
  const more = builds.length > 20 ? ` and ${builds.length - 20} more` : "";
  return `Export of ${doc.subject.kind} "${doc.subject.name}", assembled from ${builds.length} build(s): ${listed}${more}.`;
}

function rootPackage(
  doc: ExportDocument,
  rootId: string,
  created: string,
): Record<string, unknown> {
  return {
    SPDXID: rootId,
    name: doc.subject.name,
    downloadLocation: NOASSERTION,
    filesAnalyzed: false,
    licenseConcluded: NOASSERTION,
    licenseDeclared: NOASSERTION,
    copyrightText: NOASSERTION,
    annotations: [
      annotation(created, `Subject kind: ${doc.subject.kind}. Subject id: ${doc.subject.id}.`),
    ],
  };
}

function spdxPackage(c: ExportComponent, created: string): Record<string, unknown> {
  const externalRefs: Array<Record<string, string>> = [];
  if (c.purl) {
    externalRefs.push({
      referenceCategory: "PACKAGE-MANAGER",
      referenceType: "purl",
      referenceLocator: c.purl,
    });
  }
  if (c.cpe) {
    externalRefs.push({
      referenceCategory: "SECURITY",
      referenceType: "cpe23Type",
      referenceLocator: c.cpe,
    });
  }

  const pkg: Record<string, unknown> = {
    SPDXID: spdxId(c.identityHash),
    name: c.name,
    /*
      NOASSERTION throughout, and it is the correct value rather than a placeholder. It means
      "no claim is being made", which is exactly true: this platform does not yet record
      licences or download locations, and any other value here would be an assertion nobody
      made. An empty string would be a claim that the field is empty.
    */
    downloadLocation: NOASSERTION,
    filesAnalyzed: false,
    licenseConcluded: NOASSERTION,
    licenseDeclared: NOASSERTION,
    copyrightText: NOASSERTION,
  };

  if (c.version) pkg.versionInfo = c.version;
  if (externalRefs.length > 0) pkg.externalRefs = externalRefs;

  const notes = [`Ecosystem: ${c.ecosystem}.`, `Origin: ${c.origin}.`];
  if (c.paths && c.paths.length > 0) {
    const total =
      c.pathCount !== null && c.pathCount > COMPONENT_LOCATION_PATH_CAP
        ? ` (${c.paths.length} of ${c.pathCount})`
        : "";
    notes.push(`Locations${total}: ${c.paths.join(", ")}.`);
  }
  pkg.annotations = [annotation(created, notes.join(" "))];

  return pkg;
}

function annotation(created: string, comment: string): Record<string, string> {
  return {
    annotationDate: created,
    annotationType: "OTHER",
    annotator: "Tool: sbom-platform",
    comment,
  };
}

/**
 * SPDX identifiers are constrained to letters, digits, dot and dash.
 *
 * Identity hashes are hex and already conform, but the substitution is unconditional: the
 * hash is a SHA-256 of a purl today and nothing guarantees that forever, and a single stray
 * character would produce a document that fails validation with no clue as to which package
 * caused it.
 */
function spdxId(identityHash: string): string {
  return `SPDXRef-Package-${identityHash.replace(/[^a-zA-Z0-9.-]/g, "-")}`;
}
