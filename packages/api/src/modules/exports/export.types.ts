import type {
  ComponentOrigin,
  ExportFlavour,
  VexJustification,
  VexReadiness,
  VexStatus,
  VulnSeverity,
} from "@sbom/shared";

/**
 * One neutral document that both renderers read.
 *
 * The alternative -- querying once per format -- was rejected because the two formats would
 * then be free to disagree about what the estate contains, and the only way to notice would
 * be for somebody to export both and diff them by hand. Assembling once means a CycloneDX
 * and an SPDX export of the same subject are the same inventory by construction, and the
 * renderers are pure functions over it, which is also what makes them cheap to test.
 */

export interface ExportSource {
  scanId: string;
  applicationId: string;
  applicationName: string;
  createdAt: string;
  imageRef: string | null;
  commitSha: string | null;
  buildNumber: string | null;
  branch: string | null;
  toolName: string | null;
  toolVersion: string | null;
}

export interface ExportSubject {
  kind: "application" | "scan" | "group";
  id: string;
  name: string;
  /**
   * The builds this document was assembled from -- one for a scan or an application,
   * potentially dozens for a group.
   *
   * Carried into the rendered output rather than used and discarded. An SBOM with no
   * provenance is unfalsifiable: the reader cannot tell which build it describes, so they
   * cannot check it against anything.
   */
  sources: ExportSource[];
}

export interface ExportVulnerability {
  id: string;
  severity: VulnSeverity;
  cvssBaseScore: number | null;
  cvssVector: string | null;
  epssScore: number | null;
  knownExploited: boolean;
  description: string | null;
  fixState: string;
  fixVersions: string[];
  urls: string[];
  dataSource: string | null;
}

export interface ExportMalicious {
  id: string;
  packageName: string;
  sources: string[];
  matchMode: string;
}

export interface ExportComponent {
  identityHash: string;
  name: string;
  version: string | null;
  ecosystem: string;
  kind: "library" | "os" | "runtime";
  purl: string | null;
  cpe: string | null;
  origin: ComponentOrigin;
  paths: string[] | null;
  pathCount: number | null;
  /** Empty on an inventory export, and empty is correct there -- nothing was asked for. */
  vulnerabilities: ExportVulnerability[];
  malicious: ExportMalicious[];
}

export interface ExportDocument {
  subject: ExportSubject;
  flavour: ExportFlavour;
  generatedAt: string;
  components: ExportComponent[];
  /**
   * What had actually been assessed when this was generated.
   *
   * Rendered into the document itself, not just returned to the caller. A file outlives the
   * request that produced it: somebody opens it six months later with no idea whether the
   * absence of findings meant a clean estate or a feature that was switched off, and the
   * document has to be able to answer that on its own.
   */
  assessment: {
    vulnerabilityScanning: boolean;
    maliciousDetection: boolean;
  };
}

/**
 * A VEX document: what the organisation asserts about vulnerabilities in a subject.
 *
 * Scoped to the same subject as an SBOM export, and that is the point of it. A VEX document
 * is meant to travel beside a specific SBOM, and the component references here are the same
 * bom-refs the CycloneDX export of that subject emits -- so a consumer holding both can
 * actually resolve one against the other. An estate-wide VEX listing every suppression would
 * be simpler to produce and useless to receive, because most of its statements would concern
 * packages the recipient does not have.
 */
export interface VexStatement {
  suppressionId: string;
  vulnerabilityId: string;
  status: VexStatus;
  justification: VexJustification | null;
  /** The administrator's stated reason. Becomes the `detail` a reader actually acts on. */
  detail: string;
  /** Identity hashes of the components in this subject that the statement covers. */
  affects: string[];
  createdAt: string;
  createdByEmail: string | null;
}

export interface VexDocument {
  subject: ExportSubject;
  generatedAt: string;
  statements: VexStatement[];
  /**
   * Coverage, carried into the rendered document.
   *
   * `unclassified` is the number of suppressions that apply to this subject but say nothing a
   * VEX consumer can read. Publishing the document without that number would present a
   * partial set of assertions as a complete one -- and a consumer has no way to detect the
   * difference from the outside.
   */
  readiness: VexReadiness;
}
