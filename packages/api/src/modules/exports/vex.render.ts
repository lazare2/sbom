import { randomUUID } from "node:crypto";
import { CYCLONEDX_SPEC_VERSION, VEX_CYCLONEDX_STATE } from "@sbom/shared";
import type { VexDocument } from "./export.types.js";

/**
 * Renders assessments as a CycloneDX VEX document.
 *
 * ## Why this is not just a field on the SBOM export
 *
 * A VEX document has a different lifecycle from the inventory it describes. The packages in a
 * build never change; what the organisation believes about them changes as people investigate.
 * Keeping them separate means an updated assessment can be republished without reissuing the
 * SBOM, which is the arrangement the format was designed for.
 *
 * ## Every statement is somebody's, and says so
 *
 * `detail` carries the administrator's own words and the analysis records who wrote them and
 * when. A VEX statement is an assertion made to people outside the organisation who cannot
 * check it; an anonymous one asks them to trust a document rather than a decision, and the
 * first question anybody asks about an inconvenient "not affected" is who decided that.
 */

const TOOL_NAME = "sbom-platform";

export function renderVex(doc: VexDocument): Record<string, unknown> {
  return {
    bomFormat: "CycloneDX",
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: doc.generatedAt,
      tools: { components: [{ type: "application", name: TOOL_NAME }] },
      component: {
        "bom-ref": `${doc.subject.kind}:${doc.subject.id}`,
        type: "application",
        name: doc.subject.name,
      },
      properties: [
        { name: "sbom:document", value: "vex" },
        { name: "sbom:subject:kind", value: doc.subject.kind },
        { name: "sbom:subject:id", value: doc.subject.id },
        { name: "sbom:vex:statements", value: String(doc.statements.length) },
        /*
          The coverage declaration, and the reason this renderer exists rather than the
          statements being appended to the SBOM export. A recipient cannot tell a complete set
          of assertions from a partial one by looking at it, so the document says which it is.
          Suppressions with no VEX status are real assessments this platform holds and cannot
          express; omitting the count would present the remainder as the whole.
        */
        { name: "sbom:vex:unclassified-suppressions", value: String(doc.readiness.unclassified) },
      ],
    },
    vulnerabilities: doc.statements.map((s) => ({
      "bom-ref": s.suppressionId,
      id: s.vulnerabilityId,
      analysis: {
        state: VEX_CYCLONEDX_STATE[s.status],
        // Present only for not_affected, which is the one state the spec asks to justify.
        ...(s.justification ? { justification: s.justification } : {}),
        detail: s.detail,
      },
      affects: [...s.affects].sort().map((ref) => ({ ref })),
      properties: [
        { name: "sbom:assessed-at", value: s.createdAt },
        // The author, when the row has one. An account deleted since is why this can be null,
        // and an absent property is more honest than "unknown" rendered as a name.
        ...(s.createdByEmail ? [{ name: "sbom:assessed-by", value: s.createdByEmail }] : []),
      ],
    })),
  };
}
