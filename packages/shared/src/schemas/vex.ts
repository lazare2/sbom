import { z } from "zod";

/**
 * VEX -- an assertion about whether a vulnerability actually affects the product.
 *
 * ## Why a suppression is not already a VEX statement
 *
 * A suppression records that an administrator assessed a finding and chose to exclude it.
 * That single act covers three claims which are not interchangeable:
 *
 *   - the scanner matched the wrong package        -> `false_positive`
 *   - the vulnerable code is not reachable here    -> `not_affected`
 *   - it is real and we are accepting the risk     -> `affected`
 *
 * Internally the distinction only changes a sentence on a page. In a VEX document it changes
 * what a downstream consumer is told, and they may act on it without ever speaking to us.
 * Exporting the third case as `not_affected` -- which is what any single-status scheme
 * derived from "it is suppressed" would do -- states that the product is not vulnerable when
 * it is. That is the one failure this feature cannot be allowed to have, so the status is
 * asked for explicitly and never inferred from the free-text reason.
 *
 * ## Unclassified is a real state and stays one
 *
 * Suppressions created before this existed have no status, and nothing back-fills them. They
 * are excluded from the VEX document and counted on screen so somebody can work through
 * them. Defaulting them would be the same defect as a zero-filled severity breakdown: a
 * judgement nobody made, rendered as though somebody had.
 */

export const vexStatuses = ["not_affected", "false_positive", "affected"] as const;
export type VexStatus = (typeof vexStatuses)[number];

export const VEX_STATUS_LABELS: Record<VexStatus, string> = {
  not_affected: "Not affected",
  false_positive: "False positive",
  affected: "Affected, risk accepted",
};

export const VEX_STATUS_HINTS: Record<VexStatus, string> = {
  not_affected: "The vulnerable code is present but cannot be reached in the way we use it.",
  false_positive: "The scanner matched the wrong package or version. There is no such finding.",
  affected: "The finding is real. We have assessed the risk and chosen to carry it for now.",
};

/**
 * CycloneDX 1.6 `analysis.state`. The mapping is one-way and deliberately narrow.
 *
 * CycloneDX offers `resolved`, `resolved_with_pedigree` and `in_triage` as well. None is
 * offered here: this platform has no evidence a fix was applied, and a suppression is by
 * definition not in triage. Offering states we cannot substantiate would invite somebody to
 * pick one.
 */
export const VEX_CYCLONEDX_STATE: Record<VexStatus, string> = {
  not_affected: "not_affected",
  false_positive: "false_positive",
  affected: "exploitable",
};

/**
 * CycloneDX justifications, restricted to those that can honestly describe a suppression.
 *
 * Required when the status is `not_affected` and meaningless otherwise -- the spec attaches
 * justification to that state alone, because there is nothing to justify about a finding you
 * have agreed is real.
 */
export const vexJustifications = [
  "code_not_present",
  "code_not_reachable",
  "requires_configuration",
  "requires_dependency",
  "requires_environment",
  "protected_by_compiler",
  "protected_at_runtime",
  "protected_at_perimeter",
  "protected_by_mitigating_control",
] as const;
export type VexJustification = (typeof vexJustifications)[number];

export const VEX_JUSTIFICATION_LABELS: Record<VexJustification, string> = {
  code_not_present: "The vulnerable code is not in the distributed artifact",
  code_not_reachable: "The vulnerable code is present but never executed",
  requires_configuration: "Requires a configuration we do not use",
  requires_dependency: "Requires a dependency we do not ship",
  requires_environment: "Requires an environment we do not run in",
  protected_by_compiler: "Compiler or build flags neutralise it",
  protected_at_runtime: "The runtime prevents exploitation",
  protected_at_perimeter: "Network controls prevent it being reached",
  protected_by_mitigating_control: "Another control already mitigates it",
};

/**
 * The pairing rule, in one place so the API, the form and the renderer cannot disagree.
 *
 * A `not_affected` with no justification is an incomplete VEX statement that some consumers
 * reject outright; a justification on any other status is a claim about a state it does not
 * describe. Both are rejected rather than quietly dropped.
 */
export const vexAssessmentSchema = z
  .object({
    status: z.enum(vexStatuses),
    justification: z.enum(vexJustifications).nullish(),
  })
  .superRefine((value, ctx) => {
    if (value.status === "not_affected" && !value.justification) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["justification"],
        message: "A justification is required when the status is 'not affected'.",
      });
    }
    if (value.status !== "not_affected" && value.justification) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["justification"],
        message: "A justification only applies when the status is 'not affected'.",
      });
    }
  });
export type VexAssessment = z.infer<typeof vexAssessmentSchema>;

export function requiresJustification(status: VexStatus): boolean {
  return status === "not_affected";
}

/** What the UI shows next to "export VEX" so an incomplete document is never a surprise. */
export interface VexReadiness {
  /** Suppressions that carry a status and will appear in the document. */
  classified: number;
  /** Suppressions with no status. Excluded, never defaulted. */
  unclassified: number;
}
