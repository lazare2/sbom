import { describe, expect, it } from "vitest";
import {
  classifySuppressionSchema,
  createSuppressionSchema,
  requiresJustification,
  vexStatuses,
  VEX_CYCLONEDX_STATE,
  VEX_STATUS_LABELS,
} from "@sbom/shared";
import { renderVex } from "../../src/modules/exports/vex.render.js";
import type { VexDocument, VexStatement } from "../../src/modules/exports/export.types.js";

/**
 * What a VEX document asserts on the organisation's behalf.
 *
 * This is the only thing the platform produces that tells somebody else whether they are
 * exposed. Everything else is read by people who can click through to the evidence; a VEX
 * statement is read by a stranger's tooling and acted on without anyone looking.
 *
 * The failure this file exists to prevent is one specific mapping error. A suppression means
 * "an administrator assessed this and excluded it", and that covers three claims which are
 * not interchangeable -- the scanner was wrong, the code is unreachable, and it is real but
 * accepted. Only the third means the product IS vulnerable. Any scheme that derives a single
 * status from "it is suppressed" collapses all three into `not_affected`, which tells a
 * recipient they are safe when they are not. So the status is asked for, never inferred, and
 * the tests below pin both that it is required and that "affected" survives the trip into the
 * document as an admission rather than a denial.
 */

function statement(over: Partial<VexStatement> = {}): VexStatement {
  return {
    suppressionId: "33333333-3333-3333-3333-333333333333",
    vulnerabilityId: "CVE-2021-23337",
    status: "not_affected",
    justification: "code_not_reachable",
    detail: "The prototype pollution path is never reached; we do not call the affected API.",
    affects: ["aaaa1111"],
    createdAt: "2026-08-02T10:00:00.000Z",
    createdByEmail: "security@example.com",
    ...over,
  };
}

function harness(over: Partial<VexDocument> = {}): VexDocument {
  return {
    subject: {
      kind: "application",
      id: "11111111-1111-1111-1111-111111111111",
      name: "payments-api",
      sources: [],
    },
    generatedAt: "2026-08-25T12:00:00.000Z",
    statements: [statement()],
    readiness: { classified: 1, unclassified: 0 },
    ...over,
  };
}

function props(entry: unknown): Record<string, string> {
  const list = (entry as { properties?: Array<{ name: string; value: string }> }).properties ?? [];
  return Object.fromEntries(list.map((p) => [p.name, p.value]));
}

describe("the status mapping is the whole feature", () => {
  it("publishes an accepted risk as exploitable, not as not_affected", () => {
    /*
     * The failure the field exists to prevent. "We have looked at this and decided to carry
     * it" means the product IS vulnerable. Publishing it as `not_affected` would tell a
     * recipient the opposite of the truth, in a document they have no way to check.
     */
    const doc = renderVex(harness({ statements: [statement({ status: "affected", justification: null })] }));
    const entry = (doc.vulnerabilities as Array<{ analysis: { state: string } }>)[0]!;
    expect(entry.analysis.state).toBe("exploitable");
  });

  it("keeps a false positive distinct from a genuine non-exposure", () => {
    // "The scanner matched the wrong package" and "the code is unreachable" are different
    // facts about different things, and a consumer treats them differently.
    expect(VEX_CYCLONEDX_STATE.false_positive).toBe("false_positive");
    expect(VEX_CYCLONEDX_STATE.not_affected).toBe("not_affected");
  });

  it("has a CycloneDX state and a label for every status it offers", () => {
    // A status added later with no mapping would render as `undefined` in the analysis block,
    // producing a document that fails validation for reasons nobody could trace back here.
    for (const status of vexStatuses) {
      expect(VEX_CYCLONEDX_STATE[status]).toBeTruthy();
      expect(VEX_STATUS_LABELS[status]).toBeTruthy();
    }
  });

  it("offers no state the platform cannot substantiate", () => {
    /*
     * CycloneDX also defines `resolved`, `resolved_with_pedigree` and `in_triage`. This
     * platform has no evidence a fix was applied, and a suppression is by definition not in
     * triage. Offering them would invite somebody to pick one.
     */
    const states = Object.values(VEX_CYCLONEDX_STATE);
    expect(states).not.toContain("resolved");
    expect(states).not.toContain("in_triage");
  });
});

describe("the document", () => {
  it("carries the justification only where the spec attaches one", () => {
    const withJust = renderVex(harness());
    const a = (withJust.vulnerabilities as Array<{ analysis: Record<string, unknown> }>)[0]!;
    expect(a.analysis.justification).toBe("code_not_reachable");

    // Nothing to justify about a finding you have agreed is real.
    const accepted = renderVex(
      harness({ statements: [statement({ status: "affected", justification: null })] }),
    );
    const b = (accepted.vulnerabilities as Array<{ analysis: Record<string, unknown> }>)[0]!;
    expect(b.analysis).not.toHaveProperty("justification");
  });

  it("carries the assessor's own words as the detail", () => {
    // The reason is the only thing that tells a reader what was actually considered. A
    // document with a state and no detail asks them to trust a machine.
    const doc = renderVex(harness());
    const entry = (doc.vulnerabilities as Array<{ analysis: { detail: string } }>)[0]!;
    expect(entry.analysis.detail).toContain("never reached");
  });

  it("names who assessed it, and omits the field rather than inventing a name", () => {
    const named = renderVex(harness());
    expect(props((named.vulnerabilities as unknown[])[0])["sbom:assessed-by"]).toBe(
      "security@example.com",
    );

    // Null happens when the account has since been deleted. "unknown" rendered as a name
    // would look like an assessor called unknown.
    const anon = renderVex(harness({ statements: [statement({ createdByEmail: null })] }));
    expect(props((anon.vulnerabilities as unknown[])[0])["sbom:assessed-by"]).toBeUndefined();
  });

  it("declares how many assessments it could not express", () => {
    /*
     * A recipient cannot tell a complete set of statements from a partial one by looking at
     * it. Omitting this count would present the remainder as the whole -- and unclassified
     * suppressions are real decisions the platform holds and cannot publish.
     */
    const doc = renderVex(harness({ readiness: { classified: 1, unclassified: 7 } }));
    const meta = props(doc.metadata);
    expect(meta["sbom:vex:unclassified-suppressions"]).toBe("7");
    expect(meta["sbom:vex:statements"]).toBe("1");
  });

  it("still says so when it has nothing to assert", () => {
    // An empty VEX beside an SBOM means "we have assessed nothing", which is a real and
    // useful statement. It must not be an error or an empty response.
    const doc = renderVex(harness({ statements: [], readiness: { classified: 0, unclassified: 3 } }));
    expect(doc.vulnerabilities).toEqual([]);
    expect(props(doc.metadata)["sbom:vex:unclassified-suppressions"]).toBe("3");
  });

  it("identifies itself as VEX rather than as an inventory", () => {
    // Both are CycloneDX with the same media type. Without this a consumer holding two files
    // has to guess which is which from the presence of a components array.
    expect(props(renderVex(harness()).metadata)["sbom:document"]).toBe("vex");
  });

  it("references components by the same bom-ref the SBOM export uses", () => {
    // The two documents are published together and one is meant to resolve against the other.
    const doc = renderVex(
      harness({ statements: [statement({ affects: ["bbbb2222", "aaaa1111"] })] }),
    );
    const entry = (doc.vulnerabilities as Array<{ affects: Array<{ ref: string }> }>)[0]!;
    expect(entry.affects).toEqual([{ ref: "aaaa1111" }, { ref: "bbbb2222" }]);
  });

  it("orders statements so republishing an unchanged set produces the same bytes", () => {
    const doc = renderVex(
      harness({
        statements: [
          statement({ suppressionId: "s2", vulnerabilityId: "CVE-2024-2222" }),
          statement({ suppressionId: "s1", vulnerabilityId: "CVE-2020-1111" }),
        ],
      }),
    );
    // Rendered in the order given: sorting is the assembler's job, and this pins that the
    // renderer does not reshuffle what it was handed.
    const ids = (doc.vulnerabilities as Array<{ id: string }>).map((v) => v.id);
    expect(ids).toEqual(["CVE-2024-2222", "CVE-2020-1111"]);
  });
});

describe("the suppression contract", () => {
  it("will not create a suppression that does not say what it claims", () => {
    // Nullable in the database for rows that predate the field; required here so no new
    // unclassified debt is created.
    expect(() =>
      createSuppressionSchema.parse({ vulnerabilityId: "CVE-2021-44228", reason: "accepted" }),
    ).toThrow();
  });

  it("accepts a complete one", () => {
    const parsed = createSuppressionSchema.parse({
      vulnerabilityId: "CVE-2021-44228",
      reason: "accepted for this quarter",
      vexStatus: "affected",
    });
    expect(parsed.vexStatus).toBe("affected");
  });

  it("requires a justification for not_affected", () => {
    // Some consumers reject a `not_affected` carrying no reason outright, and they are right
    // to: it is an assertion of safety with nothing behind it.
    expect(() =>
      createSuppressionSchema.parse({
        vulnerabilityId: "CVE-2021-44228",
        reason: "not reachable",
        vexStatus: "not_affected",
      }),
    ).toThrow();
  });

  it("rejects a justification on a status that does not take one", () => {
    /*
     * Not merely ignored. A justification left over in a form after switching the status is
     * a claim about a different state, and silently dropping it would let a stale value look
     * like it had been considered.
     */
    expect(() =>
      createSuppressionSchema.parse({
        vulnerabilityId: "CVE-2021-44228",
        reason: "accepted",
        vexStatus: "affected",
        vexJustification: "code_not_reachable",
      }),
    ).toThrow();
  });

  it("applies the same rule when classifying an existing suppression", () => {
    // The two are the only ways a status can be set. A rule enforced in one of them is not a
    // rule, which is why the refinement is shared rather than written twice.
    expect(() => classifySuppressionSchema.parse({ vexStatus: "not_affected" })).toThrow();
    expect(classifySuppressionSchema.parse({ vexStatus: "false_positive" }).vexStatus).toBe(
      "false_positive",
    );
  });

  it("agrees with the helper the forms use to decide whether to ask", () => {
    // The dialog shows the justification field based on this; the API validates on the
    // refinement above. If they disagreed, the form would submit something always rejected.
    for (const status of vexStatuses) {
      expect(requiresJustification(status)).toBe(status === "not_affected");
    }
  });
});
