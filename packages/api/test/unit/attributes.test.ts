import { describe, expect, it } from "vitest";
import { mergeAttributes, validateAttributes } from "../../src/modules/admin/attributes.js";
import type { AttributeDefinitionRow } from "../../src/db/schema.js";

function def(overrides: Partial<AttributeDefinitionRow> & { key: string }): AttributeDefinitionRow {
  return {
    id: `id-${overrides.key}`,
    key: overrides.key,
    label: overrides.label ?? overrides.key,
    type: overrides.type ?? "string",
    options: overrides.options ?? null,
    sortOrder: overrides.sortOrder ?? 0,
    isActive: overrides.isActive ?? true,
    createdAt: new Date(),
  };
}

const DEFS = [
  def({ key: "squad", label: "Squad" }),
  def({ key: "severity", label: "Severity", type: "select", options: ["critical", "high", "low"] }),
  def({ key: "replicas", label: "Replicas", type: "number" }),
  def({ key: "customer_facing", label: "Customer facing", type: "boolean" }),
  def({ key: "notes", label: "Notes", type: "text" }),
];

describe("validateAttributes", () => {
  it("accepts values matching their definitions", () => {
    expect(
      validateAttributes(DEFS, {
        squad: "payments",
        severity: "critical",
        replicas: 3,
        customer_facing: true,
        notes: "handles card data",
      }),
    ).toEqual({
      squad: "payments",
      severity: "critical",
      replicas: 3,
      customer_facing: true,
      notes: "handles card data",
    });
  });

  /**
   * Field-level messages live in `details`, keyed by field, not in the
   * top-level message — that is the shape the whole API validates with, and
   * what lets the edit form render an error under the offending input rather
   * than one banner for the whole dialog.
   */
  function detailFor(attributes: Record<string, unknown>, key: string): string {
    try {
      validateAttributes(DEFS, attributes as never);
      expect.unreachable("should have thrown");
    } catch (err) {
      return (err as { details: Record<string, string[]> }).details[key]?.[0] ?? "";
    }
  }

  it("rejects an unknown key rather than silently storing it", () => {
    // The jsonb column would happily accept `sqaud`, and nobody would find out
    // until someone asked why a squad's application list was short.
    expect(() => validateAttributes(DEFS, { sqaud: "payments" })).toThrowError(/not valid/);
    expect(detailFor({ sqaud: "payments" }, "sqaud")).toMatch(/unknown attribute/);
  });

  it("names the defined keys in the error, so the typo is obvious", () => {
    expect(detailFor({ sqaud: "payments" }, "sqaud")).toContain("squad");
  });

  it("rejects a select value outside its options and lists the valid ones", () => {
    const detail = detailFor({ severity: "urgent" }, "severity");
    expect(detail).toContain("critical");
    expect(detail).toContain("high");
  });

  it("coerces a numeric string, since every HTML input yields a string", () => {
    expect(validateAttributes(DEFS, { replicas: "5" })).toEqual({ replicas: 5 });
  });

  it("rejects a non-numeric value for a number attribute", () => {
    expect(detailFor({ replicas: "many" }, "replicas")).toMatch(/must be a number/);
  });

  it('accepts the string forms of booleans that a <select> produces', () => {
    expect(validateAttributes(DEFS, { customer_facing: "true" })).toEqual({ customer_facing: true });
    expect(validateAttributes(DEFS, { customer_facing: "false" })).toEqual({ customer_facing: false });
  });

  it("rejects a boolean value that is neither true nor false", () => {
    expect(detailFor({ customer_facing: "maybe" }, "customer_facing")).toMatch(/true or false/);
  });

  it("treats null and empty string as 'clear this value'", () => {
    // Both arrive from the UI: null from a cleared select, "" from a cleared
    // text input. They must mean the same thing or the two controls behave
    // differently for no reason the user can see.
    expect(validateAttributes(DEFS, { squad: null })).toEqual({ squad: null });
    expect(validateAttributes(DEFS, { squad: "" })).toEqual({ squad: null });
  });

  it("reports every invalid field at once, not just the first", () => {
    try {
      validateAttributes(DEFS, { severity: "urgent", replicas: "many" });
      expect.unreachable("should have thrown");
    } catch (err) {
      const details = (err as { details: Record<string, string[]> }).details;
      expect(Object.keys(details).sort()).toEqual(["replicas", "severity"]);
    }
  });

  it("accepts an empty patch", () => {
    expect(validateAttributes(DEFS, {})).toEqual({});
  });
});

describe("mergeAttributes", () => {
  it("overlays the patch onto the current values", () => {
    expect(mergeAttributes({ squad: "payments", severity: "low" }, { severity: "high" })).toEqual({
      squad: "payments",
      severity: "high",
    });
  });

  it("leaves keys the patch does not mention untouched", () => {
    // This is what makes a partial edit form safe: sending only the field that
    // changed must not wipe the others.
    expect(mergeAttributes({ squad: "payments", owner: "alice" }, { squad: "billing" })).toEqual({
      squad: "billing",
      owner: "alice",
    });
  });

  it("deletes a key set to null rather than storing a null", () => {
    // Storing null would leave `attributes ? 'squad'` true for an application
    // with no squad, and that predicate drives the filter dropdown.
    const result = mergeAttributes({ squad: "payments", owner: "alice" }, { squad: null });
    expect(result).toEqual({ owner: "alice" });
    expect("squad" in result).toBe(false);
  });

  it("does not mutate the original object", () => {
    const current = { squad: "payments" };
    mergeAttributes(current, { squad: "billing" });
    expect(current).toEqual({ squad: "payments" });
  });
});
