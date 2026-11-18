import { describe, expect, it } from "vitest";
import {
  advisorySearchQuerySchema,
  cvssVersionOf,
  findingsQuerySchema,
  matchesCvssFilter,
  parseCvssFilter,
  readCvssMetrics,
} from "@sbom/shared";
import { cvssMetricConditions, cvssVersionCondition } from "../../src/modules/vulnerabilities/attack-vector.js";

/** Filtering on every CVSS base metric, read from the vector each advisory already carries. */

const V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const V31_HARD = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N";
const V40 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N";
// Supplemental metrics that reuse letters: S (Safety), AU (Automatable), U (Urgency, words).
const V40_SUPPLEMENTAL = "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/U:Clear";
const V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P";

describe("reading the filter", () => {
  it("takes single parts, several, or a pasted vector", () => {
    expect(parseCvssFilter("AC:L").parts).toEqual(["AC:L"]);
    expect(parseCvssFilter(["pr:n", "UI:N"]).parts).toEqual(["PR:N", "UI:N"]);
    expect(parseCvssFilter(V31).parts).toEqual(["AV:N", "AC:L", "PR:N", "UI:N", "S:C", "C:H", "I:H", "A:H"]);
  });

  it("counts CVSS 4.0's VC/VI/VA as C/I/A and reports what it does not know", () => {
    const { parts, ignored } = parseCvssFilter(V40);
    expect(parts).toEqual(expect.arrayContaining(["C:H", "I:L", "A:N", "AT:P", "UI:P"]));
    expect(ignored).toEqual(["SC:N", "SI:N", "SA:N"]);
  });

  it("refuses unknown values in the query instead of widening the filter", () => {
    expect(advisorySearchQuerySchema.safeParse({ cvss: "AC:X" }).success).toBe(false);
    expect(findingsQuerySchema.safeParse({ cvss: "ZZ:N" }).success).toBe(false);
    expect(advisorySearchQuerySchema.parse({ cvss: ["AC:L", "PR:N/UI:N"] }).cvss).toEqual(["AC:L", "PR:N", "UI:N"]);
    expect(advisorySearchQuerySchema.parse({}).cvss).toEqual([]);
    expect(advisorySearchQuerySchema.parse({ cvssVersion: "4" }).cvssVersion).toEqual(["4"]);
  });
});

describe("matching vectors", () => {
  it("ORs values of one metric and ANDs metrics", () => {
    expect(matchesCvssFilter(V31, ["AC:L", "AC:H"])).toBe(true);
    expect(matchesCvssFilter(V31_HARD, ["AC:L"])).toBe(false);
    expect(matchesCvssFilter(V31, ["AC:L", "PR:N", "C:H"])).toBe(true);
    expect(matchesCvssFilter(V31, ["AC:L", "PR:L"])).toBe(false);
  });

  it("reads CVSS 4.0 impacts and versions' own values", () => {
    expect(matchesCvssFilter(V40, ["C:H", "I:L", "AT:P", "UI:P"])).toBe(true);
    expect(matchesCvssFilter(V31, ["AT:N"])).toBe(false); // 3.x has no attack requirements
    expect(matchesCvssFilter(V40, ["S:U", "S:C"])).toBe(false); // 4.0 has no scope
  });

  it("never mistakes supplemental metrics for base ones", () => {
    expect(matchesCvssFilter(V40_SUPPLEMENTAL, ["S:C"])).toBe(false);
    expect(matchesCvssFilter(V40_SUPPLEMENTAL, ["A:H"])).toBe(true);
    expect(matchesCvssFilter(V40_SUPPLEMENTAL, ["A:N"])).toBe(false);
    expect(readCvssMetrics(V40_SUPPLEMENTAL)).toEqual({ AV: "L", AC: "L", AT: "N", PR: "H", UI: "N", C: "N", I: "N", A: "H" });
  });

  it("leaves out advisories with no vector once any metric is chosen", () => {
    expect(matchesCvssFilter(null, ["AC:L"])).toBe(false);
    expect(matchesCvssFilter(null, [])).toBe(true);
  });

  it("names the version", () => {
    expect([V40, V31, V2, null, "garbage"].map(cvssVersionOf)).toEqual(["4", "3", "2", "none", "none"]);
  });
});

describe("the SQL", () => {
  it("is one condition per metric, with the pattern as a parameter", () => {
    expect(cvssMetricConditions([])).toEqual([]);
    expect(cvssMetricConditions(["AC:L", "AC:H", "PR:N"])).toHaveLength(2);
    expect(cvssVersionCondition([])).toBeNull();
    expect(cvssVersionCondition(["4", "none"])).not.toBeNull();
  });
});
