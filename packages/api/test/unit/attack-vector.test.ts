import { describe, expect, it } from "vitest";
import {
  advisorySearchQuerySchema,
  describeExploitability,
  findingsQuerySchema,
  isOpenRemoteAttack,
  readCvssVector,
} from "@sbom/shared";
import {
  attackVectorCondition,
  attackVectorLetter,
  matchesNoPrerequisites,
} from "../../src/modules/vulnerabilities/attack-vector.js";

/**
 * Step 3: where an attacker has to be, read from the CVSS vector every advisory already carries.
 */

const V31_LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const V30_LOCAL = "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
const V31_NEEDS_CLICK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N";
const V31_ADJACENT = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
const V31_PHYSICAL = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V40_REMOTE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const V40_PASSIVE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
// v4 with the supplemental metric AU (Automatable), which is not v2's Au.
const V40_AUTOMATABLE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AU:N";
const V2_REMOTE = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
const V2_PARENS = "(AV:L/AC:L/Au:S/C:C/I:C/A:C)";

describe("reading a CVSS vector", () => {
  it.each([
    [V31_LOG4SHELL, "network", true, true],
    [V30_LOCAL, "local", false, true],
    [V31_NEEDS_CLICK, "network", true, false],
    [V31_ADJACENT, "adjacent", true, true],
    [V31_PHYSICAL, "physical", true, true],
    [V40_REMOTE, "network", true, true],
    [V40_PASSIVE, "network", true, false],
    [V40_AUTOMATABLE, "network", false, true],
    // v2 has no user-interaction part: unknown, never guessed.
    [V2_REMOTE, "network", true, null],
    [V2_PARENS, "local", false, null],
  ])("%s", (vector, attackVector, noPrivileges, noUserInteraction) => {
    expect(readCvssVector(vector)).toEqual({ attackVector, noPrivileges, noUserInteraction });
  });

  it("says nothing when there is no vector, or one it cannot read", () => {
    const none = { attackVector: null, noPrivileges: null, noUserInteraction: null };
    expect(readCvssVector(null)).toEqual(none);
    expect(readCvssVector("")).toEqual(none);
    expect(readCvssVector("not a vector")).toEqual(none);
  });

  it("is not fooled by lower case", () => {
    expect(readCvssVector(V31_LOG4SHELL.toLowerCase()).attackVector).toBe("network");
  });

  it("marks only remote, no sign-in and no action as the easiest attack", () => {
    expect(isOpenRemoteAttack(readCvssVector(V31_LOG4SHELL))).toBe(true);
    expect(isOpenRemoteAttack(readCvssVector(V31_NEEDS_CLICK))).toBe(false);
    expect(isOpenRemoteAttack(readCvssVector(V31_ADJACENT))).toBe(false);
    expect(isOpenRemoteAttack(readCvssVector(V2_REMOTE))).toBe(false);
  });
});

describe("the plain sentence on the vulnerability page", () => {
  it.each([
    [V31_LOG4SHELL, "Can be attacked remotely, over the network, without signing in or anybody's action."],
    [V31_NEEDS_CLICK, "Can be attacked remotely, over the network, without signing in; it needs someone to take an action, such as opening a link."],
    [V30_LOCAL, "Can be attacked only by someone with access to the machine, without anybody's action; it needs a signed-in account."],
    [V2_REMOTE, "Can be attacked remotely, over the network, without signing in."],
    [null, "The advisory does not say where an attacker has to be."],
  ])("%s", (vector, sentence) => {
    expect(describeExploitability(readCvssVector(vector))).toBe(sentence);
  });
});

describe("the database filter reads vectors exactly as the page does", () => {
  const vectors = [
    V31_LOG4SHELL, V30_LOCAL, V31_NEEDS_CLICK, V31_ADJACENT, V31_PHYSICAL,
    V40_REMOTE, V40_PASSIVE, V40_AUTOMATABLE, V2_REMOTE, V2_PARENS, null, "garbage",
  ];
  const letter = { network: "N", adjacent: "A", local: "L", physical: "P" } as const;

  it.each(vectors)("attack vector of %s", (vector) => {
    const read = readCvssVector(vector).attackVector;
    expect(attackVectorLetter(vector)).toBe(read ? letter[read] : null);
  });

  it.each(vectors)("no sign-in or action for %s", (vector) => {
    const e = readCvssVector(vector);
    expect(matchesNoPrerequisites(vector)).toBe(e.noPrivileges === true && e.noUserInteraction === true);
  });
});

describe("the filter parameters", () => {
  it("accept one value or several, and unknown", () => {
    expect(advisorySearchQuerySchema.parse({ attackVector: "network" }).attackVector).toEqual(["network"]);
    expect(findingsQuerySchema.parse({ attackVector: ["local", "unknown"] }).attackVector).toEqual(["local", "unknown"]);
    expect(findingsQuerySchema.parse({ noPrerequisites: "true" }).noPrerequisites).toBe(true);
  });

  it("refuse anything else", () => {
    expect(() => advisorySearchQuerySchema.parse({ attackVector: "internet" })).toThrow();
  });

  it("add no condition when nothing is chosen", () => {
    expect(attackVectorCondition([])).toBeNull();
    expect(attackVectorCondition(["network"])).not.toBeNull();
  });
});
