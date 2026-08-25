import { describe, expect, it } from "vitest";
import {
  corroborationOf,
  maliciousCorroborations,
  MALICIOUS_CORROBORATION_LABELS,
  listMaliciousQuerySchema,
  maliciousFindingSort,
} from "@sbom/shared";

/**
 * How many independent parties reported a package, and how that is turned into a tier.
 *
 * The tier decides which findings a human opens first, and the failure it must not have is
 * the quiet one: a report with no attribution silently counted as though someone had vouched
 * for it. Measured against the installed feed, 16.9% of reports carry no reporter at all and
 * 77.1% carry exactly one — so the boundary between "nobody said who" and "one party said so"
 * covers 94% of everything, and getting it wrong would mis-sort almost the entire table.
 *
 * The other half of what is pinned here is that the tier is only ever *derived*. It is
 * computed from the `sources` column at read time rather than stored, which is what lets a
 * feed refresh that adds a second reporter to an existing report promote it without a
 * migration or a re-sweep. A stored copy would need both and would be wrong in between.
 */

describe("corroborationOf", () => {
  it("calls two or more reporters corroborated", () => {
    expect(corroborationOf(["amazon-inspector", "ghsa-malware"])).toBe("corroborated");
    expect(corroborationOf(["a", "b", "c", "d"])).toBe("corroborated");
  });

  it("calls exactly one reporter a single source", () => {
    // 77% of the feed. The ordinary case, and deliberately not treated as a problem.
    expect(corroborationOf(["ghsa-malware"])).toBe("single_source");
  });

  it("distinguishes no attribution from a single reporter", () => {
    /*
     * The distinction this whole tier exists for. Upstream sets
     * `malicious-packages-origins` to null on some reports, so an empty list means "we cannot
     * tell who said this", not "one party said it". Folding the two together would present
     * 39,944 unattributed reports as though somebody had put their name to them.
     */
    expect(corroborationOf([])).toBe("unattributed");
    expect(corroborationOf(null)).toBe("unattributed");
    expect(corroborationOf(undefined)).toBe("unattributed");
  });

  it("never returns a value outside the declared set", () => {
    for (const sources of [[], ["one"], ["one", "two"], ["a", "b", "c"]]) {
      expect(maliciousCorroborations).toContain(corroborationOf(sources));
    }
  });

  it("has wording for every tier", () => {
    // A tier added later without a label would render as `undefined` in a table cell.
    for (const tier of maliciousCorroborations) {
      expect(MALICIOUS_CORROBORATION_LABELS[tier]).toBeTruthy();
    }
  });
});

describe("the findings query contract", () => {
  it("accepts each tier as a filter", () => {
    for (const tier of maliciousCorroborations) {
      const parsed = listMaliciousQuerySchema.parse({ corroboration: tier });
      expect(parsed.corroboration).toBe(tier);
    }
  });

  it("leaves the filter absent by default rather than defaulting to a tier", () => {
    // An implicit default would hide 94% of the feed behind a filter nobody set.
    expect(listMaliciousQuerySchema.parse({}).corroboration).toBeUndefined();
  });

  it("rejects a tier it does not define", () => {
    expect(() => listMaliciousQuerySchema.parse({ corroboration: "probably" })).toThrow();
  });

  it("offers corroboration as a sort column", () => {
    expect(maliciousFindingSort.fields).toContain("corroboration");
  });

  it("still defaults to the most urgent column, not to evidence", () => {
    /*
     * Evidence quality is a triage aid, not the headline. A table that opened sorted by it
     * would put a well-attested package nobody ships above a single-source one sitting in
     * production right now.
     */
    expect(maliciousFindingSort.defaultField).toBe("currentApplications");
  });
});
