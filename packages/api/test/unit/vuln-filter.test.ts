import { describe, expect, it } from "vitest";
import {
  bucketize,
  dashboardSeverityBuckets,
  normalizeVulnFilter,
  scopeIncludes,
  severitiesForBuckets,
  totalOf,
  vulnFilterParams,
  vulnFilterQuerySchema,
  vulnSeverities,
  type SeverityCounts,
} from "@sbom/shared";

/**
 * The dashboard vulnerability filter.
 *
 * Pure functions, tested here rather than through the API, because every one of them is a
 * place where a filter could silently mean something other than what the chips on screen
 * say — and a figure read under a misunderstood filter is worse than no figure.
 *
 * The properties that matter:
 *   1. "Everything selected" and "nothing selected" have to collapse to one representation,
 *      or the fast aggregate path gets skipped for a filter that narrows nothing and the
 *      two code paths stop being comparable.
 *   2. The five display buckets must partition all six of Grype's severities exactly once,
 *      so the visible columns always sum to the total.
 *   3. A malformed or stale URL must widen, never fail.
 */

const counts: SeverityCounts = {
  critical: 3,
  high: 11,
  medium: 40,
  low: 7,
  negligible: 5,
  unknown: 2,
};

describe("severity buckets", () => {
  it("partitions every severity exactly once", () => {
    /*
     * The property the whole display rests on. If a severity belonged to two buckets the
     * columns would over-count; if it belonged to none, they would not sum to the total and
     * a reader checking the arithmetic would find the page wrong.
     */
    const covered = dashboardSeverityBuckets.flatMap((bucket) => severitiesForBuckets([bucket]));
    expect([...covered].sort()).toEqual([...vulnSeverities].sort());
    expect(new Set(covered).size).toBe(covered.length);
  });

  it("sums the buckets to the same total as the raw counts", () => {
    const buckets = bucketize(counts);
    const summed = dashboardSeverityBuckets.reduce((acc, bucket) => acc + buckets[bucket], 0);
    expect(summed).toBe(totalOf(counts));
    expect(summed).toBe(68);
  });

  it("folds negligible and unrated into one bucket", () => {
    // Unrated is a real answer, not missing data — it has to be counted somewhere, and
    // promoting it to low would invent an assessment nobody made.
    expect(bucketize(counts).other).toBe(7);
  });

  it("treats an empty selection as every severity", () => {
    expect(severitiesForBuckets([])).toEqual([...vulnSeverities]);
  });
});

describe("normalizeVulnFilter", () => {
  it("is inert by default", () => {
    const filter = normalizeVulnFilter(vulnFilterQuerySchema.parse({}));
    expect(filter).toEqual({
      scope: "all",
      severities: [],
      group: null,
      groupName: null,
      active: false,
      label: null,
    });
  });

  it("collapses a full severity selection to none", () => {
    /*
     * Selecting all five buckets and selecting none describe the same set. Without this
     * they would produce different `active` values, and the service would take the slow
     * exact path — and report a filter on the page and the PDF cover — for a filter that
     * excludes nothing.
     */
    const filter = normalizeVulnFilter(
      vulnFilterQuerySchema.parse({ severity: dashboardSeverityBuckets.join(",") }),
    );
    expect(filter.severities).toEqual([]);
    expect(filter.active).toBe(false);
    expect(filter.label).toBeNull();
  });

  it("is active when the scope narrows even with every severity selected", () => {
    const filter = normalizeVulnFilter(vulnFilterQuerySchema.parse({ scope: "os" }));
    expect(filter.active).toBe(true);
    expect(filter.label).toBe("Base image and runtimes");
  });

  it("describes scope and severity in one line, for the page and the PDF cover alike", () => {
    // One label, computed once. Two consumers wording the same filter differently is how a
    // printed report ends up disagreeing with the screen it came from.
    const filter = normalizeVulnFilter(
      vulnFilterQuerySchema.parse({ scope: "app", severity: "high,critical" }),
    );
    expect(filter.label).toBe("Application dependencies · Critical, High");
  });
});

describe("query parsing", () => {
  it("accepts a comma list and a repeated key alike", () => {
    // The pages use one comma-separated parameter to keep a shared link short; Fastify
    // hands back an array when a key repeats. Rejecting either would break links that look
    // entirely reasonable.
    const comma = vulnFilterQuerySchema.parse({ severity: "critical,high" });
    const repeated = vulnFilterQuerySchema.parse({ severity: ["critical", "high"] });
    expect(comma.severity).toEqual(repeated.severity);
    expect(comma.severity).toEqual(["critical", "high"]);
  });

  it("canonicalises order so two spellings of one filter share a cache key", () => {
    expect(vulnFilterQuerySchema.parse({ severity: "low,critical" }).severity).toEqual([
      "critical",
      "low",
    ]);
  });

  it("drops unrecognised buckets instead of failing", () => {
    /*
     * A stale bookmark naming a bucket that no longer exists should widen to a broader
     * view. Erroring would turn an old link into a dead end on a page whose whole purpose
     * is to be linkable.
     */
    const parsed = vulnFilterQuerySchema.parse({ severity: "critical,banana,,HIGH" });
    expect(parsed.severity).toEqual(["critical", "high"]);
  });

  it("falls back to every scope when the scope is unknown", () => {
    expect(() => vulnFilterQuerySchema.parse({ scope: "sideways" })).toThrow();
  });

  it("round-trips through the URL form", () => {
    const filter = normalizeVulnFilter(
      vulnFilterQuerySchema.parse({ scope: "app", severity: "critical,other" }),
    );
    const params = vulnFilterParams(filter);
    expect(params).toEqual({ scope: "app", severity: "critical,other" });
    expect(normalizeVulnFilter(vulnFilterQuerySchema.parse(params))).toEqual(filter);
  });

  it("omits inert values from the URL, so an unfiltered view has a clean address", () => {
    expect(vulnFilterParams({ scope: "all", severities: [] })).toEqual({});
  });
});

describe("scopeIncludes", () => {
  it("admits both halves only for the combined scope", () => {
    expect(scopeIncludes("all", "app")).toBe(true);
    expect(scopeIncludes("all", "os")).toBe(true);
    expect(scopeIncludes("app", "app")).toBe(true);
    // The reason each half of the report is nullable: excluded has to be distinguishable
    // from counted-and-empty, at every level.
    expect(scopeIncludes("app", "os")).toBe(false);
    expect(scopeIncludes("os", "app")).toBe(false);
  });
});

/**
 * A group narrows *which applications* the page describes, where scope and severity narrow
 * *which findings* within a fixed population. That difference is why the group also reaches
 * the inventory panels, and why the banner has to say which of the two is in force.
 *
 * The name is resolved by the caller because this function is pure and shared with the client.
 * The interesting case is therefore an id with no name behind it — a bookmark pointing at a
 * deleted group — where a label that silently omitted the narrowing would present figures for
 * a subset of the estate as though they covered all of it.
 */
describe("normalizeVulnFilter — group", () => {
  const GROUP = "3f1c2b4a-5d6e-4f70-8192-a3b4c5d6e7f8";

  it("is active on a group alone, with no other narrowing", () => {
    const filter = normalizeVulnFilter(
      vulnFilterQuerySchema.parse({ group: GROUP }),
      "Checkout Platform",
    );

    expect(filter.group).toBe(GROUP);
    expect(filter.active).toBe(true);
    expect(filter.label).toBe("Group: Checkout Platform");
  });

  it("still reports the narrowing when the group name cannot be resolved", () => {
    // A deleted group, or a hand-edited URL. The figures really are restricted to whatever
    // membership survives, so the banner must not go quiet just because the name is gone.
    const filter = normalizeVulnFilter(vulnFilterQuerySchema.parse({ group: GROUP }), null);

    expect(filter.active).toBe(true);
    expect(filter.label).toBe("Group: unknown");
  });

  it("puts the group first when combined with the other filters", () => {
    // Read left to right: the population, then what is counted within it.
    const filter = normalizeVulnFilter(
      vulnFilterQuerySchema.parse({ group: GROUP, scope: "os", severity: "critical" }),
      "Public Facing",
    );

    expect(filter.label).toBe("Group: Public Facing · Base image and runtimes · Critical");
  });

  it("stays inert when no group is given", () => {
    // The estate-wide default has to remain the one that takes the fast aggregate path.
    const filter = normalizeVulnFilter(vulnFilterQuerySchema.parse({}));
    expect(filter.group).toBeNull();
    expect(filter.active).toBe(false);
  });
});
