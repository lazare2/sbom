import { describe, expect, it } from "vitest";
import { sql, type SQL } from "drizzle-orm";
import { PgDialect } from "drizzle-orm/pg-core";
import { AnalyticsService } from "../../src/modules/analytics/analytics.service.js";
import { ComponentsService } from "../../src/modules/components/components.service.js";
import type { ReadScope } from "../../src/modules/environments/environment.service.js";
import { InventoryService } from "../../src/modules/inventory/inventory.service.js";
import { teamPredicate } from "../../src/modules/inventory/team-filter.js";

/**
 * Aggregates that used to read past the caller's access.
 *
 * Each of these once counted rows in every estate - including applications the reader was
 * never granted - beside figures that were correctly scoped. Nothing errors when that
 * happens: the number is simply larger than it should be. So the queries are rendered here
 * without a database and checked for the one thing that matters: every subquery that reads
 * `application` or `scan` carries the reader's estate.
 */

const ENV_ID = "11111111-1111-4111-8111-111111111111";
const APP_ID = "22222222-2222-4222-8222-222222222222";

/** A reader narrowed to one application: the case a missing predicate leaks for. */
const RESTRICTED = {
  id: ENV_ID,
  name: "Production",
  visibility: { unrestricted: false, wholeEnvironmentIds: [], groupIds: [], applicationIds: [APP_ID] },
  __readScope: true,
} as unknown as ReadScope;

const dialect = new PgDialect();

function capturingDb(row: Record<string, unknown> = {}) {
  const queries: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    execute: async (query: SQL) => {
      queries.push(dialect.sqlToQuery(query));
      return { rows: [row] };
    },
  };
  return { db, queries };
}

/** How many times the estate id is bound into a query - one per scoped subquery. */
function scopeBindings(query: { params: unknown[] }): number {
  return query.params.filter((p) => p === ENV_ID).length;
}

function analytics(db: unknown) {
  return new AnalyticsService({
    db: db as never,
    config: {} as never,
    dashboard: {} as never,
    settings: { staleInterval: async () => sql`interval '30 days'` } as never,
    vulnReport: {} as never,
  });
}

describe("read-scope leaks", () => {
  it("scopes every coverage counter, not just the eligible one", async () => {
    // One row shape serves both coverage queries: the summary and the offender list.
    const { db, queries } = capturingDb({
      eligible: 1, covered: 1, stale: 0, never_scanned: 0, pending: 0,
      id: APP_ID, name: "svc", last_scan_at: null, days_since_scan: null,
    });
    await analytics(db).coverage(5, RESTRICTED);

    const summary = queries[0]!;
    // eligible, covered, stale, never_scanned, pending.
    expect(scopeBindings(summary)).toBe(5);
    expect(summary.params).toContainEqual([APP_ID]);
  });

  it("scopes the churn section's scan counts", async () => {
    const { db, queries } = capturingDb({});
    await analytics(db).velocity(new Date(), RESTRICTED);

    // current_builds, scans in window, applications scanned in window.
    expect(scopeBindings(queries[0]!)).toBe(3);
  });

  it("limits package suggestions and the ecosystem list to visible applications", async () => {
    const { db, queries } = capturingDb({ name: "x", ecosystem: "npm", version_count: 1, count: 1 });
    const components = new ComponentsService({ db: db as never });
    await components.suggest({ q: "lib", limit: 5 }, [RESTRICTED]);
    await components.listEcosystems([RESTRICTED]);

    for (const query of queries) {
      expect(query.params).toContainEqual([ENV_ID]);
      expect(query.params).toContainEqual([APP_ID]);
    }
  });

  it("drops versions no visible application has shipped, and counts only visible ones", async () => {
    const { db, queries } = capturingDb({});
    await new ComponentsService({ db: db as never }).listVersions("openssl", [RESTRICTED]);

    const text = queries[0]!.sql;
    expect(text).toContain("count(a.id)::int AS total_applications");
    expect(text).toContain("HAVING count(a.id) > 0");
  });

  it("scopes every inventory query, and the team filter only narrows on top of it", async () => {
    // A null build time, as a row from the largest-applications query can carry.
    const { db, queries } = capturingDb({ scan_at: null });
    const inventory = new InventoryService({
      db: db as never,
      settings: { vulnScanningEnabled: async () => true } as never,
      uncoveredEcosystems: async () => [],
    });
    await inventory.report({
      scope: RESTRICTED,
      filter: { squad: ["Payments"], tribe: [], group: [] },
      limit: 5,
    });

    // totals, two package rankings, distributions, runtimes, ecosystems, fragmentation, largest apps.
    expect(queries).toHaveLength(8);
    for (const query of queries) {
      expect(query.params).toContain(ENV_ID);
      expect(query.params).toContainEqual([APP_ID]);
      // Lower-cased, so the match is case-insensitive like the advisory list's.
      expect(query.params).toContainEqual(["payments"]);
    }
  });

  it("renders no team condition at all when nothing is selected", () => {
    expect(dialect.sqlToQuery(teamPredicate({ squad: [], tribe: [], group: [] })).sql).toBe("TRUE");
  });

  it("refuses to widen an empty selection into every estate", async () => {
    const { db, queries } = capturingDb({});
    await new ComponentsService({ db: db as never }).suggest({ q: "lib", limit: 5 }, []);
    expect(queries[0]!.sql).toContain("FALSE");
  });
});
