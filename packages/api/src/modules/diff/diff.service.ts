import { sql, type SQL } from "drizzle-orm";
import type {
  ComponentRef,
  ListRemovedComponentsQuery,
  Paginated,
  RemovedComponent,
  ScanDiff,
  SortDirection,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { BadRequestError, NotFoundError } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";

/**
 * Sort clause for the removed-components table.
 *
 * Not shared with `componentOrderBy`: this query's rows are keyed on the component alone
 * (the `ever` CTE is `DISTINCT ON (component_id)`), and it carries a `last_seen_at` the
 * plain component lists do not have.
 */
function removedOrderBy(sortBy: ListRemovedComponentsQuery["sortBy"], dir: SortDirection): SQL {
  const dir_ = direction(dir);
  const nulls = directionNullsLast(dir);
  const byName = sql`lower(c.name) ASC, c.version ASC NULLS LAST`;

  switch (sortBy) {
    case "name":
      return orderBy([sql`lower(c.name) ${dir_}`, sql`c.version ASC NULLS LAST`], sql`c.id`);
    case "version":
      return orderBy([sql`c.version ${nulls}`, sql`lower(c.name) ASC`], sql`c.id`);
    case "ecosystem":
      return orderBy([sql`c.ecosystem ${dir_}`, byName], sql`c.id`);
    case "purl":
      return orderBy([sql`c.purl ${nulls}`, byName], sql`c.id`);
    case "lastSeenAt":
    default:
      return orderBy([sql`e.last_seen_at ${dir_}`, byName], sql`c.id`);
  }
}

/**
 * Per-side cap on a scan diff.
 *
 * A base-image change can legitimately swap thousands of OS packages at once,
 * and rendering 40,000 rows helps nobody. The response reports `truncated` so
 * the UI can say so rather than quietly showing a partial answer — a diff that
 * silently omits rows is worse than one that admits it stopped counting.
 */
const DIFF_CAP = 2000;

/**
 * Build-to-build comparison, and the longer-range "what did we drop" view.
 *
 * This is the payoff for retaining scan history indefinitely: the platform can
 * answer "this package was here before and is not here now, and here is the
 * exact build it disappeared in", which no point-in-time inventory can.
 */
export class DiffService {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * Compare two scans of the same application.
   *
   * Defaults are chosen so the common case needs no parameters: `toScanId`
   * alone diffs a build against the one immediately before it.
   */
  async diff(applicationId: string, opts: { fromScanId?: string; toScanId?: string }): Promise<ScanDiff> {
    const { db } = this.deps;

    const toScan = opts.toScanId
      ? await this.requireScan(opts.toScanId, applicationId)
      : await this.requireLatestScan(applicationId);

    const fromScan = opts.fromScanId
      ? await this.requireScan(opts.fromScanId, applicationId)
      : await this.requirePreviousScan(applicationId, toScan);

    if (fromScan.id === toScan.id) {
      throw new BadRequestError("A scan cannot be compared with itself.");
    }

    /**
     * The unchanged count is its own statement, not a scalar rendered onto the
     * change rows.
     *
     * It used to ride along on the first row of the query below. That query
     * returns *only* rows that differ, so two identical builds produced no rows
     * at all and the count silently read as zero — the UI then reported "0
     * unchanged" for two builds sharing every package, which says the exact
     * opposite of the truth. A count that only works when there is something
     * else to report is not a count.
     *
     * The join is an index-only intersection on `scan_component`'s
     * (scan_id, component_id) primary key.
     */
    const countRows = await db.execute<Row<{ unchanged_count: number | string }>>(sql`
      SELECT count(*)::int AS unchanged_count
      FROM scan_component f
      JOIN scan_component t
        ON t.component_id = f.component_id AND t.scan_id = ${toScan.id}::uuid
      WHERE f.scan_id = ${fromScan.id}::uuid
    `);
    const unchangedCount = Number(rowsOf(countRows)[0]?.unchanged_count ?? 0);

    // A FULL OUTER JOIN over the two component-id sets gets both directions in
    // a single pass, rather than two anti-join queries that could disagree if a
    // scan were ingested between them.
    const rows = await db.execute<Row<DiffRow>>(sql`
      WITH f AS (SELECT component_id FROM scan_component WHERE scan_id = ${fromScan.id}::uuid),
           t AS (SELECT component_id FROM scan_component WHERE scan_id = ${toScan.id}::uuid),
           paired AS (
             SELECT f.component_id AS from_id, t.component_id AS to_id
             FROM f FULL OUTER JOIN t ON f.component_id = t.component_id
           )
      SELECT
        p.from_id,
        p.to_id,
        c.id, c.name, c.version, c.ecosystem, c.purl
      FROM paired p
      JOIN component c ON c.id = COALESCE(p.from_id, p.to_id)
      WHERE p.from_id IS NULL OR p.to_id IS NULL
      ORDER BY lower(c.name) ASC, c.version ASC NULLS LAST
      LIMIT ${DIFF_CAP * 2 + 1}
    `);

    const all = rowsOf(rows);
    const truncated = all.length > DIFF_CAP * 2;
    const considered = truncated ? all.slice(0, DIFF_CAP * 2) : all;

    const addedRaw = considered.filter((r) => r.from_id === null).map(toComponentRef);
    const removedRaw = considered.filter((r) => r.to_id === null).map(toComponentRef);

    // A version bump shows up as one removal plus one addition of the same
    // package. Pairing them into `changed` is the difference between a readable
    // diff and a wall of noise: on a typical build almost every row is an
    // upgrade, and the handful of genuine adds and drops are what matter.
    const { added, removed, changed } = pairVersionChanges(addedRaw, removedRaw);

    const removedWithProvenance = await this.attachLastSeen(applicationId, removed, toScan.createdAt);

    return {
      applicationId,
      fromScan: summarise(fromScan),
      toScan: summarise(toScan),
      added,
      removed: removedWithProvenance,
      changed,
      unchangedCount,
      truncated,
    };
  }

  /**
   * Everything this application has ever shipped that its current build does
   * not contain.
   *
   * This is the section-6 requirement in one query: "package X was used before
   * (last seen in build #N, on date D) but is not present in the current build."
   */
  async listRemoved(
    applicationId: string,
    query: ListRemovedComponentsQuery,
  ): Promise<Paginated<RemovedComponent> & { latestScanId: string | null }> {
    const { db } = this.deps;

    const appRows = await db.execute<Row<{ latest_scan_id: string | null }>>(sql`
      SELECT latest_scan_id FROM application WHERE id = ${applicationId}::uuid
    `);
    const app = rowsOf(appRows)[0];
    if (!app) throw new NotFoundError("Application");

    if (!app.latest_scan_id) {
      // Never scanned: nothing has been shipped, so nothing can have been
      // dropped. An empty page, not a 404 — the application does exist.
      return { ...paginate<RemovedComponent>([], 0, query), latestScanId: null };
    }

    const conditions: SQL[] = [sql`TRUE`];
    if (query.search) conditions.push(sql`c.name ILIKE ${"%" + query.search + "%"}`);
    if (query.ecosystem) conditions.push(sql`c.ecosystem = ${query.ecosystem}`);

    /**
     * With `ignoreVersion`, a package counts as gone only when no version of it
     * remains — so a routine upgrade does not appear. Without it (the default),
     * the specific version that left is reported, which is what someone tracking
     * a known-bad release needs to see.
     */
    const stillPresent = query.ignoreVersion
      ? sql`
          EXISTS (
            SELECT 1 FROM scan_component cur
            JOIN component cc ON cc.id = cur.component_id
            WHERE cur.scan_id = ${app.latest_scan_id}::uuid
              AND lower(cc.name) = lower(c.name)
              AND cc.ecosystem = c.ecosystem
          )`
      : sql`
          EXISTS (
            SELECT 1 FROM scan_component cur
            WHERE cur.scan_id = ${app.latest_scan_id}::uuid
              AND cur.component_id = c.id
          )`;

    const rows = await db.execute<Row<RemovedRow>>(sql`
      WITH ever AS (
        SELECT DISTINCT ON (sc.component_id)
               sc.component_id,
               sc.scan_id  AS last_seen_scan_id,
               sc.created_at AS last_seen_at
        FROM scan_component sc
        WHERE sc.application_id = ${applicationId}::uuid
        ORDER BY sc.component_id, sc.created_at DESC, sc.scan_id DESC
      )
      SELECT
        c.id, c.name, c.version, c.ecosystem, c.purl,
        e.last_seen_scan_id, e.last_seen_at,
        s.build_number AS last_seen_build_number,
        count(*) OVER () AS total
      FROM ever e
      JOIN component c ON c.id = e.component_id
      JOIN scan s ON s.id = e.last_seen_scan_id
      WHERE ${sql.join(conditions, sql` AND `)}
        AND NOT ${stillPresent}
      ${removedOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const items = rowsOf(rows).map(toRemovedComponent);
    return {
      ...paginate(items, totalFromRows(rowsOf(rows)), query),
      latestScanId: app.latest_scan_id,
    };
  }

  // -------------------------------------------------------------------------

  /**
   * Find, for each removed component, the last scan at or before `asOf` that
   * still contained it.
   *
   * Not simply the `from` scan: when comparing a build against one several
   * builds back, the package may have survived a few builds into the range. The
   * build number a reader needs is the last one that actually had it.
   */
  private async attachLastSeen(
    applicationId: string,
    removed: ComponentRef[],
    asOf: Date,
  ): Promise<RemovedComponent[]> {
    if (removed.length === 0) return [];

    const ids = sql.join(
      removed.map((c) => sql`${Number(c.id)}`),
      sql`, `,
    );

    const rows = await this.deps.db.execute<Row<LastSeenRow>>(sql`
      SELECT DISTINCT ON (sc.component_id)
             sc.component_id,
             sc.scan_id AS last_seen_scan_id,
             sc.created_at AS last_seen_at,
             s.build_number AS last_seen_build_number
      FROM scan_component sc
      JOIN scan s ON s.id = sc.scan_id
      WHERE sc.application_id = ${applicationId}::uuid
        AND sc.component_id IN (${ids})
        AND sc.created_at <= ${asOf.toISOString()}::timestamptz
      ORDER BY sc.component_id, sc.created_at DESC, sc.scan_id DESC
    `);

    const byId = new Map(rowsOf(rows).map((r) => [String(r.component_id), r]));

    return removed.map((c) => {
      const seen = byId.get(c.id);
      return {
        ...c,
        // The fallback cannot normally happen — the component was in the `from`
        // scan, which is at or before `asOf` — but a null-free contract keeps
        // the UI from having to render an empty provenance cell.
        lastSeenScanId: seen?.last_seen_scan_id ?? "",
        lastSeenAt: seen ? toIso(seen.last_seen_at)! : "",
        lastSeenBuildNumber: seen?.last_seen_build_number ?? null,
      };
    });
  }

  private async requireScan(scanId: string, applicationId: string): Promise<ScanRef> {
    const rows = await this.deps.db.execute<Row<ScanRefRow>>(sql`
      SELECT id, application_id, created_at, commit_sha, build_number
      FROM scan WHERE id = ${scanId}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Scan");
    if (row.application_id !== applicationId) {
      // Comparing builds of two different applications is not a diff, it is a
      // coincidence. Rejecting keeps the result interpretable.
      throw new BadRequestError("Both scans must belong to the same application.");
    }
    return toScanRef(row);
  }

  private async requireLatestScan(applicationId: string): Promise<ScanRef> {
    const rows = await this.deps.db.execute<Row<ScanRefRow>>(sql`
      SELECT s.id, s.application_id, s.created_at, s.commit_sha, s.build_number
      FROM application a JOIN scan s ON s.id = a.latest_scan_id
      WHERE a.id = ${applicationId}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new BadRequestError("This application has no scans yet, so there is nothing to compare.");
    return toScanRef(row);
  }

  private async requirePreviousScan(applicationId: string, to: ScanRef): Promise<ScanRef> {
    const rows = await this.deps.db.execute<Row<ScanRefRow>>(sql`
      SELECT id, application_id, created_at, commit_sha, build_number
      FROM scan
      WHERE application_id = ${applicationId}::uuid
        AND (created_at, id) < (${to.createdAt.toISOString()}::timestamptz, ${to.id}::uuid)
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `);
    const row = rowsOf(rows)[0];
    if (!row) {
      throw new BadRequestError(
        "This is the first scan for this application, so there is no earlier build to compare it with.",
      );
    }
    return toScanRef(row);
  }
}

// ---------------------------------------------------------------------------

/**
 * Fold matching add/remove pairs into version changes.
 *
 * Matched on lowercased name + ecosystem, and only when exactly one entry
 * appears on each side. A package with two versions added and one removed is
 * genuinely ambiguous — which of the two is "the upgrade"? — so those stay in
 * the raw added and removed lists rather than being paired arbitrarily.
 */
export function pairVersionChanges(
  added: ComponentRef[],
  removed: ComponentRef[],
): { added: ComponentRef[]; removed: ComponentRef[]; changed: ScanDiff["changed"] } {
  const key = (c: ComponentRef) => `${c.ecosystem} ${c.name.toLowerCase()}`;

  const addedByKey = new Map<string, ComponentRef[]>();
  for (const c of added) {
    const list = addedByKey.get(key(c));
    if (list) list.push(c);
    else addedByKey.set(key(c), [c]);
  }

  const removedByKey = new Map<string, ComponentRef[]>();
  for (const c of removed) {
    const list = removedByKey.get(key(c));
    if (list) list.push(c);
    else removedByKey.set(key(c), [c]);
  }

  const changed: ScanDiff["changed"] = [];
  const pairedKeys = new Set<string>();

  for (const [k, addedEntries] of addedByKey) {
    const removedEntries = removedByKey.get(k);
    if (!removedEntries) continue;
    if (addedEntries.length !== 1 || removedEntries.length !== 1) continue;

    const to = addedEntries[0]!;
    const from = removedEntries[0]!;
    changed.push({
      name: to.name,
      ecosystem: to.ecosystem,
      fromVersion: from.version,
      toVersion: to.version,
      fromComponentId: from.id,
      toComponentId: to.id,
    });
    pairedKeys.add(k);
  }

  changed.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));

  return {
    added: added.filter((c) => !pairedKeys.has(key(c))),
    removed: removed.filter((c) => !pairedKeys.has(key(c))),
    changed,
  };
}

interface DiffRow {
  from_id: number | string | null;
  to_id: number | string | null;
  id: number | string;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
}

interface RemovedRow {
  id: number | string;
  name: string;
  version: string | null;
  ecosystem: string;
  purl: string | null;
  last_seen_scan_id: string;
  last_seen_at: Date | string;
  last_seen_build_number: string | null;
  total?: number | string;
}

interface LastSeenRow {
  component_id: number | string;
  last_seen_scan_id: string;
  last_seen_at: Date | string;
  last_seen_build_number: string | null;
}

interface ScanRefRow {
  id: string;
  application_id: string;
  created_at: Date | string;
  commit_sha: string | null;
  build_number: string | null;
}

interface ScanRef {
  id: string;
  createdAt: Date;
  commitSha: string | null;
  buildNumber: string | null;
}

function toScanRef(row: ScanRefRow): ScanRef {
  return {
    id: row.id,
    createdAt: row.created_at instanceof Date ? row.created_at : new Date(row.created_at),
    commitSha: row.commit_sha,
    buildNumber: row.build_number,
  };
}

function summarise(ref: ScanRef): ScanDiff["fromScan"] {
  return {
    id: ref.id,
    createdAt: ref.createdAt.toISOString(),
    commitSha: ref.commitSha,
    buildNumber: ref.buildNumber,
  };
}

function toComponentRef(row: DiffRow): ComponentRef {
  return {
    id: String(row.id),
    name: row.name,
    version: row.version,
    ecosystem: row.ecosystem,
    purl: row.purl,
  };
}

function toRemovedComponent(row: RemovedRow): RemovedComponent {
  return {
    id: String(row.id),
    name: row.name,
    version: row.version,
    ecosystem: row.ecosystem,
    purl: row.purl,
    lastSeenScanId: row.last_seen_scan_id,
    lastSeenAt: toIso(row.last_seen_at)!,
    lastSeenBuildNumber: row.last_seen_build_number,
  };
}
