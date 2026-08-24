import { sql } from "drizzle-orm";
import type { MaliciousMatchMode } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { MaliciousVersionRange } from "../../db/schema.js";
import type { Logger } from "../ingestion/ingestion.service.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { normalizePackageName, reportCoversVersion, type MatchableReport } from "./matching.js";

/**
 * Matching the estate's packages against the malicious-package feed.
 *
 * The counterpart to the vulnerability sweep, and deliberately much cheaper. There is no
 * subprocess, no multi-gigabyte database and no external binary: a match is a name lookup
 * followed by a version test, so this can run every few minutes where Grype runs every few
 * hours. That difference is why malicious detection can be useful at all -- a malicious
 * release is usually pulled from its registry within a day of discovery, so a check that
 * waited for the next nightly scan would frequently be looking after the fact.
 *
 * ## The work queue is derived, not stored
 *
 * The same pattern the vulnerability sweep uses, for the same reason. The set of components
 * needing a match is
 *
 *     mal_scanned_at IS NULL OR mal_feed_built_at IS NULL OR mal_feed_built_at < <snapshot>
 *
 * which covers a newly ingested package, the first run after the feature is switched on, a
 * newly published feed, and a sweep that was killed halfway -- with no job table to fall out
 * of sync, and no recovery logic for a worker that restarts mid-run.
 */

/**
 * Components examined per round trip.
 *
 * Each batch turns into one lookup keyed on (ecosystem, normalized_name), so the batch size
 * is the width of that lookup's IN list. Five hundred keeps the query plan sane while making
 * a first sweep over a large estate a few hundred queries rather than a few hundred thousand.
 */
const BATCH = 500;

/**
 * Key for grouping components and reports onto the same lookup.
 *
 * Length-prefixed rather than delimited, so no name can straddle the boundary: ecosystem
 * `npm` with name `a b` and ecosystem `npm a` with name `b` must not collide.
 */
function groupKey(ecosystem: string, normalizedName: string): string {
  return `${ecosystem.length}:${ecosystem}:${normalizedName}`;
}

interface ComponentRow {
  id: number;
  name: string;
  version: string | null;
  ecosystem: string;
}

interface ReportRow extends MatchableReport {
  ecosystem: string;
  normalized_name: string;
}

export interface SweepResult {
  componentsExamined: number;
  matchesAdded: number;
  matchesRemoved: number;
}

export class MaliciousMatchService {
  private running = false;

  constructor(private readonly deps: { db: Database; logger: Logger }) {}

  get isRunning(): boolean {
    return this.running;
  }

  /**
   * How much of the component set has been matched against a given snapshot.
   *
   * Null-safe by construction: the caller passes the snapshot watermark, and when there is no
   * snapshot there is nothing to report coverage against, so it does not call this at all.
   */
  async coverage(feedBuiltAt: Date): Promise<{ matched: number; pending: number }> {
    const rows = await this.deps.db.execute<Row<{ matched: number; pending: number }>>(sql`
      SELECT
        count(*) FILTER (WHERE NOT (${this.pendingPredicate(feedBuiltAt)}))::int AS matched,
        count(*) FILTER (WHERE ${this.pendingPredicate(feedBuiltAt)})::int AS pending
      FROM component
    `);
    const row = rowsOf(rows)[0];
    return { matched: Number(row?.matched ?? 0), pending: Number(row?.pending ?? 0) };
  }

  private pendingPredicate(feedBuiltAt: Date) {
    return sql`(
      mal_scanned_at IS NULL
      OR mal_feed_built_at IS NULL
      OR mal_feed_built_at < ${feedBuiltAt.toISOString()}::timestamptz
    )`;
  }

  /**
   * Bring every component up to date against the installed snapshot.
   *
   * Returns counts rather than the findings themselves; alerting reads what changed from the
   * database afterwards, so a sweep interrupted between matching and mailing still results in
   * the alert going out on the next pass rather than being lost with the process.
   */
  async sweep(feedBuiltAt: Date): Promise<SweepResult> {
    if (this.running) {
      return { componentsExamined: 0, matchesAdded: 0, matchesRemoved: 0 };
    }
    this.running = true;

    const result: SweepResult = { componentsExamined: 0, matchesAdded: 0, matchesRemoved: 0 };

    try {
      for (;;) {
        const batch = await this.nextBatch(feedBuiltAt);
        if (batch.length === 0) break;

        const outcome = await this.matchBatch(batch);
        result.componentsExamined += batch.length;
        result.matchesAdded += outcome.added;
        result.matchesRemoved += outcome.removed;

        await this.markScanned(
          batch.map((c) => c.id),
          feedBuiltAt,
        );
      }
    } catch (err) {
      // Swallowed for the same reason the vulnerability sweep swallows its own: this runs on
      // a timer with nothing to catch it, and a failure here must not surface anywhere else
      // in the platform. The watermark is only advanced for batches that completed, so the
      // next run resumes precisely where this one stopped.
      this.deps.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "malicious package sweep failed",
      );
    } finally {
      this.running = false;
    }

    return result;
  }

  private async nextBatch(feedBuiltAt: Date): Promise<ComponentRow[]> {
    const rows = await this.deps.db.execute<Row<ComponentRow>>(sql`
      SELECT id, name, version, ecosystem
      FROM component
      WHERE ${this.pendingPredicate(feedBuiltAt)}
      ORDER BY id
      LIMIT ${BATCH}
    `);
    return rowsOf(rows).map((r) => ({
      id: Number(r.id),
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
    }));
  }

  /**
   * Look up one batch of components and reconcile their findings.
   *
   * Reconcile rather than insert, because a re-match can legitimately REMOVE a finding: a
   * report gets withdrawn upstream, or its shape is corrected from "every version" to three
   * specific ones. Leaving the stale row would mean a retracted accusation stayed on screen
   * forever, which the platform has no way to explain and no way for a user to clear.
   */
  private async matchBatch(batch: ComponentRow[]): Promise<{ added: number; removed: number }> {
    /*
     * Grouped by the pair the lookup keys on, carrying that pair alongside the components
     * rather than encoding it into the map key and splitting it back out.
     *
     * A delimiter would have to be a character no package name can contain, and the only
     * honest candidate is a NUL -- which cannot be written into a TypeScript source file
     * without making it binary to git and invisible to grep. Holding the fields is both
     * safer and readable, and it is the same reasoning that makes computeIdentityHash
     * length-prefix its inputs instead of joining them.
     */
    const keyed = new Map<
      string,
      { ecosystem: string; normalizedName: string; components: ComponentRow[] }
    >();
    for (const component of batch) {
      const normalizedName = normalizePackageName(component.ecosystem, component.name);
      const key = groupKey(component.ecosystem, normalizedName);
      const bucket = keyed.get(key);
      if (bucket) bucket.components.push(component);
      else {
        keyed.set(key, {
          ecosystem: component.ecosystem,
          normalizedName,
          components: [component],
        });
      }
    }

    const pairs = [...keyed.values()].map(
      (group) => sql`(${group.ecosystem}, ${group.normalizedName})`,
    );

    const reportRows = await this.deps.db.execute<Row<ReportRow & { affected_versions: string[] }>>(sql`
      SELECT id, ecosystem, normalized_name, match_mode, affected_versions, version_ranges
      FROM malicious_package
      WHERE withdrawn_at IS NULL
        AND (ecosystem, normalized_name) IN (${sql.join(pairs, sql`, `)})
    `);

    const byKey = new Map<string, MatchableReport[]>();
    for (const row of rowsOf(reportRows)) {
      const key = groupKey(row.ecosystem, row.normalized_name);
      const report: MatchableReport = {
        id: row.id,
        matchMode: row.match_mode as MaliciousMatchMode,
        affectedVersions: row.affected_versions ?? [],
        versionRanges: (row.version_ranges as MaliciousVersionRange[] | null) ?? null,
      };
      const bucket = byKey.get(key);
      if (bucket) bucket.push(report);
      else byKey.set(key, [report]);
    }

    const matches: Array<{ componentId: number; reportId: string; mode: MaliciousMatchMode }> = [];
    for (const [key, group] of keyed) {
      const reports = byKey.get(key);
      if (!reports) continue;
      for (const component of group.components) {
        for (const report of reports) {
          if (reportCoversVersion(report, component.version)) {
            matches.push({ componentId: component.id, reportId: report.id, mode: report.matchMode });
          }
        }
      }
    }

    const removed = await this.pruneStale(batch, matches);
    const added = await this.insertMatches(matches);
    return { added, removed };
  }

  /**
   * Drops findings that no longer hold for the components just re-examined.
   *
   * Arrays go through `sql.param` here for the same reason they do in the feed service: a
   * bare array interpolates as a SQL value list rather than an array literal, so an empty one
   * produces `()` and fails outright while a populated one silently becomes a row constructor.
   */
  private async pruneStale(
    batch: ComponentRow[],
    matches: Array<{ componentId: number; reportId: string }>,
  ): Promise<number> {
    const keep = new Map<number, string[]>();
    for (const match of matches) {
      const bucket = keep.get(match.componentId);
      if (bucket) bucket.push(match.reportId);
      else keep.set(match.componentId, [match.reportId]);
    }

    const ids = batch.map((c) => c.id);
    const survivors = [...keep.entries()].map(
      ([componentId, reportIds]) => sql`(${componentId}::bigint, ${sql.param(reportIds)}::text[])`,
    );

    // No survivors anywhere in the batch: every existing finding for these components is
    // stale, so the correlated form below is unnecessary and would build an empty VALUES list.
    if (survivors.length === 0) {
      const gone = await this.deps.db.execute<Row<{ component_id: number }>>(sql`
        DELETE FROM component_malicious
        WHERE component_id = ANY(${sql.param(ids)}::bigint[])
        RETURNING component_id
      `);
      return rowsOf(gone).length;
    }

    const gone = await this.deps.db.execute<Row<{ component_id: number }>>(sql`
      WITH survivor(component_id, report_ids) AS (
        VALUES ${sql.join(survivors, sql`, `)}
      )
      DELETE FROM component_malicious cm
      WHERE cm.component_id = ANY(${sql.param(ids)}::bigint[])
        AND NOT EXISTS (
          SELECT 1 FROM survivor s
          WHERE s.component_id = cm.component_id
            AND cm.malicious_package_id = ANY(s.report_ids)
        )
      RETURNING cm.component_id
    `);
    return rowsOf(gone).length;
  }

  /**
   * Insert the current matches.
   *
   * `ON CONFLICT DO NOTHING` rather than upsert, so `matched_at` keeps naming the first time
   * the platform saw this finding. That timestamp is the closest thing available to "how long
   * have we been shipping this", and rewriting it on every sweep would erase it.
   */
  private async insertMatches(
    matches: Array<{ componentId: number; reportId: string; mode: MaliciousMatchMode }>,
  ): Promise<number> {
    if (matches.length === 0) return 0;

    const values = matches.map(
      (m) => sql`(${m.componentId}::bigint, ${m.reportId}, ${m.mode})`,
    );
    const inserted = await this.deps.db.execute<Row<{ component_id: number }>>(sql`
      INSERT INTO component_malicious (component_id, malicious_package_id, match_mode)
      VALUES ${sql.join(values, sql`, `)}
      ON CONFLICT (component_id, malicious_package_id) DO NOTHING
      RETURNING component_id
    `);
    return rowsOf(inserted).length;
  }

  private async markScanned(ids: number[], feedBuiltAt: Date): Promise<void> {
    await this.deps.db.execute(sql`
      UPDATE component
      SET mal_scanned_at = now(), mal_feed_built_at = ${feedBuiltAt.toISOString()}::timestamptz
      WHERE id = ANY(${sql.param(ids)}::bigint[])
    `);
  }
}
