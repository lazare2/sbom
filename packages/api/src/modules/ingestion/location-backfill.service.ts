import { sql } from "drizzle-orm";
import type { Database } from "../../db/client.js";
import type { BlobStore } from "../../services/blob-store/index.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { parseCycloneDx } from "./cyclonedx.js";

/**
 * Recovering component locations from SBOMs ingested before the platform recorded them.
 *
 * The raw CycloneDX document is kept for every scan precisely so the parser can be improved
 * and re-run — the blob store's own comment says so — and this is the first thing to take it
 * up on that. Without a backfill the location feature would work only for builds uploaded
 * after the change, and every older build would render "no path recorded", which is the exact
 * ambiguity the `locations_extracted_at` marker exists to prevent.
 *
 * ## What it will not do
 *
 * It never invents a marker it has not earned. A scan whose blob has been pruned cannot be
 * backfilled at all, so it is counted and reported as `unreadable` and its marker is left
 * NULL. That means such scans are re-attempted on the next run, which is deliberate: the
 * alternative is stamping "we looked" onto a scan nobody ever looked at, and a wrong marker
 * would be permanent while a repeated read is merely wasted work on an admin-triggered job.
 *
 * ## Why it is chunked and resumable
 *
 * An estate can hold tens of thousands of scans and each one means a blob read plus a JSON
 * parse of up to tens of megabytes. Work is committed per scan, so an interrupted run leaves
 * every scan it finished marked and simply resumes at the next NULL marker.
 */

/** Scans processed per call. Bounded so an admin request returns rather than hanging. */
const DEFAULT_BATCH = 200;

export interface LocationBackfillResult {
  /** Scans whose SBOM was re-parsed and whose marker is now set. */
  processed: number;
  /** `scan_component` rows that gained at least one path. */
  rowsUpdated: number;
  /** Scans whose raw SBOM could no longer be read. Marker left NULL, so they are retried. */
  unreadable: number;
  /** Scans still awaiting a pass after this batch. Zero means the estate is fully backfilled. */
  remaining: number;
}

export class LocationBackfillService {
  private running = false;

  constructor(
    private readonly deps: {
      db: Database;
      blobs: BlobStore;
      logger: { info: (msg: string, meta?: unknown) => void; warn: (msg: string, meta?: unknown) => void };
    },
  ) {}

  get isRunning(): boolean {
    return this.running;
  }

  /** How many scans have never had a location pass. Readable while a run is in progress. */
  async pending(): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ count: number }>>(sql`
      SELECT count(*)::int AS count FROM scan WHERE locations_extracted_at IS NULL
    `);
    return Number(rowsOf(rows)[0]?.count ?? 0);
  }

  async run(limit = DEFAULT_BATCH): Promise<LocationBackfillResult> {
    if (this.running) {
      // Concurrent runs would read the same blobs and race on the same rows to no benefit.
      return { processed: 0, rowsUpdated: 0, unreadable: 0, remaining: await this.pending() };
    }
    this.running = true;

    try {
      const candidates = await this.deps.db.execute<Row<{ id: string; sbom_blob_key: string }>>(sql`
        SELECT id, sbom_blob_key
        FROM scan
        WHERE locations_extracted_at IS NULL
        -- Newest first: the current build of each application is what somebody is looking at
        -- today, so a partially-completed backfill is useful immediately rather than only at
        -- the end.
        ORDER BY created_at DESC
        LIMIT ${limit}
      `);

      let processed = 0;
      let rowsUpdated = 0;
      let unreadable = 0;

      for (const candidate of rowsOf(candidates)) {
        try {
          rowsUpdated += await this.backfillScan(candidate.id, candidate.sbom_blob_key);
          processed += 1;
        } catch (err) {
          unreadable += 1;
          this.deps.logger.warn("location backfill could not read a scan", {
            scanId: candidate.id,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      const remaining = await this.pending();
      this.deps.logger.info("location backfill batch complete", {
        processed,
        rowsUpdated,
        unreadable,
        remaining,
      });
      return { processed, rowsUpdated, unreadable, remaining };
    } finally {
      this.running = false;
    }
  }

  /**
   * Re-parse one scan's SBOM and write its locations.
   *
   * The update joins through `component.identity_hash` rather than through anything positional,
   * because the parser's output order has no relationship to the rows already in the table and
   * the identity hash is the only thing that identifies a package across the two.
   *
   * The marker is set inside the same transaction as the row updates, so a crash midway
   * through cannot leave a scan marked as extracted with only half its locations written.
   */
  private async backfillScan(scanId: string, blobKey: string): Promise<number> {
    const raw = await this.deps.blobs.get(blobKey);
    const parsed = parseCycloneDx(raw);

    const located = parsed.components.filter((c) => c.paths !== null && c.paths.length > 0);

    return await this.deps.db.transaction(async (tx) => {
      let updated = 0;

      if (located.length > 0) {
        /*
         * One statement per scan rather than one per component. A scan can carry thousands of
         * located components, and a round trip each would make the backfill slower than
         * re-ingesting from scratch.
         *
         * The payload travels as JSON and is expanded with `jsonb_to_recordset`, not as
         * parallel arrays. Parallel arrays are the usual trick here and they cannot work for
         * this shape: `paths` is itself an array per row, and a Postgres `text[][]` demands
         * that every sub-array have the same length while `unnest` flattens it to a single
         * dimension regardless. JSON carries the ragged nesting exactly, and
         * `jsonb_to_recordset` reconstitutes each `paths` back into a real `text[]`.
         */
        const payload = located.map((c) => ({
          identity_hash: c.identityHash,
          paths: c.paths,
          path_count: c.pathCount ?? c.paths?.length ?? 0,
          layer_id: c.layerId,
        }));

        const result = await tx.execute(sql`
          UPDATE scan_component sc
          SET paths = src.paths,
              path_count = src.path_count,
              layer_id = src.layer_id
          FROM jsonb_to_recordset(${JSON.stringify(payload)}::jsonb)
            AS src(identity_hash text, paths text[], path_count int, layer_id text)
          JOIN component c ON c.identity_hash = src.identity_hash
          WHERE sc.scan_id = ${scanId}::uuid AND sc.component_id = c.id
        `);
        updated = result.rowCount ?? 0;
      }

      await tx.execute(sql`
        UPDATE scan SET locations_extracted_at = now() WHERE id = ${scanId}::uuid
      `);

      return updated;
    });
  }
}
