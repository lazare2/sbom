import { sql } from "drizzle-orm";
import type { Database } from "../../db/client.js";
import type { BlobStore } from "../../services/blob-store/index.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { parseCycloneDx } from "./cyclonedx.js";

/**
 * Recovering derived columns from SBOMs ingested before the platform recorded them.
 *
 * The raw CycloneDX document is kept for every scan precisely so the parser can be improved
 * and re-run -- the blob store's own comment says so -- and this is what takes it up on that.
 * Without a backfill each new derived column would work only for builds uploaded after the
 * change, and every older build would render an absence that looks exactly like a real
 * negative: "no path recorded" where the truth is "nobody looked".
 *
 * ## Two column sets, one pass, two markers
 *
 * It recovers component **locations** and component **dependants** together, because both
 * come out of one parse of one blob and parsing twice would double the cost of the most
 * expensive job in the system.
 *
 * They are marked separately though -- `locations_extracted_at` and
 * `dependencies_extracted_at` -- and that matters. Every scan processed by the earlier,
 * locations-only version of this service already carries a non-null location marker. Had
 * dependants shared that column, all of those scans would have looked finished and would
 * never have been visited again, so the feature would silently have covered only builds
 * ingested after the change. A scan is a candidate while *either* marker is null, and a pass
 * over an already-located scan simply rewrites the same paths, which is harmless.
 *
 * ## What it will not do
 *
 * It never invents a marker it has not earned. A scan whose blob has been pruned cannot be
 * backfilled at all, so it is counted and reported as `unreadable` and both markers are left
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

export interface SbomBackfillResult {
  /** Scans whose SBOM was re-parsed and whose markers are now set. */
  processed: number;
  /** `scan_component` rows that gained at least one path. */
  locationsUpdated: number;
  /**
   * `scan_component` rows that gained at least one dependant.
   *
   * Counted separately from locations rather than summed into one figure, because the two
   * are absent for unrelated reasons and a single total would hide that. An image scan
   * typically produces many locations and almost no dependants -- Syft reads dependency
   * edges from a lockfile, which is not in the image -- and an operator watching one number
   * climb would have no way to tell that half the job found nothing.
   */
  dependantsUpdated: number;
  /** Scans whose raw SBOM could no longer be read. Markers left NULL, so they are retried. */
  unreadable: number;
  /** Scans still awaiting a pass after this batch. Zero means the estate is fully backfilled. */
  remaining: number;
}

export class SbomBackfillService {
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

  /** How many scans still need a pass. Readable while a run is in progress. */
  async pending(): Promise<number> {
    const rows = await this.deps.db.execute<Row<{ count: number }>>(sql`
      SELECT count(*)::int AS count
      FROM scan
      WHERE locations_extracted_at IS NULL OR dependencies_extracted_at IS NULL
    `);
    return Number(rowsOf(rows)[0]?.count ?? 0);
  }

  async run(limit = DEFAULT_BATCH): Promise<SbomBackfillResult> {
    if (this.running) {
      // Concurrent runs would read the same blobs and race on the same rows to no benefit.
      return {
        processed: 0,
        locationsUpdated: 0,
        dependantsUpdated: 0,
        unreadable: 0,
        remaining: await this.pending(),
      };
    }
    this.running = true;

    try {
      const candidates = await this.deps.db.execute<Row<{ id: string; sbom_blob_key: string }>>(sql`
        SELECT id, sbom_blob_key
        FROM scan
        WHERE locations_extracted_at IS NULL OR dependencies_extracted_at IS NULL
        -- Newest first: the current build of each application is what somebody is looking at
        -- today, so a partially-completed backfill is useful immediately rather than only at
        -- the end.
        ORDER BY created_at DESC
        LIMIT ${limit}
      `);

      let processed = 0;
      let locationsUpdated = 0;
      let dependantsUpdated = 0;
      let unreadable = 0;

      for (const candidate of rowsOf(candidates)) {
        try {
          const counts = await this.backfillScan(candidate.id, candidate.sbom_blob_key);
          locationsUpdated += counts.locations;
          dependantsUpdated += counts.dependants;
          processed += 1;
        } catch (err) {
          unreadable += 1;
          this.deps.logger.warn("sbom backfill could not read a scan", {
            scanId: candidate.id,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }

      const remaining = await this.pending();
      this.deps.logger.info("sbom backfill batch complete", {
        processed,
        locationsUpdated,
        dependantsUpdated,
        unreadable,
        remaining,
      });
      return { processed, locationsUpdated, dependantsUpdated, unreadable, remaining };
    } finally {
      this.running = false;
    }
  }

  /**
   * Re-parse one scan's SBOM and write both derived column sets.
   *
   * The updates join through `component.identity_hash` rather than through anything
   * positional, because the parser's output order has no relationship to the rows already in
   * the table and the identity hash is the only thing that identifies a package across the
   * two.
   *
   * Both markers are set inside the same transaction as the row updates, so a crash midway
   * through cannot leave a scan marked as extracted with only half its data written.
   */
  private async backfillScan(
    scanId: string,
    blobKey: string,
  ): Promise<{ locations: number; dependants: number }> {
    const raw = await this.deps.blobs.get(blobKey);
    const parsed = parseCycloneDx(raw);

    const located = parsed.components.filter((c) => c.paths !== null && c.paths.length > 0);
    const depended = parsed.components.filter(
      (c) => c.pulledInBy !== null && c.pulledInBy.length > 0,
    );

    return await this.deps.db.transaction(async (tx) => {
      let locations = 0;
      let dependants = 0;

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
        locations = result.rowCount ?? 0;
      }

      if (depended.length > 0) {
        // A second statement rather than one combined update, because the two sets of
        // components barely overlap: on an image scan the located rows are npm packages and
        // the depended rows are apk packages. A single statement would have to carry both
        // payloads and null out whichever column the row is not in, which is how a rerun
        // erases the half it was not looking at.
        const payload = depended.map((c) => ({
          identity_hash: c.identityHash,
          pulled_in_by: c.pulledInBy,
          pulled_in_by_count: c.pulledInByCount ?? c.pulledInBy?.length ?? 0,
        }));

        const result = await tx.execute(sql`
          UPDATE scan_component sc
          SET pulled_in_by = src.pulled_in_by,
              pulled_in_by_count = src.pulled_in_by_count
          FROM jsonb_to_recordset(${JSON.stringify(payload)}::jsonb)
            AS src(identity_hash text, pulled_in_by text[], pulled_in_by_count int)
          JOIN component c ON c.identity_hash = src.identity_hash
          WHERE sc.scan_id = ${scanId}::uuid AND sc.component_id = c.id
        `);
        dependants = result.rowCount ?? 0;
      }

      await tx.execute(sql`
        UPDATE scan
        SET locations_extracted_at = now(), dependencies_extracted_at = now()
        WHERE id = ${scanId}::uuid
      `);

      return { locations, dependants };
    });
  }
}
