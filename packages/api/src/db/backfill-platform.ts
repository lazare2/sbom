import { sql } from "drizzle-orm";
import { getConfig } from "../config.js";
import { parseCycloneDx } from "../modules/ingestion/cyclonedx.js";
import { platformSummary } from "../modules/ingestion/platform.js";
import { createBlobStore } from "../services/blob-store/index.js";
import { closeDb, getDb } from "./client.js";

/**
 * Fills in the OS and runtime columns for scans ingested before platform
 * detection existed, by re-parsing their stored raw SBOMs.
 *
 * This is the payoff for keeping the original bytes rather than only the parsed
 * rows: a new field extracted from the SBOM can be applied to the entire
 * retained history, not just to builds from today onward. Without the raw blobs
 * every pre-existing scan would read "platform unknown" forever.
 *
 * Idempotent and resumable. Only touches scans where `os_name IS NULL AND
 * runtimes IS NULL`, so re-running after an interruption picks up where it
 * stopped, and a scan whose SBOM genuinely reveals no platform is marked with an
 * empty runtimes array rather than left null — otherwise every run would
 * reconsider the same distroless images forever.
 */

const BATCH_SIZE = 200;

async function main(): Promise<void> {
  const config = getConfig();
  const db = getDb();
  const blobStore = createBlobStore(config);
  await blobStore.verify();

  const pending = await db.execute<Record<string, unknown>>(sql`
    SELECT count(*)::int AS count FROM scan WHERE os_name IS NULL AND runtimes IS NULL
  `);
  const total = Number(
    (Array.isArray(pending) ? pending[0] : pending.rows[0])?.count ?? 0,
  );

  if (total === 0) {
    console.log("[backfill] every scan already has platform data; nothing to do");
    return;
  }

  console.log(`[backfill] ${total} scan(s) need platform data`);

  let processed = 0;
  let detected = 0;
  let empty = 0;
  let missingBlob = 0;
  let unparseable = 0;

  for (;;) {
    const batch = await db.execute<Record<string, unknown>>(sql`
      SELECT id, sbom_blob_key FROM scan
      WHERE os_name IS NULL AND runtimes IS NULL
      ORDER BY created_at ASC
      LIMIT ${BATCH_SIZE}
    `);
    const rows = (Array.isArray(batch) ? batch : batch.rows) as Array<{
      id: string;
      sbom_blob_key: string;
    }>;
    if (rows.length === 0) break;

    for (const row of rows) {
      let raw: Buffer;
      try {
        raw = await blobStore.get(row.sbom_blob_key);
      } catch {
        // The blob is gone — trimmed by a retention sweep, most likely. Mark the
        // scan as processed with an empty platform so the loop terminates
        // instead of selecting this row on every pass forever.
        await markEmpty(row.id);
        missingBlob++;
        processed++;
        continue;
      }

      try {
        const parsed = parseCycloneDx(raw);
        const p = parsed.platform;
        await db.execute(sql`
          UPDATE scan SET
            os_name    = ${p.osName},
            os_version = ${p.osVersion},
            os_pretty  = ${p.osPretty},
            runtimes   = ${JSON.stringify(p.runtimes)}::jsonb
          WHERE id = ${row.id}::uuid
        `);
        if (platformSummary(p)) detected++;
        else empty++;
      } catch {
        // A stored blob that no longer parses is not something this script can
        // fix, and it must not stop the rest of the backfill.
        await markEmpty(row.id);
        unparseable++;
      }
      processed++;
    }

    console.log(`[backfill] ${processed}/${total}`);
  }

  console.log("");
  console.log(`[backfill] platform detected : ${detected}`);
  console.log(`[backfill] nothing to detect : ${empty}  (scratch/distroless, or a non-Syft SBOM)`);
  if (missingBlob > 0) console.log(`[backfill] raw SBOM missing  : ${missingBlob}`);
  if (unparseable > 0) console.log(`[backfill] unparseable       : ${unparseable}`);
  console.log("[backfill] done");
}

/** Records "we looked and found nothing", so the row is not reconsidered. */
async function markEmpty(scanId: string): Promise<void> {
  await getDb().execute(sql`
    UPDATE scan SET runtimes = '[]'::jsonb WHERE id = ${scanId}::uuid
  `);
}

main()
  .then(() => closeDb())
  .then(() => process.exit(0))
  .catch(async (err: unknown) => {
    console.error("[backfill] failed:", err);
    await closeDb().catch(() => undefined);
    process.exit(1);
  });
