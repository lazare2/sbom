import { sql } from "drizzle-orm";
import type { DeleteScanResponse } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import type { BlobStore } from "../../services/blob-store/index.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { Actor, AuditService } from "../admin/audit.service.js";

/**
 * Removing a scan from an application's history.
 *
 * Split from `ScansService` for the reason every module here splits its two: reads
 * are open to any authenticated user, writes are admin-only and audited. Keeping
 * them together would make recording the audit entry a per-method decision, and
 * the entry that gets forgotten is always the one someone later needs.
 *
 * ## Why deletion is admin-only when upload is not
 *
 * Manual upload is open to every signed-in user because it is append-only: a wrong
 * upload is corrected by uploading the right one, and the wrong one stays visible
 * in the history with the uploader's name on it. This is the opposite operation. It
 * destroys a build record that diffs, the removed-packages view and past reports
 * point at, and nothing brings it back. The asymmetry in access follows the
 * asymmetry in consequence.
 *
 * ## What deleting a scan actually does
 *
 * More than removing a row. `scan_component` and `scan_vuln_summary` cascade, so
 * the components that build shipped stop being attributed to it and its findings
 * summary goes with it. If the scan was the application's current state, the build
 * before it is promoted -- which rewrites the application's component list, its
 * findings, and its contribution to every dashboard and analytics figure. The
 * response says which of those happened rather than leaving the caller to guess.
 *
 * Deliberately *not* done here: re-running the vulnerability sweep. Sweeps
 * summarise every scan whose components are fully matched, not only current ones,
 * so a promoted build already carries its own summary. Kicking the scanner would be
 * work with no result to show for it.
 */
export class ScansAdminService {
  constructor(private readonly deps: { db: Database; blobStore: BlobStore; audit: AuditService }) {}

  /**
   * Delete one scan, whatever produced it.
   *
   * CI scans are deletable as well as manual uploads. A pipeline can push a broken
   * SBOM -- a truncated Syft run, a build tagged with the wrong application -- at
   * least as easily as a person can, and restricting this to manual uploads would
   * leave the more common mistake unfixable.
   */
  async remove(scanId: string, actor: Actor): Promise<DeleteScanResponse> {
    const { db, blobStore, audit } = this.deps;

    const found = await db.execute<
      Row<{
        id: string;
        application_id: string;
        application_name: string;
        created_at: Date | string;
        build_number: string | null;
        commit_sha: string | null;
        branch: string | null;
        image_ref: string | null;
        component_count: number | string;
        source: string;
        uploaded_by_email: string | null;
        sbom_sha256: string;
        sbom_blob_key: string;
        is_latest: boolean;
      }>
    >(sql`
      SELECT
        s.id, s.application_id, s.created_at, s.build_number, s.commit_sha,
        s.branch, s.image_ref, s.component_count, s.source, s.uploaded_by_email,
        s.sbom_sha256, s.sbom_blob_key,
        a.name AS application_name,
        (s.id = a.latest_scan_id) AS is_latest
      FROM scan s
      JOIN application a ON a.id = s.application_id
      WHERE s.id = ${scanId}::uuid
    `);

    const scan = rowsOf(found)[0];
    if (!scan) throw new NotFoundError("Scan");

    const outcome = await db.transaction(async (tx) => {
      /*
       * Audited inside the transaction, unlike the manual upload's audit row.
       *
       * Upload can afford to audit afterwards because the scan itself is the durable
       * record and carries its own uploader. Here the record is what is being
       * destroyed, so this row is the only surviving evidence that the build existed
       * -- it has to commit with the delete or not at all. The metadata is
       * correspondingly full: enough to identify the build that was removed, since
       * nothing else will describe it afterwards.
       */
      await audit.record(
        {
          actor,
          action: "scan.delete",
          targetType: "scan",
          targetId: scan.id,
          metadata: {
            applicationId: scan.application_id,
            applicationName: scan.application_name,
            scannedAt: new Date(scan.created_at).toISOString(),
            buildNumber: scan.build_number,
            commitSha: scan.commit_sha,
            branch: scan.branch,
            imageRef: scan.image_ref,
            componentCount: Number(scan.component_count),
            source: scan.source,
            uploadedByEmail: scan.uploaded_by_email,
            sbomSha256: scan.sbom_sha256,
            wasLatest: scan.is_latest === true,
          },
        },
        tx,
      );

      // application.latest_scan_id is ON DELETE SET NULL, so this clears the pointer
      // on its own when the current build is the one going. The recompute below is
      // what puts the previous build back -- without it the application would read
      // as never scanned while its whole history was still there.
      await tx.execute(sql`DELETE FROM scan WHERE id = ${scan.id}::uuid`);

      /*
       * Full recompute rather than a decrement, matching what merge does.
       *
       * scan_count, last_scan_at and latest_scan_id are three denormalised views of
       * the same table and they have to be derived together, or an application ends
       * up with a count that disagrees with its history. Ordering by
       * (created_at, id) is the same tiebreak the history list and the
       * previous/next links use, so the build promoted here is exactly the one the
       * UI showed directly beneath the deleted row.
       */
      const updated = await tx.execute<
        Row<{ latest_scan_id: string | null; scan_count: number | string }>
      >(sql`
        UPDATE application a SET
          scan_count = (SELECT count(*) FROM scan s WHERE s.application_id = a.id),
          last_scan_at = (SELECT max(s.created_at) FROM scan s WHERE s.application_id = a.id),
          latest_scan_id = (
            SELECT s.id FROM scan s WHERE s.application_id = a.id
            ORDER BY s.created_at DESC, s.id DESC LIMIT 1
          ),
          updated_at = now()
        WHERE a.id = ${scan.application_id}::uuid
        RETURNING a.latest_scan_id, a.scan_count
      `);

      /*
       * Whether anything still needs these bytes.
       *
       * Blob keys are content-addressed, so a rebuild of unchanged code produces a
       * byte-identical SBOM under the same key and several scans legitimately share
       * one blob -- including scans of entirely different applications. Deleting it
       * unconditionally would take the raw document away from builds that still
       * exist. Checked inside the transaction so the answer cannot race a concurrent
       * ingest of the same bytes.
       */
      const others = await tx.execute<Row<{ still_referenced: boolean }>>(sql`
        SELECT EXISTS (
          SELECT 1 FROM scan WHERE sbom_blob_key = ${scan.sbom_blob_key}
        ) AS still_referenced
      `);

      const row = rowsOf(updated)[0];
      return {
        currentScanId: row?.latest_scan_id ?? null,
        remainingScanCount: Number(row?.scan_count ?? 0),
        blobOrphaned: rowsOf(others)[0]?.still_referenced !== true,
      };
    });

    /*
     * The blob goes after the commit, and its failure is not the caller's problem.
     *
     * Rolling back a committed deletion because object storage was briefly
     * unreachable would be the worse trade: the scan is already gone from every
     * query, and what is left behind is an unreferenced blob nothing can reach. A
     * 500 here would instead tell an admin the deletion failed when it did not.
     */
    let rawSbomDeleted = false;
    if (outcome.blobOrphaned) {
      try {
        await blobStore.delete(scan.sbom_blob_key);
        rawSbomDeleted = true;
      } catch {
        rawSbomDeleted = false;
      }
    }

    return {
      applicationId: scan.application_id,
      wasLatest: scan.is_latest === true,
      currentScanId: outcome.currentScanId,
      remainingScanCount: outcome.remainingScanCount,
      rawSbomDeleted,
    };
  }
}
