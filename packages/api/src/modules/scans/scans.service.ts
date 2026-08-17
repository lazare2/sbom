import { sql, type SQL } from "drizzle-orm";
import type { ListScansQuery, Paginated, ScanSource, ScanSummary } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { NotFoundError } from "../../lib/errors.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import type { BlobStore } from "../../services/blob-store/index.js";
import { toScanPlatform, type PlatformRow } from "../ingestion/platform-row.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";

interface ScanQueryRow extends PlatformRow {
  id: string;
  application_id: string;
  application_name?: string;
  created_at: Date | string;
  commit_sha: string | null;
  build_number: string | null;
  pipeline_id: string | null;
  image_ref: string | null;
  branch: string | null;
  component_count: number | string;
  tool_name: string | null;
  tool_version: string | null;
  sbom_size_bytes: number | string;
  sbom_blob_key?: string;
  is_latest: boolean;
  source: ScanSource;
  uploaded_by_email: string | null;
  total?: number | string;
}

export interface ScanDetail extends ScanSummary {
  applicationName: string;
  applicationStatus: string;
  specVersion: string | null;
  serialNumber: string | null;
  ingestTokenName: string | null;
  sbomSha256: string;
  /** Free-text reason recorded with a manual upload. Null for CI scans. */
  uploadNote: string | null;
  /** The scan immediately before this one for the same application, if any. */
  previousScanId: string | null;
  nextScanId: string | null;
}

export class ScansService {
  constructor(
    private readonly deps: { db: Database; blobStore: BlobStore },
  ) {}

  /** Scan history for one application, newest first by default. */
  async listForApplication(
    applicationId: string,
    query: ListScansQuery,
  ): Promise<Paginated<ScanSummary>> {
    const { db } = this.deps;

    const exists = await db.execute<Row<{ id: string }>>(sql`
      SELECT id FROM application WHERE id = ${applicationId}::uuid
    `);
    if (rowsOf(exists).length === 0) throw new NotFoundError("Application");

    const conditions: SQL[] = [sql`s.application_id = ${applicationId}::uuid`];
    if (query.branch) {
      conditions.push(sql`s.branch = ${query.branch}`);
    }
    const where = sql.join([sql`WHERE `, sql.join(conditions, sql` AND `)]);
    const direction = query.sortDir === "desc" ? sql.raw("DESC") : sql.raw("ASC");

    const rows = await db.execute<Row<ScanQueryRow>>(sql`
      SELECT
        s.id, s.application_id, s.created_at, s.commit_sha, s.build_number,
        s.pipeline_id, s.image_ref, s.branch, s.component_count,
        s.tool_name, s.tool_version, s.sbom_size_bytes,
        s.os_name, s.os_version, s.os_pretty, s.runtimes,
        s.source, s.uploaded_by_email,
        (s.id = a.latest_scan_id) AS is_latest,
        count(*) OVER () AS total
      FROM scan s
      JOIN application a ON a.id = s.application_id
      ${where}
      ORDER BY s.created_at ${direction}, s.id ${direction}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    return paginate(rowsOf(rows).map(toScanSummary), totalFromRows(rowsOf(rows)), query);
  }

  /**
   * One scan, with the ids of its neighbours in the same application's history.
   *
   * The neighbour ids let the UI page through builds and seed the diff view's
   * "compare with the previous build" default without a second round trip.
   */
  async getById(scanId: string): Promise<ScanDetail> {
    const rows = await this.deps.db.execute<
      Row<ScanQueryRow & {
        application_name: string;
        application_status: string;
        spec_version: string | null;
        serial_number: string | null;
        ingest_token_name: string | null;
        sbom_sha256: string;
        upload_note: string | null;
        previous_scan_id: string | null;
        next_scan_id: string | null;
      }>
    >(sql`
      SELECT
        s.id, s.application_id, s.created_at, s.commit_sha, s.build_number,
        s.pipeline_id, s.image_ref, s.branch, s.component_count,
        s.tool_name, s.tool_version, s.sbom_size_bytes,
        s.os_name, s.os_version, s.os_pretty, s.runtimes, s.sbom_sha256,
        s.spec_version, s.serial_number, s.ingest_token_name,
        s.source, s.uploaded_by_email, s.upload_note,
        a.name AS application_name,
        a.status AS application_status,
        (s.id = a.latest_scan_id) AS is_latest,
        (SELECT p.id FROM scan p
          WHERE p.application_id = s.application_id
            AND (p.created_at, p.id) < (s.created_at, s.id)
          ORDER BY p.created_at DESC, p.id DESC LIMIT 1) AS previous_scan_id,
        (SELECT n.id FROM scan n
          WHERE n.application_id = s.application_id
            AND (n.created_at, n.id) > (s.created_at, s.id)
          ORDER BY n.created_at ASC, n.id ASC LIMIT 1) AS next_scan_id
      FROM scan s
      JOIN application a ON a.id = s.application_id
      WHERE s.id = ${scanId}::uuid
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Scan");

    return {
      ...toScanSummary(row),
      applicationName: row.application_name,
      applicationStatus: row.application_status,
      specVersion: row.spec_version,
      serialNumber: row.serial_number,
      ingestTokenName: row.ingest_token_name,
      sbomSha256: row.sbom_sha256,
      uploadNote: row.upload_note,
      previousScanId: row.previous_scan_id,
      nextScanId: row.next_scan_id,
    };
  }

  /**
   * Fetches the original CycloneDX document for a scan.
   *
   * Serving the stored bytes rather than re-serialising the parsed rows is the
   * point of keeping the raw blob at all: it is the auditable artifact, byte-for-
   * byte what the CI pipeline uploaded.
   */
  async getRawSbom(scanId: string): Promise<{ body: Buffer; filename: string }> {
    const rows = await this.deps.db.execute<Row<{
      sbom_blob_key: string;
      build_number: string | null;
      created_at: Date | string;
      application_name: string;
    }>>(sql`
      SELECT s.sbom_blob_key, s.build_number, s.created_at, a.name AS application_name
      FROM scan s JOIN application a ON a.id = s.application_id
      WHERE s.id = ${scanId}::uuid
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("Scan");

    // Throws NotFoundError if the blob is gone — e.g. trimmed by a raw-SBOM
    // retention sweep while the scan row itself was retained.
    const body = await this.deps.blobStore.get(row.sbom_blob_key);

    const stamp = toIso(row.created_at)!.slice(0, 10);
    const build = row.build_number ? `-build-${row.build_number}` : "";
    const safeName = row.application_name.replace(/[^A-Za-z0-9._-]+/g, "_");
    return { body, filename: `${safeName}${build}-${stamp}.cdx.json` };
  }

  /** Recent scan activity across all applications, for the dashboard. */
  async listRecent(limit: number): Promise<Array<ScanSummary & { applicationName: string }>> {
    const rows = await this.deps.db.execute<Row<ScanQueryRow>>(sql`
      SELECT
        s.id, s.application_id, s.created_at, s.commit_sha, s.build_number,
        s.pipeline_id, s.image_ref, s.branch, s.component_count,
        s.tool_name, s.tool_version, s.sbom_size_bytes,
        s.os_name, s.os_version, s.os_pretty, s.runtimes,
        s.source, s.uploaded_by_email,
        a.name AS application_name,
        (s.id = a.latest_scan_id) AS is_latest
      FROM scan s
      JOIN application a ON a.id = s.application_id
      ORDER BY s.created_at DESC
      LIMIT ${limit}
    `);
    return rowsOf(rows).map((r) => ({
      ...toScanSummary(r),
      // Always selected by this query, unlike the per-application variants where
      // the app name is already known from the page context.
      applicationName: r.application_name ?? "",
    }));
  }
}

function toScanSummary(row: ScanQueryRow): ScanSummary {
  return {
    id: row.id,
    applicationId: row.application_id,
    createdAt: toIso(row.created_at)!,
    commitSha: row.commit_sha,
    buildNumber: row.build_number,
    pipelineId: row.pipeline_id,
    imageRef: row.image_ref,
    branch: row.branch,
    componentCount: Number(row.component_count),
    toolName: row.tool_name,
    toolVersion: row.tool_version,
    sbomSizeBytes: Number(row.sbom_size_bytes),
    isLatest: row.is_latest === true,
    platform: toScanPlatform(row),
    // Defaulted rather than asserted: `listRecent` and the per-application list
    // both select these, but a future query that forgets to should degrade to
    // "looks like CI" instead of rendering `undefined` as a badge.
    source: row.source ?? "ci",
    uploadedByEmail: row.uploaded_by_email ?? null,
  };
}
