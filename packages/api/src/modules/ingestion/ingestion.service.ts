import { eq, inArray, sql } from "drizzle-orm";
import type {
  DuplicateSbomDetails,
  IngestScanFields,
  IngestScanResponse,
  ManualUploadFields,
  ManualUploadResponse,
  ScanSource,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import {
  application,
  applicationAlias,
  component,
  scan,
  scanComponent,
  type ApplicationRow,
} from "../../db/schema.js";
import { sha256Hex } from "../../lib/crypto.js";
import { ConflictError, NotFoundError } from "../../lib/errors.js";
import { sbomBlobKey, type BlobStore } from "../../services/blob-store/index.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { parseCycloneDx, type ParsedComponent } from "./cyclonedx.js";
import { platformSummary } from "./platform.js";

/**
 * Postgres allows at most 65535 bind parameters per statement. `component` has 6
 * inserted columns and `scan_component` has 4, so these chunk sizes keep both
 * comfortably under the ceiling while still being few enough round trips that a
 * 50k-component image ingests in tens of statements rather than thousands.
 */
const COMPONENT_INSERT_CHUNK = 1000;
const SCAN_COMPONENT_INSERT_CHUNK = 2000;
const COMPONENT_LOOKUP_CHUNK = 5000;

/**
 * Namespace for the per-application advisory lock taken by manual uploads, so the
 * key cannot collide with one taken anywhere else. `0x53424F4D` is "SBOM" in
 * ASCII, and fits int4 — the type both keys of `pg_advisory_xact_lock` take.
 */
const MANUAL_UPLOAD_LOCK_NAMESPACE = 0x53424f4d;

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}

export interface IngestInput {
  fields: IngestScanFields;
  rawSbom: Buffer;
  tokenName: string;
}

/** A signed-in user uploading an SBOM for an application they picked in the UI. */
export interface ManualIngestInput {
  /** From the URL, not from the SBOM: the target is chosen by the person, not the document. */
  applicationId: string;
  fields: ManualUploadFields;
  rawSbom: Buffer;
  uploader: { id: string; email: string };
}

interface ResolvedApplication {
  app: ApplicationRow;
  created: boolean;
  /** The submitted `app_name`, when an alias redirected it elsewhere. */
  redirectedFrom: string | null;
}

/**
 * Which application a scan belongs to, and how that was decided.
 *
 * CI submits a name and the platform resolves it (matching, aliasing, or
 * auto-creating). A manual upload names the application by id, so there is nothing
 * to resolve and nothing to auto-create — the target already exists because the
 * user navigated to it.
 */
type IngestTarget =
  | { kind: "app_name"; appName: string }
  | { kind: "application_id"; applicationId: string };

/** The CI/CD-shaped metadata columns, normalised away from the two form shapes. */
interface ScanMetadata {
  commitSha: string | null;
  buildNumber: string | null;
  pipelineId: string | null;
  imageRef: string | null;
  branch: string | null;
}

interface Provenance {
  source: ScanSource;
  ingestTokenName: string | null;
  uploadedBy: { id: string; email: string } | null;
  note: string | null;
  /**
   * Refuse the write with a 409 when this application already holds a
   * byte-identical SBOM. Off for CI: a pipeline re-scanning an unchanged artifact
   * legitimately produces the same bytes, and rejecting that would break the
   * `curl -f` contract for a non-problem.
   */
  rejectDuplicate: boolean;
}

interface StoredScan {
  scanId: string;
  resolved: ResolvedApplication;
  /** True when this scan became the application's current state. */
  becameLatest: boolean;
  /** An earlier scan of this application with identical bytes, if one existed. */
  duplicateOfScanId: string | null;
}

export interface Logger {
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
}

export class IngestionService {
  constructor(
    private readonly deps: {
      db: Database;
      blobStore: BlobStore;
      logger: Logger;
    },
  ) {}

  /**
   * Ingest one SBOM posted by a CI/CD pipeline.
   *
   * Thin wrapper over `store()`; the interesting behaviour is documented there.
   */
  async ingest(input: IngestInput): Promise<IngestScanResponse> {
    const { fields, rawSbom, tokenName } = input;

    const stored = await this.store({
      rawSbom,
      target: { kind: "app_name", appName: fields.app_name },
      metadata: {
        commitSha: fields.commit_sha ?? null,
        buildNumber: fields.build_number ?? null,
        pipelineId: fields.pipeline_id ?? null,
        imageRef: fields.image_ref ?? null,
        branch: fields.branch ?? null,
      },
      provenance: {
        source: "ci",
        ingestTokenName: tokenName,
        uploadedBy: null,
        note: null,
        rejectDuplicate: false,
      },
      logContext: { appNameSubmitted: fields.app_name, tokenName },
    });

    return stored.response;
  }

  /**
   * Ingest one SBOM uploaded by hand from an application's scan history.
   *
   * Goes through exactly the same `store()` as the CI path, which is the whole
   * requirement: the resulting scan is a normal scan. It is searchable, it appears
   * in diffs and analytics, and it becomes the application's current build. The
   * only differences are at the edges — the application is identified by id rather
   * than resolved from a name, nothing is ever auto-created, and a byte-identical
   * re-upload is refused rather than silently duplicated.
   */
  async ingestManual(input: ManualIngestInput): Promise<ManualUploadResponse> {
    const { applicationId, fields, rawSbom, uploader } = input;

    const stored = await this.store({
      rawSbom,
      target: { kind: "application_id", applicationId },
      metadata: {
        commitSha: fields.commit_sha ?? null,
        buildNumber: fields.build_number ?? null,
        // A manual upload has no pipeline. Left null rather than invented, so
        // "which pipeline produced this" stays an honest question to ask of the row.
        pipelineId: null,
        imageRef: fields.image_ref ?? null,
        branch: fields.branch ?? null,
      },
      provenance: {
        source: "manual",
        ingestTokenName: null,
        uploadedBy: uploader,
        note: fields.note ?? null,
        rejectDuplicate: !fields.allow_duplicate,
      },
      logContext: { uploadedBy: uploader.email, allowDuplicate: fields.allow_duplicate },
    });

    return {
      ...stored.response,
      source: "manual",
      becameLatest: stored.becameLatest,
      duplicateOfScanId: stored.duplicateOfScanId,
    };
  }

  /**
   * Parse, store and link one SBOM. The single path both entry points take.
   *
   * Ordering is deliberate and load-bearing:
   *   1. Parse first — a document that isn't CycloneDX is rejected before we
   *      write anything anywhere.
   *   2. Store the raw blob second, OUTSIDE the transaction. The write is
   *      content-addressed and idempotent, so a retry is free. If the
   *      transaction then fails we leak an unreferenced blob, which the retention
   *      sweep collects. The opposite order would risk a committed `scan` row
   *      pointing at a blob that was never written — an unrecoverable hole in the
   *      audit trail.
   *   3. Do all relational work in one transaction, so a scan is never visible
   *      without its components, and `latest_scan_id` never points at a
   *      half-populated scan.
   */
  private async store(input: {
    rawSbom: Buffer;
    target: IngestTarget;
    metadata: ScanMetadata;
    provenance: Provenance;
    logContext: Record<string, unknown>;
  }): Promise<{ response: IngestScanResponse } & StoredScan> {
    const { db, blobStore, logger } = this.deps;
    const { rawSbom, target, metadata, provenance } = input;

    const parsed = parseCycloneDx(rawSbom);

    const sbomSha256 = sha256Hex(rawSbom);
    const blobKey = sbomBlobKey(sbomSha256);
    const put = await blobStore.put(blobKey, rawSbom);

    const result = await db.transaction(async (tx): Promise<StoredScan> => {
      const resolved = await this.resolveTarget(tx, target);

      /*
       * Serialise manual uploads per application so the duplicate check below is
       * a guarantee rather than a hope: without this, a double-clicked upload
       * button fires two requests that both look for an existing scan, both find
       * none, and both insert.
       *
       * A unique index on (application_id, sbom_sha256) would be the stronger
       * fix, but it is not available: CI re-scanning an unchanged artifact
       * produces the same bytes legitimately, and the ingest endpoint must not
       * start failing builds over it. Locking only on the manual path leaves the
       * CI contract untouched, and manual uploads are rare enough that
       * serialising them costs nothing.
       */
      if (provenance.source === "manual") {
        await tx.execute(sql`
          SELECT pg_advisory_xact_lock(
            ${MANUAL_UPLOAD_LOCK_NAMESPACE},
            hashtext(${resolved.app.id})
          )
        `);
      }

      // Looked up whenever a duplicate is *possible*, not only when it is
      // refused: a forced duplicate still reports which scan it repeats, so the
      // person who forced it can see what they now have two of.
      const duplicate =
        provenance.source === "manual"
          ? await this.findDuplicate(tx, resolved.app.id, sbomSha256)
          : null;

      if (duplicate && provenance.rejectDuplicate) {
        throw new ConflictError(
          "This application has already received this exact SBOM. " +
            "Re-upload it only if you intend to record a second identical build.",
          duplicate,
        );
      }

      const [inserted] = await tx
        .insert(scan)
        .values({
          applicationId: resolved.app.id,
          commitSha: metadata.commitSha,
          buildNumber: metadata.buildNumber,
          pipelineId: metadata.pipelineId,
          // Fall back to the image the SBOM says it describes when the submitter
          // did not pass one explicitly — Syft records it in metadata.component.
          imageRef: metadata.imageRef ?? parsed.subjectName ?? null,
          branch: metadata.branch,
          ingestTokenName: provenance.ingestTokenName,
          source: provenance.source,
          uploadedByUserId: provenance.uploadedBy?.id ?? null,
          uploadedByEmail: provenance.uploadedBy?.email ?? null,
          uploadNote: provenance.note,
          sbomBlobKey: blobKey,
          sbomSizeBytes: rawSbom.length,
          sbomSha256,
          specVersion: parsed.specVersion,
          serialNumber: parsed.serialNumber,
          toolName: parsed.toolName,
          toolVersion: parsed.toolVersion,
          componentCount: parsed.components.length,
          // Observed OS and runtimes. Denormalised onto the scan so every list
          // and detail view can show "what this runs on" without a join.
          osName: parsed.platform.osName,
          osVersion: parsed.platform.osVersion,
          osPretty: parsed.platform.osPretty,
          runtimes: parsed.platform.runtimes,
        })
        .returning();

      if (!inserted) throw new Error("failed to insert scan row");

      await this.linkComponents(tx, {
        scanId: inserted.id,
        applicationId: resolved.app.id,
        createdAt: inserted.createdAt,
        components: parsed.components,
      });

      const becameLatest = await this.updateApplicationPointer(tx, {
        applicationId: resolved.app.id,
        scanId: inserted.id,
        scanCreatedAt: inserted.createdAt,
      });

      return {
        scanId: inserted.id,
        resolved,
        becameLatest,
        duplicateOfScanId: duplicate?.existingScanId ?? null,
      };
    });

    logger.info(
      {
        ...input.logContext,
        scanId: result.scanId,
        source: provenance.source,
        applicationId: result.resolved.app.id,
        applicationName: result.resolved.app.name,
        applicationCreated: result.resolved.created,
        redirectedFrom: result.resolved.redirectedFrom,
        becameLatest: result.becameLatest,
        duplicateOfScanId: result.duplicateOfScanId,
        components: parsed.components.length,
        skipped: parsed.skipped.length,
        duplicatesCollapsed: parsed.duplicatesCollapsed,
        platform: platformSummary(parsed.platform),
        sbomBytes: rawSbom.length,
        blobDeduplicated: put.deduplicated,
      },
      "scan ingested",
    );

    return {
      ...result,
      response: {
        scanId: result.scanId,
        applicationId: result.resolved.app.id,
        applicationName: result.resolved.app.name,
        applicationStatus: result.resolved.app.status,
        applicationCreated: result.resolved.created,
        redirectedFrom: result.resolved.redirectedFrom,
        componentCount: parsed.components.length,
        skippedComponents: parsed.skipped.length,
      },
    };
  }

  /**
   * An earlier scan of this application carrying byte-identical SBOM content.
   *
   * Scoped to the one application on purpose. The same SBOM appearing under two
   * applications is normal — a shared base image, or a monorepo publishing the
   * same artifact twice — and is not something to warn about. The blob store
   * already deduplicates the payload itself, so this is about not recording the
   * same build twice, not about storage.
   */
  private async findDuplicate(
    tx: Database,
    applicationId: string,
    sbomSha256: string,
  ): Promise<DuplicateSbomDetails | null> {
    const result = await tx.execute<
      Row<{
        id: string;
        created_at: Date | string;
        build_number: string | null;
        is_latest: boolean;
      }>
    >(sql`
      SELECT s.id, s.created_at, s.build_number, (s.id = a.latest_scan_id) AS is_latest
      FROM scan s
      JOIN application a ON a.id = s.application_id
      WHERE s.application_id = ${applicationId}::uuid
        AND s.sbom_sha256 = ${sbomSha256}
      ORDER BY s.created_at DESC
      LIMIT 1
    `);

    const row = rowsOf(result)[0];
    if (!row) return null;

    return {
      existingScanId: row.id,
      existingScanCreatedAt: new Date(row.created_at).toISOString(),
      existingBuildNumber: row.build_number,
      existingIsLatest: row.is_latest === true,
    };
  }

  /**
   * Resolve the target application.
   *
   * The two kinds are genuinely different operations, not two spellings of one:
   * a name may match nothing and be auto-created, whereas an id either exists or
   * the request is a 404. A manual upload must never auto-create an application —
   * the user reached the upload form by navigating to an application that already
   * exists, so an id that resolves to nothing means the record was deleted
   * underneath them, and inventing a replacement would be the wrong answer.
   */
  private async resolveTarget(tx: Database, target: IngestTarget): Promise<ResolvedApplication> {
    if (target.kind === "app_name") {
      return this.resolveApplication(tx, target.appName);
    }

    const [row] = await tx
      .select()
      .from(application)
      .where(eq(application.id, target.applicationId))
      .limit(1);

    if (!row) throw new NotFoundError("Application");
    return { app: row, created: false, redirectedFrom: null };
  }

  /**
   * Map the submitted `app_name` onto an application, in this order:
   *   1. Exact (case-insensitive) name match.
   *   2. A "merge always" alias, which redirects the scan to the merge target.
   *   3. Auto-create as `pending_confirmation`.
   *
   * Step 3 is why the ingest endpoint never rejects an unknown app: losing a
   * build's SBOM because nobody pre-registered the repo would be a worse
   * outcome than an admin having a queue of apps to confirm.
   */
  private async resolveApplication(
    tx: Database,
    appName: string,
  ): Promise<ResolvedApplication> {
    const byName = await this.findByName(tx, appName);
    if (byName) return { app: byName, created: false, redirectedFrom: null };

    const [alias] = await tx
      .select({ applicationId: applicationAlias.applicationId })
      .from(applicationAlias)
      .where(sql`lower(${applicationAlias.aliasName}) = lower(${appName})`)
      .limit(1);

    if (alias) {
      const [target] = await tx
        .select()
        .from(application)
        .where(eq(application.id, alias.applicationId))
        .limit(1);
      if (target) {
        return { app: target, created: false, redirectedFrom: appName };
      }
      // Alias pointing at a deleted application. The FK is ON DELETE CASCADE so
      // this should be unreachable, but falling through to auto-create is the
      // safe behaviour if it ever happens.
      this.deps.logger.warn({ appName, aliasTarget: alias.applicationId }, "alias target missing");
    }

    /*
     * Two builds of a brand-new application can arrive concurrently and race on
     * the unique lower(name) index. The loser re-reads the winner's row rather
     * than failing the upload.
     *
     * `ON CONFLICT DO NOTHING` rather than catching the unique violation, which is
     * what this used to do and which did not work: Postgres aborts the entire
     * transaction on a failed statement, so the recovering `findByName` below
     * errored with 25P02 and the loser got a 500. Verified with a probe posting two
     * concurrent scans for an unseen app_name — one 201, one 500. DO NOTHING never
     * raises, so the transaction stays usable; under READ COMMITTED it blocks until
     * the competing insert resolves, then returns zero rows if that insert
     * committed, or inserts normally if it rolled back.
     *
     * No conflict target: the only unique constraint here besides the primary key
     * is an expression index on lower(name), which cannot be named as a target
     * without repeating the expression.
     */
    const [created] = await tx
      .insert(application)
      .values({ name: appName, status: "pending_confirmation" })
      .onConflictDoNothing()
      .returning();
    if (created) return { app: created, created: true, redirectedFrom: null };

    const existing = await this.findByName(tx, appName);
    if (existing) return { app: existing, created: false, redirectedFrom: null };

    throw new Error(`could not resolve or create application "${appName}"`);
  }

  private async findByName(tx: Database, name: string): Promise<ApplicationRow | undefined> {
    const [row] = await tx
      .select()
      .from(application)
      .where(sql`lower(${application.name}) = lower(${name})`)
      .limit(1);
    return row;
  }

  /**
   * Upsert the parsed components into the shared `component` table, then link
   * them to this scan.
   *
   * `ON CONFLICT DO NOTHING` followed by a SELECT, rather than the
   * `DO UPDATE SET id = id RETURNING` trick: the no-op update would write a dead
   * tuple for every already-known package on every scan, which at thousands of
   * scans a day would bloat and thrash `component` for no benefit.
   */
  private async linkComponents(
    tx: Database,
    args: {
      scanId: string;
      applicationId: string;
      createdAt: Date;
      components: readonly ParsedComponent[];
    },
  ): Promise<void> {
    if (args.components.length === 0) return;

    for (const batch of chunk(args.components, COMPONENT_INSERT_CHUNK)) {
      await tx
        .insert(component)
        .values(
          batch.map((c) => ({
            identityHash: c.identityHash,
            name: c.name,
            version: c.version,
            ecosystem: c.ecosystem,
            purl: c.purl,
            cpe: c.cpe,
            kind: c.kind,
          })),
        )
        .onConflictDoNothing({ target: component.identityHash });
    }

    // Resolve every identity hash to its component id. Chunked to stay under the
    // bind-parameter ceiling.
    const idByHash = new Map<string, number>();
    const hashes = args.components.map((c) => c.identityHash);
    for (const batch of chunk(hashes, COMPONENT_LOOKUP_CHUNK)) {
      const rows = await tx
        .select({ id: component.id, identityHash: component.identityHash })
        .from(component)
        .where(inArray(component.identityHash, batch));
      for (const row of rows) idByHash.set(row.identityHash, row.id);
    }

    const links = args.components.map((c) => {
      const componentId = idByHash.get(c.identityHash);
      if (componentId === undefined) {
        // Unreachable: we just inserted or found every hash inside this
        // transaction. Failing loudly beats silently storing a partial scan.
        throw new Error(`component id missing for identity hash ${c.identityHash}`);
      }
      return {
        scanId: args.scanId,
        componentId,
        applicationId: args.applicationId,
        createdAt: args.createdAt,
      };
    });

    for (const batch of chunk(links, SCAN_COMPONENT_INSERT_CHUNK)) {
      await tx.insert(scanComponent).values(batch);
    }
  }

  /**
   * Advance the application's denormalised current-state pointers.
   *
   * `scan_count` always increments, but `latest_scan_id` only moves forward: two
   * builds ingesting concurrently would otherwise leave the pointer on whichever
   * transaction happened to commit last, which is not necessarily the newer
   * scan. The CASE guard makes commit order irrelevant.
   */
  private async updateApplicationPointer(
    tx: Database,
    args: { applicationId: string; scanId: string; scanCreatedAt: Date },
  ): Promise<boolean> {
    const result = await tx.execute<Row<{ became_latest: boolean }>>(sql`
      UPDATE ${application}
      SET scan_count = ${application.scanCount} + 1,
          latest_scan_id = CASE
            WHEN ${application.lastScanAt} IS NULL OR ${application.lastScanAt} <= ${args.scanCreatedAt}
            THEN ${args.scanId}::uuid
            ELSE ${application.latestScanId}
          END,
          last_scan_at = CASE
            WHEN ${application.lastScanAt} IS NULL OR ${application.lastScanAt} <= ${args.scanCreatedAt}
            THEN ${args.scanCreatedAt}::timestamptz
            ELSE ${application.lastScanAt}
          END,
          updated_at = now()
      WHERE ${application.id} = ${args.applicationId}::uuid
      RETURNING (${application.latestScanId} = ${args.scanId}::uuid) AS became_latest
    `);

    // RETURNING sees the post-update row, so this reads the outcome of the CASE
    // above rather than re-deriving it in JS — the one place that cannot disagree
    // with what was actually written.
    return rowsOf(result)[0]?.became_latest === true;
  }
}
