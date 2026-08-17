import type { FastifyInstance } from "fastify";
import { idParamSchema, manualUploadFieldsSchema, type ManualUploadResponse } from "@sbom/shared";
import { BadRequestError, ValidationError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";

/**
 * `POST /api/v1/applications/:id/scans` — manual SBOM upload.
 *
 * The same ingestion as `POST /api/v1/scans`, reached by a signed-in person from
 * an application's scan history instead of by a pipeline with a bearer token. The
 * resulting scan is a normal scan in every respect: it becomes the application's
 * current build, its components are searchable, and it appears in diffs, the
 * dashboard and the analytics report. That equivalence is the requirement, and it
 * is enforced structurally — this route builds no scan rows of its own, it calls
 * `ingestion.ingestManual()`, which shares one private `store()` with the CI path.
 *
 * Four deliberate differences from the CI endpoint, each because a human is on the
 * other end rather than a `curl -f`:
 *
 *  1. The application comes from the URL, never from `app_name`. Nothing is
 *     auto-created; an unknown id is a 404. Someone uploading from a page they
 *     navigated to has already chosen the target, and letting the SBOM's own
 *     contents redirect it elsewhere would be a surprise, not a convenience.
 *  2. A byte-identical re-upload is a 409 rather than a second identical build,
 *     unless `allow_duplicate=true`. A double-clicked button is far more likely
 *     than a genuine need for the duplicate. CI keeps the old behaviour, because
 *     re-scanning an unchanged artifact legitimately produces the same bytes.
 *  3. Who uploaded it is recorded on the scan and on the audit log.
 *  4. A much lower rate limit. No person needs to upload SBOMs at CI speed, and
 *     the ceiling bounds an accidental script.
 *
 * Registered as its own plugin scope rather than added to `applications.routes.ts`
 * so that file stays honestly read-only, and so this route's `requireAuth` hook is
 * scope-wide in the same way every other guard in this codebase is.
 */
export async function manualUploadRoutes(fastify: FastifyInstance): Promise<void> {
  const { ingestion, audit, config, vulnWorker } = fastify.ctx;

  /*
   * `requireAuth`, not `requireAdmin`.
   *
   * Any authenticated user may upload, matching the access model of the rest of
   * the platform and the trust level of the path this mirrors: CI ingest is
   * authenticated by a token shared across pipelines, it auto-creates
   * applications with no human approval, and any pipeline author can use it.
   * Restricting the *named, audited* equivalent to admins while leaving the
   * anonymous-by-design one open to every pipeline would be backwards, and it
   * would block the case the feature exists for — an engineer holding an SBOM for
   * an application whose pipeline is not wired up yet.
   *
   * The write is also append-only: history is never overwritten, a wrong upload
   * is corrected by uploading the right one, and every upload names its uploader.
   *
   * To make this admin-only instead, change this one line to `fastify.requireAdmin`.
   */
  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.post(
    "/:id/scans",
    {
      config: {
        // Two orders of magnitude below the CI endpoint's 600/min. An SBOM upload
        // costs a parse plus thousands of inserts, and nobody drives that by hand.
        rateLimit: { max: 20, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const { id } = parseOrThrow(idParamSchema, request.params, "Params");
      const user = getUser(request);

      if (!request.isMultipart()) {
        return reply.status(415).send({
          error: {
            code: "unsupported_media_type",
            message:
              "This endpoint expects multipart/form-data with an `sbom` file part containing CycloneDX JSON.",
          },
        });
      }

      let sbomBuffer: Buffer | undefined;
      let sbomFilename: string | undefined;
      const rawFields: Record<string, string> = {};

      for await (const part of request.parts()) {
        if (part.type === "file") {
          if (part.fieldname === "sbom" && sbomBuffer === undefined) {
            sbomBuffer = await part.toBuffer();
            sbomFilename = part.filename;
          } else {
            // Every file stream must be consumed or the request never completes.
            await part.toBuffer();
            request.log.warn({ fieldname: part.fieldname }, "ignoring unexpected file part");
          }
        } else {
          rawFields[part.fieldname] ??= String(part.value);
        }
      }

      if (sbomBuffer === undefined) {
        throw new BadRequestError(
          "Missing `sbom` file part. Attach the CycloneDX JSON produced by `syft <image> -o cyclonedx-json`.",
        );
      }
      if (sbomBuffer.length === 0) {
        throw new BadRequestError("The selected file is empty.");
      }

      const parsedFields = manualUploadFieldsSchema.safeParse(rawFields);
      if (!parsedFields.success) {
        throw new ValidationError(
          "Invalid upload metadata.",
          parsedFields.error.issues.map((i) => ({
            field: i.path.join(".") || "_",
            message: i.message,
          })),
        );
      }

      const result: ManualUploadResponse = await ingestion.ingestManual({
        applicationId: id,
        fields: parsedFields.data,
        rawSbom: sbomBuffer,
        uploader: { id: user.id, email: user.email },
      });

      /*
       * Audited outside the ingest transaction, unlike admin writes.
       *
       * The scan is the durable record and it already carries its uploader, so an
       * audit row is a convenience for the admin trail rather than the only
       * evidence. Rolling back a successfully stored scan because the audit insert
       * failed would be the worse trade — it would turn a logging problem into
       * lost SBOM data.
       */
      await audit.record({
        actor: { id: user.id, email: user.email },
        action: "scan.manual_upload",
        targetType: "scan",
        targetId: result.scanId,
        metadata: {
          applicationId: result.applicationId,
          applicationName: result.applicationName,
          filename: sbomFilename ?? null,
          sbomBytes: sbomBuffer.length,
          componentCount: result.componentCount,
          buildNumber: parsedFields.data.build_number ?? null,
          becameLatest: result.becameLatest,
          duplicateOfScanId: result.duplicateOfScanId,
          note: parsedFields.data.note ?? null,
        },
      });

      request.log.info(
        {
          scanId: result.scanId,
          applicationId: result.applicationId,
          sbomFilename,
          sbomBytes: sbomBuffer.length,
          maxBytes: config.INGEST_MAX_SBOM_BYTES,
          uploadedBy: user.email,
        },
        "manual sbom upload completed",
      );

      // Same asynchronous treatment as the CI path — a manual upload is a normal scan
      // in this respect too, and the receipt should not wait on Grype.
      vulnWorker.requestSweepAfterIngest();

      return reply.status(201).send(result);
    },
  );
}
