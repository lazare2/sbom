import type { FastifyInstance } from "fastify";
import { ingestScanFieldsSchema, type IngestScanResponse } from "@sbom/shared";
import { BadRequestError, UnauthorizedError, ValidationError } from "../../lib/errors.js";
import { IngestTokenService } from "./ingest-token.service.js";

/**
 * `POST /api/v1/scans` — the CI/CD ingestion endpoint.
 *
 * Both integration paths (a Jenkins shared-library step and a GitLab CI
 * `include:` template) post an identical `multipart/form-data` body here, and the
 * API has no way to tell which called it — that is by design.
 *
 * Because pipelines invoke this with `curl -f`, the status code is the contract:
 *   201 — the scan is committed and queryable
 *   400 — the request is malformed (missing file, bad app_name); retrying won't help
 *   401 — bad or missing ingest token
 *   413 — SBOM larger than INGEST_MAX_SBOM_BYTES
 *   415 — not multipart/form-data
 *   422 — the file is not a CycloneDX SBOM
 *   5xx — transient; the pipeline may retry
 *
 * An unrecognised `app_name` is deliberately NOT an error: it auto-creates a
 * `pending_confirmation` application so a build's SBOM is never dropped just
 * because nobody pre-registered the repo.
 */
export async function ingestionRoutes(fastify: FastifyInstance): Promise<void> {
  const { ingestTokens, ingestion, config, vulnWorker } = fastify.ctx;

  fastify.post(
    "/scans",
    {
      config: {
        // Generous: ~1000 applications building several times a day, and CI
        // bursts (a monorepo pipeline, a mass rebuild) are legitimate. The limit
        // exists to stop a runaway loop, not to shape normal traffic.
        rateLimit: { max: 600, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      // --- 1. authenticate the CI system --------------------------------
      const bearer = IngestTokenService.parseBearer(request.headers.authorization);
      if (!bearer) {
        throw new UnauthorizedError(
          "Missing bearer token. Send `Authorization: Bearer <token>` with the ingest token from your CI credentials store.",
        );
      }
      const verifiedToken = await ingestTokens.verify(bearer);
      if (!verifiedToken) {
        request.log.warn(
          { ip: request.ip, userAgent: request.headers["user-agent"] },
          "ingest rejected: invalid token",
        );
        throw new UnauthorizedError("Invalid or revoked ingest token.");
      }

      // --- 2. read the multipart body -----------------------------------
      if (!request.isMultipart()) {
        return reply.status(415).send({
          error: {
            code: "unsupported_media_type",
            message:
              "This endpoint expects multipart/form-data with an `sbom` file part. " +
              "Example: curl -f -H 'Authorization: Bearer $TOKEN' -F sbom=@sbom.json -F app_name=my-service <url>",
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
            // Every file stream must be consumed or the request never
            // completes. Drain and discard anything unexpected.
            await part.toBuffer();
            request.log.warn({ fieldname: part.fieldname }, "ignoring unexpected file part");
          }
        } else {
          // Multipart values arrive as strings; a repeated field keeps the first.
          rawFields[part.fieldname] ??= String(part.value);
        }
      }

      if (sbomBuffer === undefined) {
        throw new BadRequestError(
          "Missing `sbom` file part. Attach the CycloneDX JSON produced by `syft <image> -o cyclonedx-json`.",
        );
      }
      if (sbomBuffer.length === 0) {
        throw new BadRequestError(
          "The `sbom` file part is empty. Check that the syft step ran and wrote output before the upload.",
        );
      }

      // --- 3. validate metadata fields ----------------------------------
      const parsedFields = ingestScanFieldsSchema.safeParse(rawFields);
      if (!parsedFields.success) {
        throw new ValidationError(
          "Invalid scan metadata.",
          parsedFields.error.issues.map((i) => ({
            field: i.path.join(".") || "_",
            message: i.message,
          })),
        );
      }

      // --- 4. ingest ------------------------------------------------------
      const result: IngestScanResponse = await ingestion.ingest({
        fields: parsedFields.data,
        rawSbom: sbomBuffer,
        tokenName: verifiedToken.name,
      });

      request.log.info(
        {
          sbomFilename,
          sbomBytes: sbomBuffer.length,
          maxBytes: config.INGEST_MAX_SBOM_BYTES,
        },
        "ingest request completed",
      );

      /*
       * Vulnerability matching is kicked off but never waited for.
       *
       * 201 keeps meaning exactly what it meant before this feature existed — the SBOM
       * is committed and queryable — so a pipeline's `curl -f` is unaffected. Findings
       * appear seconds later. Making this synchronous would put Grype's runtime on every
       * build (measured: ~9s for a 3,000-package image) and would force an impossible
       * choice when Grype fails: fail a build whose SBOM stored perfectly, or return 201
       * while silently recording no vulnerabilities.
       *
       * No-ops when scanning is disabled, so nothing changes for a deployment that has
       * never turned it on.
       */
      vulnWorker.requestSweepAfterIngest();

      return reply.status(201).send(result);
    },
  );
}
