import type { FastifyInstance } from "fastify";
import { ingestSastRequestSchema, idParamSchema } from "@sbom/shared";
import { UnauthorizedError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { IngestTokenService } from "../ingestion/ingest-token.service.js";
import { resolveIngestScope } from "../ingestion/ingestion.routes.js";
import { environmentAccess } from "../environments/scope.js";

/**
 * `POST /api/v1/sast` — the SAST ingest endpoint, for `sast-scan`'s CI
 * templates (`ci-templates/gitlab/sast-scan.gitlab-ci.yml`,
 * `ci-templates/jenkins/vars/sastScan.groovy`).
 *
 * JSON, not multipart: there is no file to stream, only the array
 * `python3 -m sast --format json` already produced. Otherwise deliberately
 * parallel to `POST /api/v1/scans` — same bearer-token auth, same
 * `environment` field and the same bound/unbound resolution rule
 * (`resolveIngestScope`, shared with it rather than re-derived here), same
 * status-code contract:
 *
 *   201 — the run is committed and queryable
 *   400 — malformed request (bad app_name, no environment for an unbound token)
 *   401 — bad or missing ingest token
 *   403 — a bound token named a different environment
 *   404 — no application by that name in the resolved environment (see sast.service.ts
 *         for why this does not auto-create one, unlike the SBOM endpoint)
 */
export async function sastIngestRoutes(fastify: FastifyInstance): Promise<void> {
  const { ingestTokens, sast, environments } = fastify.ctx;

  fastify.post(
    "/sast",
    {
      config: {
        // Same ceiling as the SBOM endpoint and the same reasoning: a runaway
        // loop is what this bounds, not a busy but legitimate pipeline.
        rateLimit: { max: 600, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const token = IngestTokenService.parseBearer(request.headers.authorization);
      if (!token) {
        throw new UnauthorizedError(
          "Missing bearer token. Send `Authorization: Bearer <token>` with the ingest token from your CI credentials store.",
        );
      }
      const verifiedToken = await ingestTokens.verify(token);
      if (!verifiedToken) {
        request.log.warn(
          { ip: request.ip, userAgent: request.headers["user-agent"] },
          "sast ingest rejected: invalid token",
        );
        throw new UnauthorizedError("Invalid or revoked ingest token.");
      }

      const body = parseOrThrow(ingestSastRequestSchema, request.body, "Body");
      const scope = await resolveIngestScope(environments, verifiedToken, body.environment ?? null);

      const result = await sast.ingest(body, scope, verifiedToken.name);

      request.log.info(
        { applicationId: result.applicationId, findingCount: result.findingCount },
        "sast ingest completed",
      );

      return reply.status(201).send(result);
    },
  );
}

/**
 * `GET /api/v1/sast/applications/:id` — the latest SAST run for an
 * application, read side. Session-authenticated like every other read route;
 * registered in its own scope for the same reason `scanRoutes` is — so the
 * ingest route's bearer auth above and this route's session guard can never
 * cross over.
 */
export async function sastRoutes(fastify: FastifyInstance): Promise<void> {
  const { applications, sast } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/applications/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");

    // Confirms the application exists and is visible to the caller (and yields
    // a clean 404/403 if not) before querying its SAST run — the same pattern
    // `/scans/:id/components` uses for the same reason: this doesn't need
    // application data itself, but validating access without a public method
    // that returns just a yes/no would mean adding one.
    await applications.getById(id, await environmentAccess(request));

    const run = await sast.getLatestForApplication(id);
    return reply.send({ run });
  });
}
