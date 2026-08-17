import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { idParamSchema, listScanComponentsQuerySchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";

/**
 * Read-only scan endpoints. Same access rule as applications: any authenticated
 * user, no write access.
 *
 * Note the route prefix is `/scans` for GETs while ingestion POSTs to the same
 * path with a bearer token. They are registered in separate scopes so the
 * session-auth hook here cannot ever apply to the CI upload, and vice versa.
 */
export async function scanRoutes(fastify: FastifyInstance): Promise<void> {
  const { scans, applications } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  /** Recent activity across all applications, for the dashboard. */
  fastify.get("/recent", async (request, reply) => {
    const { limit } = parseOrThrow(
      z.object({ limit: z.coerce.number().int().min(1).max(100).default(20) }),
      request.query,
      "Query",
    );
    return reply.send({ scans: await scans.listRecent(limit) });
  });

  fastify.get("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send(await scans.getById(id));
  });

  /**
   * Component list for a specific historical scan, not just the latest. This is
   * what makes the retained history actually useful rather than merely stored.
   */
  fastify.get("/:id/components", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(listScanComponentsQuerySchema, request.query, "Query");
    // Confirms the scan exists (and yields a clean 404 if not) before querying
    // its components, which would otherwise return a misleading empty page.
    await scans.getById(id);
    return reply.send(await applications.listComponentsOfScan(id, query));
  });

  fastify.get("/:id/ecosystems", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    await scans.getById(id);
    return reply.send({ ecosystems: await applications.listEcosystemsOfScan(id) });
  });

  /**
   * The original uploaded CycloneDX document, byte for byte.
   *
   * This is the reason the raw blob is retained at all: the parsed rows are a
   * derived view, and an audit needs the artifact the pipeline actually produced.
   */
  fastify.get("/:id/raw", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const { body, filename } = await scans.getRawSbom(id);
    return reply
      .header("Content-Type", "application/json")
      .header("Content-Disposition", `attachment; filename="${filename}"`)
      .header("Content-Length", String(body.length))
      .send(body);
  });
}
