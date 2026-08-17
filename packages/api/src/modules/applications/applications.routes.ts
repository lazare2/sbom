import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  idParamSchema,
  listApplicationsQuerySchema,
  listRemovedComponentsQuerySchema,
  listScanComponentsQuerySchema,
  listScansQuerySchema,
  scanDiffQuerySchema,
} from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";

/**
 * Read-only application endpoints.
 *
 * Every route sits behind `requireAuth` but not `requireAdmin`: per the access
 * model for this phase, any authenticated user can read every application and all
 * of its SBOM data. There is deliberately no per-application or per-squad
 * filtering here.
 */
export async function applicationRoutes(fastify: FastifyInstance): Promise<void> {
  const { applications, scans, diff } = fastify.ctx;

  // Applied to every route in this plugin scope.
  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/", async (request, reply) => {
    const query = parseOrThrow(listApplicationsQuerySchema, request.query, "Query");
    return reply.send(await applications.list(query));
  });

  /** Distinct values for an attribute key, for the list view's filter dropdowns. */
  fastify.get("/attribute-values/:key", async (request, reply) => {
    const { key } = parseOrThrow(
      z.object({ key: z.string().regex(/^[a-z][a-z0-9_]*$/, "must be lower_snake_case") }),
      request.params,
      "Params",
    );
    return reply.send({ values: await applications.listAttributeValues(key) });
  });

  fastify.get("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send(await applications.getById(id));
  });

  /** Components of the application's current state (its latest scan). */
  fastify.get("/:id/components", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(listScanComponentsQuerySchema, request.query, "Query");
    return reply.send(await applications.listLatestComponents(id, query));
  });

  /** Ecosystem breakdown of the latest scan, for the filter dropdown and a chart. */
  fastify.get("/:id/ecosystems", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const app = await applications.getById(id);
    if (!app.latestScanId) return reply.send({ ecosystems: [] });
    return reply.send({ ecosystems: await applications.listEcosystemsOfScan(app.latestScanId) });
  });

  /** Full scan history for this application. */
  fastify.get("/:id/scans", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(listScansQuerySchema, request.query, "Query");
    return reply.send(await scans.listForApplication(id, query));
  });

  /**
   * Packages this application has shipped at some point but no longer does,
   * each with the build it was last seen in.
   *
   * Separate from the scan-to-scan diff below: this spans the entire retained
   * history rather than two adjacent builds, so a dependency dropped a year ago
   * still shows up.
   */
  fastify.get("/:id/removed-components", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(listRemovedComponentsQuerySchema, request.query, "Query");
    return reply.send(await diff.listRemoved(id, query));
  });

  /**
   * Compare two builds. With no parameters, compares the latest scan against
   * the one immediately before it — the "what changed in this build" default.
   */
  fastify.get("/:id/diff", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(scanDiffQuerySchema, request.query, "Query");
    return reply.send(
      await diff.diff(id, {
        ...(query.fromScanId ? { fromScanId: query.fromScanId } : {}),
        ...(query.toScanId ? { toScanId: query.toScanId } : {}),
      }),
    );
  });
}
