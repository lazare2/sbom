import type { FastifyInstance } from "fastify";
import { idParamSchema, listGroupAdvisoriesQuerySchema, listGroupsQuerySchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";

/**
 * Read-only group endpoints.
 *
 * Behind `requireAuth` but not `requireAdmin`, matching the applications module: any signed-in
 * user can read every group and its membership. There is deliberately no per-group visibility
 * — groups describe the estate rather than partition access to it, and a group nobody outside
 * its members can see would make "which of our applications are public facing" unanswerable
 * by the person most likely to ask.
 */
export async function groupRoutes(fastify: FastifyInstance): Promise<void> {
  const { groups } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/", async (request, reply) => {
    const query = parseOrThrow(listGroupsQuerySchema, request.query, "Query");
    return reply.send(await groups.list(query));
  });

  fastify.get("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send({ group: await groups.getById(id) });
  });

  /**
   * The group's distinct advisories, each with how many members it reaches.
   *
   * Paginated separately from the group itself: a large group can carry thousands of
   * advisories, and the detail response has to stay small enough to render a header from.
   */
  fastify.get("/:id/advisories", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(listGroupAdvisoriesQuerySchema, request.query, "Query");
    return reply.send(await groups.listAdvisories(id, query));
  });
}
