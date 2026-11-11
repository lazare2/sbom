import type { FastifyInstance } from "fastify";
import { inventoryQuerySchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { requireScope } from "../environments/scope.js";

/** What the reader's estate is made of. Read-only, any authenticated user, one estate at a time. */
export async function inventoryRoutes(fastify: FastifyInstance): Promise<void> {
  const { inventory } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/report", async (request, reply) => {
    const { limit, ...filter } = parseOrThrow(inventoryQuerySchema, request.query, "Query");
    return reply.send(await inventory.report({ scope: await requireScope(request), filter, limit }));
  });
}
