import type { FastifyInstance } from "fastify";
import { parseOrThrow } from "../../lib/validate.js";
import { z } from "zod";

/**
 * Attribute definitions, read side.
 *
 * The UI needs these to render labels, input types, and select options for the
 * per-application attributes rather than hardcoding "squad / owner / severity" —
 * that is the whole point of keeping them as data. Writing them is an admin
 * action and lives under `/admin/attribute-definitions`.
 */
export async function attributeRoutes(fastify: FastifyInstance): Promise<void> {
  const { attributeDefinitions } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/", async (request, reply) => {
    const query = parseOrThrow(
      z.object({ includeInactive: z.enum(["true", "false"]).default("false") }),
      request.query,
      "Query",
    );

    // Deactivated definitions are hidden by default: a reader filtering the
    // application list should not be offered an attribute the organisation has
    // retired. The admin panel asks for them explicitly.
    return reply.send({
      definitions: await attributeDefinitions.list(query.includeInactive === "true"),
    });
  });
}
