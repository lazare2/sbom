import type { FastifyInstance, FastifyRequest } from "fastify";
import { moduleIdParamSchema, setModuleEnabledSchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import type { Actor } from "../admin/audit.service.js";

function actorOf(request: FastifyRequest): Actor {
  const user = getUser(request);
  // The token, when one authenticated this request rather than a browser session. See the
  // note on `Actor.viaToken`.
  return {
    id: user.id,
    email: user.email,
    ...(request.apiToken ? { viaToken: request.apiToken.name } : {}),
  };
}

/**
 * Which modules exist and which are on. Readable by every signed-in account, because the menu
 * is built from it; it holds names and switches, nothing about the estate.
 */
export async function moduleRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/", async (_request, reply) => {
    return reply.send({ modules: await fastify.ctx.modules.states(fastify.ctx) });
  });
}

/** Switching a module on or off. Mounted behind `requireAdmin`. */
export async function moduleAdminRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAdmin);

  fastify.patch("/:id", async (request, reply) => {
    const { id } = parseOrThrow(moduleIdParamSchema, request.params, "Params");
    const { enabled } = parseOrThrow(setModuleEnabledSchema, request.body);
    return reply.send({
      module: await fastify.ctx.modules.setEnabled(fastify.ctx, id, enabled, actorOf(request)),
    });
  });
}
