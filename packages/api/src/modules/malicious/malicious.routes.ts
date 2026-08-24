import type { FastifyInstance } from "fastify";
import { listMaliciousQuerySchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";

/**
 * Malicious-package reads.
 *
 * Behind `requireAuth` but not `requireAdmin`, matching the vulnerability read routes: any
 * signed-in user can see what the estate is carrying. Only acting on it -- acknowledging,
 * changing settings, forcing a refresh -- is restricted.
 *
 * Registered in two scopes for the reason the vulnerability module is. The findings routes
 * refuse with 409 while detection is off, so an estate nobody has checked can never render as
 * an estate with nothing wrong; the status route stays readable in every state, because the
 * SPA has to tell "switched off" from "broken" to decide what to put on screen.
 */
export async function maliciousRoutes(fastify: FastifyInstance): Promise<void> {
  const { malicious } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  /**
   * Refuses as a whole rather than returning an empty list.
   *
   * `{ items: [] }` from a disabled feature is indistinguishable from a clean estate, and the
   * client would have no way to know which it was looking at. A named code forces it to
   * handle the difference.
   */
  fastify.addHook("preHandler", async (_request, reply) => {
    if (!(await malicious.isEnabled())) {
      return reply.status(409).send({
        error: {
          code: "malicious_detection_disabled",
          message:
            "Malicious package detection is switched off. An administrator can enable it in Admin -> Malicious packages.",
        },
      });
    }
  });

  fastify.get("/", async (request, reply) => {
    const query = parseOrThrow(listMaliciousQuerySchema, request.query, "Query");
    return reply.send(await malicious.list(query));
  });

  fastify.get("/:id", async (request, reply) => {
    // Not `idParamSchema`: these ids are upstream OSV strings like `MAL-2024-1677`, not uuids.
    const { id } = request.params as { id: string };
    return reply.send({ finding: await malicious.getById(id) });
  });
}

/**
 * Feature state, readable whatever condition the feature is in.
 *
 * Its own plugin so it cannot inherit the refusal hook above. This is the endpoint that lets
 * the UI explain a disabled or never-downloaded feed instead of rendering it as an error.
 */
export async function maliciousStatusRoutes(fastify: FastifyInstance): Promise<void> {
  const { malicious } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/", async (_request, reply) => {
    return reply.send(await malicious.status());
  });
}
