import type { FastifyInstance, FastifyRequest } from "fastify";
import { directoryConnectionInputSchema, directoryGroupSearchSchema } from "@sbom/shared";
import { AppError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import type { Actor } from "../admin/audit.service.js";
import { DirectoryError } from "./connector.js";

function actorOf(request: FastifyRequest): Actor {
  const user = getUser(request);
  return { id: user.id, email: user.email, ...(request.apiToken ? { viaToken: request.apiToken.name } : {}) };
}

/**
 * Administration > Directory. Usable while the module is off, on purpose: the connection is set
 * up and tested first, and only then switched on.
 */
export async function directoryAdminRoutes(fastify: FastifyInstance): Promise<void> {
  const { directory } = fastify.ctx;

  fastify.get("/", async (_request, reply) => reply.send({ settings: await directory.settings() }));

  fastify.put("/", async (request, reply) => {
    const body = parseOrThrow(directoryConnectionInputSchema, request.body);
    return reply.send({ settings: await directory.save(body, actorOf(request)) });
  });

  /** Connects, signs in and searches once; the result is kept for the screen. */
  fastify.post("/test", async (_request, reply) => reply.send({ diagnosis: await directory.test() }));

  /** Groups to link a squad to. 502 with the reason when the directory cannot answer. */
  fastify.get("/groups", async (request, reply) => {
    const { q } = parseOrThrow(directoryGroupSearchSchema, request.query, "Query");
    try {
      return reply.send({ groups: await directory.findGroups(q) });
    } catch (error) {
      if (error instanceof DirectoryError) {
        throw new AppError({ statusCode: 502, code: `directory_${error.code}`, message: error.message });
      }
      throw error;
    }
  });
}
