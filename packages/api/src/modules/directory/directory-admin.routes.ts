import type { FastifyInstance, FastifyRequest } from "fastify";
import {
  directoryConnectionInputSchema,
  directoryGroupSearchSchema,
  directorySyncRequestSchema,
  directorySyncSettingsSchema,
  idParamSchema,
  linkSquadToDirectorySchema,
} from "@sbom/shared";
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
  const { directory, directoryLinks, directorySync } = fastify.ctx;

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

  /** Every squad that takes its members from a directory group. */
  fastify.get("/squad-links", async (_request, reply) => reply.send({ links: await directoryLinks.list() }));

  /** Links a squad to a group (or moves its link to another group). Needs the module on. */
  fastify.put("/squad-links/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const { groupId } = parseOrThrow(linkSquadToDirectorySchema, request.body);
    return reply.send({ link: await directoryLinks.link(id, groupId, actorOf(request)) });
  });

  /** Unlinks a squad; its members stay, hand-managed again. */
  fastify.delete("/squad-links/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    await directoryLinks.unlink(id, actorOf(request));
    return reply.status(204).send();
  });

  /** The sync's settings, last run and whether one is running. */
  fastify.get("/sync", async (_request, reply) => reply.send({ sync: await directorySync.state() }));

  fastify.put("/sync/settings", async (request, reply) => {
    const body = parseOrThrow(directorySyncSettingsSchema, request.body);
    return reply.send({ sync: await directorySync.updateSettings(body, actorOf(request)) });
  });

  /** What a sync would do now. Changes nothing. 502 when the directory cannot be read. */
  fastify.post("/sync/preview", async (_request, reply) => {
    try {
      return reply.send({ plan: await directorySync.preview() });
    } catch (error) {
      if (error instanceof DirectoryError) {
        throw new AppError({ statusCode: 502, code: `directory_${error.code}`, message: error.message });
      }
      throw error;
    }
  });

  /** Sync now. Held for approval like the nightly run, unless `approve` says the plan was seen. */
  fastify.post("/sync", async (request, reply) => {
    const { approve } = parseOrThrow(directorySyncRequestSchema, request.body ?? {});
    return reply.send({ run: await directorySync.run("manual", actorOf(request), approve) });
  });
}
