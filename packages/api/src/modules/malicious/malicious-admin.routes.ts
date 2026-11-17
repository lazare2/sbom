import type { FastifyInstance, FastifyRequest } from "fastify";
import {
  acknowledgeMaliciousRequestSchema,
  idParamSchema,
  listMaliciousHistoryQuerySchema,
  updateMaliciousSettingsSchema,
} from "@sbom/shared";
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
 * The malicious-packages settings page: mounted at /admin/malicious, behind `requireAdmin`
 * applied by the module frame. The addresses are the ones these routes had when they lived in
 * admin.routes.ts.
 */
export async function maliciousAdminRoutes(fastify: FastifyInstance): Promise<void> {
  const { adminMalicious, malicious, maliciousFeed } = fastify.ctx;

  /*
    Settings and status are readable here as well as on the public status route, because the
    admin page needs the feed's attempt history and its recipient list -- neither of which
    belongs in a payload every signed-in user can fetch.
  */
  fastify.get("/settings", async (_request, reply) => {
    return reply.send({
      settings: await adminMalicious.getSettings(),
      status: await malicious.status(),
    });
  });

  fastify.patch("/settings", async (request, reply) => {
    const body = parseOrThrow(updateMaliciousSettingsSchema, request.body);
    return reply.send({ settings: await adminMalicious.updateSettings(body, actorOf(request)) });
  });

  fastify.get("/history", async (request, reply) => {
    const { limit } = parseOrThrow(listMaliciousHistoryQuerySchema, request.query, "Query");
    return reply.send({ attempts: await maliciousFeed.history(limit) });
  });

  /**
   * Fetch the feed now.
   *
   * 200 with an outcome rather than a failure status when the feed cannot be reached. An
   * air-gapped deployment reaches this path every time, and a 5xx would make a normal
   * condition look like a broken server -- the outcome and the URL that failed are what the
   * administrator actually needs.
   */
  fastify.post("/update", async (request, reply) => {
    return reply.send(await adminMalicious.updateFeed(actorOf(request)));
  });

  /** Record a decision about a finding. Never hides it; the row stays and gains a label. */
  fastify.post("/acknowledgements", async (request, reply) => {
    const body = parseOrThrow(acknowledgeMaliciousRequestSchema, request.body);
    return reply
      .status(201)
      .send({ acknowledgement: await adminMalicious.acknowledge(body, actorOf(request)) });
  });

  fastify.delete("/acknowledgements/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    await adminMalicious.removeAcknowledgement(id, actorOf(request));
    return reply.status(204).send();
  });
}
