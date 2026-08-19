import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  attributeDefinitionSchema,
  confirmApplicationRequestSchema,
  createApplicationRequestSchema,
  createGroupRequestSchema,
  createIngestTokenRequestSchema,
  createUserRequestSchema,
  idParamSchema,
  listAuditLogQuerySchema,
  listUsersQuerySchema,
  mergeApplicationRequestSchema,
  resetUserPasswordRequestSchema,
  setGroupMembersRequestSchema,
  updateGroupRequestSchema,
  updateApplicationRequestSchema,
  updateAttributeDefinitionSchema,
  updateUserRequestSchema,
  updatePlatformSettingsSchema,
} from "@sbom/shared";
import { NotFoundError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { vulnAdminRoutes } from "../vulnerabilities/vuln-admin.routes.js";
import type { Actor } from "./audit.service.js";

/** The acting admin, denormalised onto every audit row this request writes. */
function actorOf(request: FastifyRequest): Actor {
  const user = getUser(request);
  return { id: user.id, email: user.email };
}

const aliasBodySchema = z.object({
  aliasName: z
    .string()
    .trim()
    .min(1)
    .max(255)
    .regex(/^[^\p{C}]+$/u, "must not contain control characters"),
});

/**
 * Admin write API.
 *
 * Every route in this plugin sits behind `requireAdmin`, applied once as a
 * scope-wide hook rather than per route. That ordering is deliberate: a new
 * endpoint added to this file is protected by default, whereas a per-route
 * `preHandler` is protected only if the author remembered.
 */
export async function adminRoutes(fastify: FastifyInstance): Promise<void> {
  const {
    adminUsers,
    adminApplications,
    adminGroups,
    adminScans,
    attributeDefinitions,
    audit,
    ingestTokens,
    settings,
  } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAdmin);

  // -------------------------------------------------------------------------
  // Users
  // -------------------------------------------------------------------------

  fastify.get("/users", async (request, reply) => {
    const query = parseOrThrow(listUsersQuerySchema, request.query, "Query");
    return reply.send(await adminUsers.list(query));
  });

  fastify.get("/users/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send({ user: await adminUsers.getById(id) });
  });

  /**
   * 201 with the generated password in the body. It is shown once and never
   * retrievable again — the plaintext is not stored, only its argon2 hash.
   */
  fastify.post("/users", async (request, reply) => {
    const body = parseOrThrow(createUserRequestSchema, request.body);
    const created = await adminUsers.create(body, actorOf(request));
    return reply.status(201).send(created);
  });

  fastify.patch("/users/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(updateUserRequestSchema, request.body);
    return reply.send({ user: await adminUsers.update(id, body, actorOf(request)) });
  });

  fastify.post("/users/:id/reset-password", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(resetUserPasswordRequestSchema, request.body ?? {});
    return reply.send(await adminUsers.resetPassword(id, body, actorOf(request)));
  });

  fastify.delete("/users/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    await adminUsers.remove(id, actorOf(request));
    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // Applications
  // -------------------------------------------------------------------------

  fastify.post("/applications", async (request, reply) => {
    const body = parseOrThrow(createApplicationRequestSchema, request.body);
    const created = await adminApplications.create(body, actorOf(request));
    return reply.status(201).send({ application: created });
  });

  fastify.patch("/applications/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(updateApplicationRequestSchema, request.body);
    return reply.send({ application: await adminApplications.update(id, body, actorOf(request)) });
  });

  fastify.delete("/applications/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const result = await adminApplications.remove(id, actorOf(request));
    return reply.send(result);
  });

  // -------------------------------------------------------------------------
  // Scan history
  // -------------------------------------------------------------------------

  /**
   * Remove one build from an application's history.
   *
   * Under `/admin` rather than beside the read-only `/scans` routes, and admin-only
   * while manual upload is open to any signed-in user. Upload is append-only -- a
   * wrong SBOM is corrected by uploading the right one -- whereas this destroys a
   * record that diffs and past reports point at, and nothing brings it back.
   *
   * Deleting the current build is allowed and promotes the one before it, which is
   * the case the endpoint mostly exists for: an SBOM uploaded against the wrong
   * application becomes its current state immediately, and the fix has to be able
   * to reach it. The response reports the promotion so the client knows the
   * application's whole current-state view just changed.
   */
  fastify.delete("/scans/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send(await adminScans.remove(id, actorOf(request)));
  });

  // -------------------------------------------------------------------------
  // Groups
  // -------------------------------------------------------------------------

  fastify.post("/groups", async (request, reply) => {
    const body = parseOrThrow(createGroupRequestSchema, request.body);
    return reply.status(201).send({ group: await adminGroups.create(body, actorOf(request)) });
  });

  fastify.patch("/groups/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(updateGroupRequestSchema, request.body);
    return reply.send({ group: await adminGroups.update(id, body, actorOf(request)) });
  });

  /**
   * Replaces the whole membership rather than adding or removing one at a time.
   *
   * A PUT because it is idempotent and the body is the complete resulting set — sending the
   * same list twice leaves the group in the same state, which is what makes a retry after a
   * dropped response safe.
   */
  fastify.put("/groups/:id/members", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(setGroupMembersRequestSchema, request.body);
    return reply.send({ group: await adminGroups.setMembers(id, body, actorOf(request)) });
  });

  /** Deletes the group only. The applications in it are untouched. */
  fastify.delete("/groups/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send(await adminGroups.remove(id, actorOf(request)));
  });

  // --- pending-confirmation resolution ---------------------------------------

  fastify.post("/applications/:id/confirm", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(confirmApplicationRequestSchema, request.body ?? {});
    return reply.send({ application: await adminApplications.confirm(id, body, actorOf(request)) });
  });

  fastify.post("/applications/:id/merge", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(mergeApplicationRequestSchema, request.body);
    return reply.send(await adminApplications.merge(id, body, actorOf(request)));
  });

  // --- aliases ---------------------------------------------------------------

  fastify.post("/applications/:id/aliases", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(aliasBodySchema, request.body);
    await adminApplications.addAlias(id, body.aliasName, actorOf(request));
    return reply.status(201).send({ aliasName: body.aliasName });
  });

  fastify.delete("/applications/:id/aliases/:aliasName", async (request, reply) => {
    const params = parseOrThrow(
      z.object({ id: z.string().uuid(), aliasName: z.string().min(1).max(255) }),
      request.params,
      "Params",
    );
    await adminApplications.removeAlias(params.id, params.aliasName, actorOf(request));
    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // Attribute definitions
  // -------------------------------------------------------------------------

  fastify.post("/attribute-definitions", async (request, reply) => {
    const body = parseOrThrow(attributeDefinitionSchema, request.body);
    const created = await attributeDefinitions.create(body, actorOf(request));
    return reply.status(201).send({ definition: created });
  });

  fastify.patch("/attribute-definitions/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(updateAttributeDefinitionSchema, request.body);
    return reply.send({ definition: await attributeDefinitions.update(id, body, actorOf(request)) });
  });

  /**
   * `?purge=true` also strips the key from every application that carries it.
   * Without it, a definition still in use is refused with a 409 naming the
   * count, so nobody deletes 200 squad tags by reflex.
   */
  fastify.delete("/attribute-definitions/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const query = parseOrThrow(
      z.object({ purge: z.enum(["true", "false"]).default("false") }),
      request.query,
      "Query",
    );
    const result = await attributeDefinitions.remove(id, { purge: query.purge === "true" }, actorOf(request));
    return reply.send(result);
  });

  // -------------------------------------------------------------------------
  // CI ingest tokens
  // -------------------------------------------------------------------------

  fastify.get("/ingest-tokens", async (_request, reply) => {
    return reply.send({ tokens: await ingestTokens.list() });
  });

  fastify.post("/ingest-tokens", async (request, reply) => {
    const body = parseOrThrow(createIngestTokenRequestSchema, request.body);
    const created = await ingestTokens.create({ name: body.name, createdByUserId: getUser(request).id });

    await audit.record({
      actor: actorOf(request),
      action: "ingest_token.create",
      targetType: "ingest_token",
      targetId: created.id,
      metadata: { name: body.name },
    });

    const tokens = await ingestTokens.list();
    const summary = tokens.find((t) => t.id === created.id);
    if (!summary) throw new Error("created ingest token not found in listing");

    return reply.status(201).send({ token: summary, plaintext: created.token });
  });

  fastify.delete("/ingest-tokens/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const revoked = await ingestTokens.revoke(id);
    if (!revoked) throw new NotFoundError("Ingest token");

    await audit.record({
      actor: actorOf(request),
      action: "ingest_token.revoke",
      targetType: "ingest_token",
      targetId: id,
    });

    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // Vulnerability scanning
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // Platform settings
  // -------------------------------------------------------------------------

  /*
    Separate from /vuln/settings, which owns the scanning switches. This is for values that
    describe the estate rather than the scanner -- currently the staleness threshold, which
    is a property of how often an organisation builds rather than of the software, and so
    belongs to whoever runs it rather than to whoever deployed it.
  */
  fastify.get("/settings", async (_request, reply) => {
    return reply.send({ settings: await settings.getPlatformSettings() });
  });

  fastify.patch("/settings", async (request, reply) => {
    const body = parseOrThrow(updatePlatformSettingsSchema, request.body);
    const actor = actorOf(request);
    const { before, after } = await settings.updatePlatformSettings(body, actor);

    // Recorded because it changes what every dashboard reports: an application that was
    // fine yesterday can be stale today with no scan having changed, and the audit trail is
    // what explains that to whoever asks.
    await audit.record({
      actor,
      action: "settings.update",
      targetType: "setting",
      targetId: "platform",
      metadata: { before, after },
    });

    return reply.send({ settings: after });
  });

  // Nested inside this scope so it inherits `requireAdmin` rather than declaring its
  // own guard, which is the pattern that makes a forgotten guard impossible here.
  await fastify.register(vulnAdminRoutes, { prefix: "/vuln" });

  // -------------------------------------------------------------------------
  // Audit trail
  // -------------------------------------------------------------------------

  fastify.get("/audit-log", async (request, reply) => {
    const query = parseOrThrow(listAuditLogQuerySchema, request.query, "Query");
    return reply.send(await audit.list(query));
  });
}
