import { requireScope } from "../environments/scope.js";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  attributeDefinitionSchema,
  confirmApplicationRequestSchema,
  createApplicationRequestSchema,
  acknowledgeMaliciousRequestSchema,
  createGroupRequestSchema,
  createIngestTokenRequestSchema,
  createUserRequestSchema,
  idParamSchema,
  listApiErrorsQuerySchema,
  listAuditLogQuerySchema,
  listMaliciousHistoryQuerySchema,
  listUsersQuerySchema,
  mergeApplicationRequestSchema,
  resetUserPasswordRequestSchema,
  setGroupMembersRequestSchema,
  setUserApplicationAccessSchema,
  setUserEnvironmentsRequestSchema,
  updateGroupRequestSchema,
  updateMaliciousSettingsSchema,
  updateApplicationRequestSchema,
  updateAttributeDefinitionSchema,
  updateUserRequestSchema,
  updatePlatformSettingsSchema,
} from "@sbom/shared";
import { ConflictError, NotFoundError } from "../../lib/errors.js";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { vulnAdminRoutes } from "../vulnerabilities/vuln-admin.routes.js";
import type { Actor } from "./audit.service.js";

/** The acting admin, denormalised onto every audit row this request writes. */
function actorOf(request: FastifyRequest): Actor {
  const user = getUser(request);
  return { id: user.id, email: user.email };
}

/**
 * Batch size for one backfill pass.
 *
 * Bounded at both ends: a floor of 1 so a caller can step through one scan at a time while
 * diagnosing, and a ceiling of 2000 because each scan means a blob read plus a full JSON parse
 * and an unbounded limit turns an admin click into an hour-long request.
 */
const backfillSbomSchema = z.object({
  limit: z.coerce.number().int().min(1).max(2000).default(200),
});

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
    environments,
    applicationAccess,
    adminApplications,
    adminGroups,
    adminScans,
    adminMalicious,
    malicious,
    maliciousFeed,
    attributeDefinitions,
    audit,
    apiErrors,
    ingestTokens,
    sbomBackfill,
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

  /**
   * Which estates a read-only account may see.
   *
   * Returned for administrators too, even though the role already grants everything. The
   * rows exist and are simply not consulted while the account is an admin -- hiding them
   * would mean an admin screen that shows nothing for an admin, and a demotion to a
   * read-only role that silently hands over whichever estates happened to be stored.
   */
  fastify.get("/users/:id/environments", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    // Through the users service so a missing account is a 404 rather than an empty list.
    await adminUsers.getById(id);
    return reply.send({ environmentIds: await environments.environmentsForUser(id) });
  });

  /**
   * PUT, not PATCH, because the body is the complete set rather than a delta.
   *
   * The screen edits a checklist, so the whole set is what it knows. Two admins editing at
   * once would otherwise each apply their delta to a set the other had already changed, and
   * the loser's removal would come back.
   */
  fastify.put("/users/:id/environments", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(setUserEnvironmentsRequestSchema, request.body);
    await adminUsers.getById(id);

    /*
      Every id has to name an environment that exists. Accepting an unknown one would
      silently drop it -- the checklist would come back with a box unticked and no
      explanation, which reads as the save having failed for a different reason.
    */
    const known = new Set(await environments.allIds());
    const unknown = body.environmentIds.filter((envId) => !known.has(envId));
    if (unknown.length > 0) {
      throw new NotFoundError("Environment");
    }

    const before = await environments.environmentsForUser(id);
    await environments.setEnvironmentsForUser(id, body.environmentIds);

    await audit.record({
      actor: actorOf(request),
      action: "user.environments_set",
      targetType: "user",
      targetId: id,
      // Ids and counts. A name can change and the trail still has to say which estate.
      metadata: {
        from: before,
        to: body.environmentIds,
        count: { from: before.length, to: body.environmentIds.length },
      },
    });

    return reply.send({ environmentIds: body.environmentIds });
  });

  /**
   * Which groups and applications a read-only account may see, inside those environments.
   *
   * The second access axis. Read back even for administrators, whose grants are stored and
   * simply not consulted while the role is `admin` — hiding them would mean an admin screen
   * that shows nothing for an admin, and a later demotion to a read-only role that hands
   * over whatever happened to be stored without anybody having reviewed it.
   */
  fastify.get("/users/:id/application-access", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    await adminUsers.getById(id);
    return reply.send(await applicationAccess.forUser(id));
  });

  fastify.put("/users/:id/application-access", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(setUserApplicationAccessSchema, request.body);
    await adminUsers.getById(id);

    /*
      Unknown ids are refused rather than dropped, for the reason the environment route
      gives: a checklist that comes back with a box unticked and no explanation reads as the
      save having failed for some other reason.

      Both lists are checked even when `restricted` is false. The grants are stored either
      way so that switching the account back to restricted restores what it had, and storing
      an id that names nothing would make that restoration quietly incomplete.
    */
    if (body.groupIds.length > 0 || body.applicationIds.length > 0) {
      const found = await applicationAccess.countKnown(body.groupIds, body.applicationIds);
      if (found.groups !== body.groupIds.length) throw new NotFoundError("Group");
      if (found.applications !== body.applicationIds.length) {
        throw new NotFoundError("Application");
      }
    }

    const before = await applicationAccess.forUser(id);
    await applicationAccess.setForUser(id, body);
    const after = await applicationAccess.forUser(id);

    await audit.record({
      actor: actorOf(request),
      action: "user.application_access_set",
      targetType: "user",
      targetId: id,
      /*
        Ids and counts, never names -- a group can be renamed and the trail still has to say
        which one was granted. `visible` is the figure that makes the row answerable months
        later: "three groups" does not say whether somebody was given four services or forty.
      */
      metadata: {
        restricted: { from: before.restricted, to: after.restricted },
        groupIds: { from: before.groupIds, to: after.groupIds },
        applicationIds: { from: before.applicationIds, to: after.applicationIds },
        visible: { from: before.visibleApplicationCount, to: after.visibleApplicationCount },
      },
    });

    return reply.send(after);
  });

  // -------------------------------------------------------------------------
  // Applications
  // -------------------------------------------------------------------------

  fastify.post("/applications", async (request, reply) => {
    const body = parseOrThrow(createApplicationRequestSchema, request.body);
    const created = await adminApplications.create(body, actorOf(request), await requireScope(request));
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
  // Malicious packages
  // -------------------------------------------------------------------------

  /*
    Settings and status are readable here as well as on the public status route, because the
    admin page needs the feed's attempt history and its recipient list -- neither of which
    belongs in a payload every signed-in user can fetch.
  */
  fastify.get("/malicious/settings", async (_request, reply) => {
    return reply.send({
      settings: await adminMalicious.getSettings(),
      status: await malicious.status(),
    });
  });

  fastify.patch("/malicious/settings", async (request, reply) => {
    const body = parseOrThrow(updateMaliciousSettingsSchema, request.body);
    return reply.send({ settings: await adminMalicious.updateSettings(body, actorOf(request)) });
  });

  fastify.get("/malicious/history", async (request, reply) => {
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
  fastify.post("/malicious/update", async (request, reply) => {
    return reply.send(await adminMalicious.updateFeed(actorOf(request)));
  });

  /** Record a decision about a finding. Never hides it; the row stays and gains a label. */
  fastify.post("/malicious/acknowledgements", async (request, reply) => {
    const body = parseOrThrow(acknowledgeMaliciousRequestSchema, request.body);
    return reply
      .status(201)
      .send({ acknowledgement: await adminMalicious.acknowledge(body, actorOf(request)) });
  });

  fastify.delete("/malicious/acknowledgements/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    await adminMalicious.removeAcknowledgement(id, actorOf(request));
    return reply.status(204).send();
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

  /**
   * Recover component locations from the stored SBOMs of scans ingested before the platform
   * recorded them.
   *
   * A batch at a time rather than one long request, and the response reports what is left so
   * the caller can decide whether to run it again. That keeps an estate with tens of thousands
   * of scans from turning this into a request that either times out or holds a connection open
   * for an hour.
   *
   * 409 rather than a queue when a run is already in progress: two concurrent passes would
   * read the same blobs and contend on the same rows for no gain, and an operator who clicked
   * twice should be told, not silently ignored.
   */
  fastify.post("/scans/backfill-sbom", async (request, reply) => {
    if (sbomBackfill.isRunning) {
      throw new ConflictError("An SBOM backfill is already running.", "backfill_in_progress");
    }

    const body = parseOrThrow(backfillSbomSchema, request.body ?? {});
    const result = await sbomBackfill.run(body.limit);

    await audit.record({
      actor: actorOf(request),
      // Kept as the existing action name rather than renamed with the job. The audit trail
      // is append-only and the admin page filters on an exact action string, so renaming it
      // would split one job's history into two namespaces at the point of the rename.
      action: "scan.backfill_locations",
      targetType: "scan",
      // A batch has no single target, so the key names the job rather than a row.
      targetId: "locations",
      // Spread so the interface's named fields satisfy the audit row's index signature; the
      // recorded values are the counts themselves, which is what makes a run explainable
      // afterwards ("processed 200, 3 unreadable") rather than merely logged as having
      // happened.
      metadata: { ...result },
    });

    return reply.send(result);
  });

  /** How much of the estate still has no provenance pass, for the admin screen. */
  fastify.get("/scans/backfill-sbom", async (_request, reply) => {
    return reply.send({
      pending: await sbomBackfill.pending(),
      running: sbomBackfill.isRunning,
    });
  });

  // -------------------------------------------------------------------------
  // Groups
  // -------------------------------------------------------------------------

  fastify.post("/groups", async (request, reply) => {
    const body = parseOrThrow(createGroupRequestSchema, request.body);
    const scope = await requireScope(request);
    return reply
      .status(201)
      .send({ group: await adminGroups.create(body, actorOf(request), scope) });
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
    /*
      A token reaches one estate unless somebody explicitly asked otherwise. Defaulting to
      the administrator's current environment rather than to unrestricted means the easy
      path is also the contained one.
    */
    const environmentId = body.unrestricted
      ? null
      : (body.environmentId ?? (await requireScope(request)).id);
    const created = await ingestTokens.create({
      name: body.name,
      environmentId,
      createdByUserId: getUser(request).id,
    });

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

  // -------------------------------------------------------------------------
  // Error log
  // -------------------------------------------------------------------------
  //
  // Deliberately separate from the audit trail rather than a filter on it. The audit trail
  // is evidence of what an administrator did and is never pruned; this is diagnostics of
  // what failed, and is. Merging them would mean either pruning the evidence or keeping
  // every rejected request forever.

  fastify.get("/errors", async (request, reply) => {
    const query = parseOrThrow(listApiErrorsQuerySchema, request.query, "Query");
    return reply.send(await apiErrors.list(query));
  });

  fastify.get("/errors/summary", async (_request, reply) => {
    return reply.send(await apiErrors.summary());
  });

  fastify.delete("/errors", async (request, reply) => {
    const user = getUser(request);
    const removed = await apiErrors.clear();
    await audit.record({
      actor: { id: user.id, email: user.email },
      action: "error_log.clear",
      targetType: "setting",
      targetId: "error.log",
      // The count is the whole outcome: clearing an empty log and discarding a thousand
      // failures are the same action and want telling apart.
      metadata: { removed },
    });
    return reply.send({ removed });
  });
}
