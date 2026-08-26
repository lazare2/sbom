import type { FastifyInstance, FastifyRequest } from "fastify";
import {
  createEnvironmentRequestSchema,
  deleteEnvironmentRequestSchema,
  idParamSchema,
  updateEnvironmentRequestSchema,
} from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import type { Actor } from "../admin/audit.service.js";
import { environmentAccess } from "./scope.js";

function actorOf(request: FastifyRequest): Actor {
  const user = getUser(request);
  return { id: user.id, email: user.email };
}

/**
 * Reading the estates.
 *
 * Behind `requireAuth` rather than `requireAdmin`, because this is what the header switcher
 * loads on every page: a read-only user has to be able to see the environments they were
 * granted or they cannot navigate at all. It returns exactly those, so the list is also the
 * answer to "which estates am I allowed to know about" — an environment the caller was not
 * granted is absent rather than listed and locked, since a locked row confirms it exists.
 */
export async function environmentRoutes(fastify: FastifyInstance): Promise<void> {
  const { environments } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAuth);

  fastify.get("/", async (request, reply) => {
    return reply.send({ environments: await environments.list(await environmentAccess(request)) });
  });

  fastify.get("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send({ environment: await environments.get(id, await environmentAccess(request)) });
  });
}

/**
 * Administering the estates.
 *
 * Applies `requireAdmin` to its own scope rather than relying on where it happens to be
 * registered, matching `reportRoutes`: inheriting the guard would work today and stop working
 * silently the day somebody moves the registration.
 */
export async function environmentAdminRoutes(fastify: FastifyInstance): Promise<void> {
  const { environments, settings, audit } = fastify.ctx;

  fastify.addHook("preHandler", fastify.requireAdmin);

  /*
    Registered before `/:id` so the static segment is unambiguous. Fastify would prefer it
    anyway, but a reader should not have to know that to be sure which handler runs.
  */
  fastify.get("/comparison", async (request, reply) => {
    const enabled = await settings.vulnScanningEnabled();
    return reply.send(
      await environments.comparison(
        await environmentAccess(request),
        await settings.staleInterval(),
        enabled,
      ),
    );
  });

  fastify.post("/", async (request, reply) => {
    const body = parseOrThrow(createEnvironmentRequestSchema, request.body);
    const created = await environments.create(body);

    await audit.record({
      actor: actorOf(request),
      action: "environment.create",
      targetType: "environment",
      targetId: created.id,
      metadata: { name: created.name },
    });

    return reply.status(201).send({ environment: created });
  });

  /**
   * A rename is a change to a published interface, not a relabel.
   *
   * Pipelines name their environment in the upload, so the old name lives in CI
   * configuration that this platform cannot see or update. The audit row therefore records
   * both names: when uploads start failing tomorrow, the trail is the only place that
   * connects the failure to the rename.
   */
  fastify.patch("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(updateEnvironmentRequestSchema, request.body);
    const before = await environments.get(id, { all: true, environmentIds: [] });
    const after = await environments.update(id, body);

    await audit.record({
      actor: actorOf(request),
      action: "environment.update",
      targetType: "environment",
      targetId: id,
      metadata: {
        name: { from: before.name, to: after.name },
        descriptionChanged: before.description !== after.description,
      },
    });

    return reply.send({ environment: after });
  });

  /**
   * Deletion, with the name typed back in the body.
   *
   * The count of what was destroyed goes in the audit row before the request returns,
   * because afterwards there is nothing left to count. That row is the only remaining
   * evidence that an estate with 40 applications ever existed.
   */
  fastify.delete("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const body = parseOrThrow(deleteEnvironmentRequestSchema, request.body ?? {});
    const removed = await environments.remove(id, body.confirmName);

    await audit.record({
      actor: actorOf(request),
      action: "environment.delete",
      targetType: "environment",
      targetId: id,
      metadata: { name: removed.name, applications: removed.applications },
    });

    return reply.status(204).send();
  });
}
