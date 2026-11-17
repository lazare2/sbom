import type { FastifyInstance } from "fastify";
import { idParamSchema, targetDatesSchema } from "@sbom/shared";
import { z } from "zod";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { readAccess, requireScope } from "../environments/scope.js";
import type { PlatformModule } from "../platform/module.js";
import { DeveloperService } from "./developer.service.js";

/** `since`: keep measuring "new" from this point while the page stays open. */
const actionPlanQuerySchema = z.object({ since: z.string().datetime().optional() });

async function developerRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAuth);
  const developer = fastify.ctx.modules.services<DeveloperService>("developer");

  fastify.get("/my-projects", async (request, reply) => {
    return reply.send(await developer.myProjects(getUser(request).id, await requireScope(request)));
  });

  fastify.get("/applications/:id/action-plan", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const { since } = parseOrThrow(actionPlanQuerySchema, request.query, "Query");
    const user = getUser(request);
    return reply.send(
      await developer.actionPlan(id, { id: user.id, role: user.role }, await readAccess(request), since ? new Date(since) : undefined),
    );
  });
}

/** Target dates: days to fix, by rule. Mounted behind requireAdmin by the module frame. */
async function developerAdminRoutes(fastify: FastifyInstance): Promise<void> {
  const { settings, audit } = fastify.ctx;

  fastify.get("/targets", async (_request, reply) => {
    return reply.send({ targets: await settings.getTargetDates() });
  });

  fastify.put("/targets", async (request, reply) => {
    const body = parseOrThrow(targetDatesSchema, request.body);
    const user = getUser(request);
    const actor = { id: user.id, email: user.email, ...(request.apiToken ? { viaToken: request.apiToken.name } : {}) };
    const { before, after } = await settings.updateTargetDates(body, actor);
    // Recorded because it changes which actions are late, on every project, with no build changing.
    await audit.record({ actor, action: "settings.update", targetType: "setting", targetId: "targets", metadata: { before, after } });
    return reply.send({ targets: after });
  });
}

/**
 * The developer view: "My projects" and each project's action plan.
 *
 * Always on. What it says about vulnerabilities comes from the modules that report them (through
 * the action plan and project urgency hooks), so with vulnerability scanning off it still lists
 * a person's projects and says plainly that nothing is checked.
 */
export const developerModule: PlatformModule = {
  id: "developer",
  name: "Developer view",
  description: "My projects with a status in plain words, and an action plan for each project.",

  services: (ctx) => new DeveloperService(ctx),

  routes: [
    { prefix: "", access: "user", plugin: developerRoutes },
    { prefix: "/admin/developer", access: "admin", plugin: developerAdminRoutes },
  ],

  routeDocs: {
    "GET /api/v1/admin/developer/targets": {
      summary: "Target dates: days to fix a vulnerability used in real attacks, a critical one and a high one.",
      tag: "Developer view",
      auth: "admin",
    },
    "PUT /api/v1/admin/developer/targets": {
      summary: "Change the target dates. Applies at once to every project's action plan and status.",
      tag: "Developer view",
      auth: "admin",
      body: targetDatesSchema,
      notes:
        "criticalDays is the same value as criticalFixDays in the needs-attention settings: " +
        "changing it here changes it there.",
    },
    "GET /api/v1/my-projects": {
      summary: "The caller's own projects - through their squads or granted to them - most urgent first.",
      tag: "Developer view",
      auth: "user",
      notes:
        "Each project has a status (fix-now, fix-soon, no-recent-build, nothing-to-do) and the " +
        "reason in words. Only projects in the selected environment that the caller may read.",
    },
    "GET /api/v1/applications/:id/action-plan": {
      summary: "One project's status and its action plan: one line per thing to do.",
      tag: "Developer view",
      auth: "user",
      notes:
        "Every vulnerability in the current build (accepted risks left out) is in exactly one line: " +
        "a package upgrade, the base-image rebuild, or the closing 'no fix yet' line.",
    },
  },
};
