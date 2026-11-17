import type { FastifyInstance } from "fastify";
import { idParamSchema } from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";
import { readAccess, requireScope } from "../environments/scope.js";
import type { PlatformModule } from "../platform/module.js";
import { DeveloperService } from "./developer.service.js";

async function developerRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAuth);
  const developer = fastify.ctx.modules.services<DeveloperService>("developer");

  fastify.get("/my-projects", async (request, reply) => {
    return reply.send(await developer.myProjects(getUser(request).id, await requireScope(request)));
  });

  fastify.get("/applications/:id/action-plan", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    return reply.send(await developer.actionPlan(id, await readAccess(request)));
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

  routes: [{ prefix: "", access: "user", plugin: developerRoutes }],

  routeDocs: {
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
